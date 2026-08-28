#!/usr/bin/env node

import { mkdir, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";
import sharp from "sharp";

export const QA_BACKGROUNDS = [
  { name: "ios-dark", color: { r: 28, g: 28, b: 30, alpha: 1 } },
  { name: "web-dark", color: { r: 23, g: 23, b: 25, alpha: 1 } },
  { name: "light", color: { r: 242, g: 242, b: 247, alpha: 1 } },
];

const MAX_WHITE_MATTE_PIXELS = 100;
const MAX_WHITE_MATTE_RATE = 0.005;
const OPAQUE_NEIGHBOR_ALPHA = 245;
const SEARCH_RADIUS = 3;

function pixelOffset(x, y, width, channels) {
  return (y * width + x) * channels;
}

export async function analyzeEventImage(buffer, name = "event image") {
  const metadata = await sharp(buffer).metadata();
  if (!metadata.hasAlpha || metadata.channels !== 4) {
    throw new Error(`${name} must be a genuine RGBA PNG`);
  }

  const { data, info } = await sharp(buffer)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });
  const cornerAlpha = [
    data[3],
    data[pixelOffset(info.width - 1, 0, info.width, info.channels) + 3],
    data[pixelOffset(0, info.height - 1, info.width, info.channels) + 3],
    data[pixelOffset(info.width - 1, info.height - 1, info.width, info.channels) + 3],
  ];

  let semitransparentPixels = 0;
  let suspiciousWhiteMattePixels = 0;

  for (let y = 0; y < info.height; y += 1) {
    for (let x = 0; x < info.width; x += 1) {
      const offset = pixelOffset(x, y, info.width, info.channels);
      const red = data[offset];
      const green = data[offset + 1];
      const blue = data[offset + 2];
      const alpha = data[offset + 3];
      if (alpha === 0 || alpha === 255) continue;
      semitransparentPixels += 1;

      const channelSpread = Math.max(red, green, blue) - Math.min(red, green, blue);
      const isBrightNeutral = red >= 220 && green >= 220 && blue >= 220 && channelSpread <= 18;
      if (!isBrightNeutral) continue;

      let nearestOpaqueColor = null;
      let nearestDistance = Number.POSITIVE_INFINITY;
      for (let deltaY = -SEARCH_RADIUS; deltaY <= SEARCH_RADIUS; deltaY += 1) {
        for (let deltaX = -SEARCH_RADIUS; deltaX <= SEARCH_RADIUS; deltaX += 1) {
          if (deltaX === 0 && deltaY === 0) continue;
          const neighborX = x + deltaX;
          const neighborY = y + deltaY;
          if (
            neighborX < 0 || neighborY < 0 ||
            neighborX >= info.width || neighborY >= info.height
          ) continue;
          const neighborOffset = pixelOffset(
            neighborX,
            neighborY,
            info.width,
            info.channels,
          );
          if (data[neighborOffset + 3] < OPAQUE_NEIGHBOR_ALPHA) continue;
          const distance = deltaX * deltaX + deltaY * deltaY;
          if (distance < nearestDistance) {
            nearestDistance = distance;
            nearestOpaqueColor = [
              data[neighborOffset],
              data[neighborOffset + 1],
              data[neighborOffset + 2],
            ];
          }
        }
      }

      if (!nearestOpaqueColor) continue;
      const neighborLuma = nearestOpaqueColor.reduce((sum, channel) => sum + channel, 0) / 3;
      const colorDistance = Math.hypot(
        red - nearestOpaqueColor[0],
        green - nearestOpaqueColor[1],
        blue - nearestOpaqueColor[2],
      );
      if (neighborLuma < 190 && colorDistance > 75) suspiciousWhiteMattePixels += 1;
    }
  }

  const suspiciousWhiteMatteRate = suspiciousWhiteMattePixels / Math.max(1, semitransparentPixels);
  const passesWhiteMatteGate = !(
    suspiciousWhiteMattePixels > MAX_WHITE_MATTE_PIXELS &&
    suspiciousWhiteMatteRate > MAX_WHITE_MATTE_RATE
  );

  return {
    name,
    width: info.width,
    height: info.height,
    cornerAlpha,
    semitransparentPixels,
    suspiciousWhiteMattePixels,
    suspiciousWhiteMatteRate,
    passesWhiteMatteGate,
  };
}

async function writeThreeBackgroundPreview(buffer, outputPath) {
  const metadata = await sharp(buffer).metadata();
  const panels = await Promise.all(
    QA_BACKGROUNDS.map(({ color }) => sharp(buffer).flatten({ background: color }).png().toBuffer()),
  );
  await mkdir(path.dirname(outputPath), { recursive: true });
  await sharp({
    create: {
      width: metadata.width * panels.length,
      height: metadata.height,
      channels: 4,
      background: { r: 0, g: 0, b: 0, alpha: 0 },
    },
  })
    .composite(panels.map((input, index) => ({ input, left: index * metadata.width, top: 0 })))
    .png({ compressionLevel: 9 })
    .toFile(outputPath);
}

export async function verifyEventImageEdges({ previewDirectory = null } = {}) {
  const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
  const webDirectory = path.resolve(scriptDirectory, "../public/event-images");
  const nativeDirectory = path.resolve(
    scriptDirectory,
    "../../HerdHost/Assets.xcassets/EventScenes",
  );
  const filenames = (await readdir(webDirectory)).filter((name) => name.endsWith(".png")).sort();
  const reports = [];

  for (const filename of filenames) {
    const id = filename.replace(/\.png$/u, "");
    const webPath = path.join(webDirectory, filename);
    const nativePath = path.join(
      nativeDirectory,
      `event-scene-${id}.imageset`,
      `event-scene-${id}.png`,
    );
    const [webBuffer, nativeBuffer] = await Promise.all([readFile(webPath), readFile(nativePath)]);
    if (!webBuffer.equals(nativeBuffer)) {
      throw new Error(`${id} differs between web and iPhone; install the same approved export in both`);
    }
    const report = await analyzeEventImage(webBuffer, id);
    if (report.cornerAlpha.some((alpha) => alpha !== 0)) {
      throw new Error(`${id} must retain fully transparent canvas corners`);
    }
    if (!report.passesWhiteMatteGate) {
      throw new Error(
        `${id} contains ${report.suspiciousWhiteMattePixels} likely white-matte edge pixels ` +
        `(${(report.suspiciousWhiteMatteRate * 100).toFixed(2)}% of antialiased pixels)`,
      );
    }
    reports.push(report);
    if (previewDirectory) {
      await writeThreeBackgroundPreview(
        webBuffer,
        path.resolve(previewDirectory, `${id}-ios-web-light.png`),
      );
    }
  }
  return reports;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const previewIndex = process.argv.indexOf("--preview-dir");
  const previewDirectory = previewIndex >= 0 ? process.argv[previewIndex + 1] : null;
  const reports = await verifyEventImageEdges({ previewDirectory });
  for (const report of reports) {
    console.log(
      `${report.name}: ${report.suspiciousWhiteMattePixels} suspicious white-edge pixels ` +
      `(${(report.suspiciousWhiteMatteRate * 100).toFixed(3)}%)`,
    );
  }
  console.log(`Verified ${reports.length} matching web/iPhone RGBA event images.`);
}
