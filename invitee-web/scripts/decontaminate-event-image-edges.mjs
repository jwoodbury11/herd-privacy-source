#!/usr/bin/env node

import { readFile, writeFile } from "node:fs/promises";
import process from "node:process";
import { pathToFileURL } from "node:url";
import sharp from "sharp";

const OPAQUE_ALPHA = 245;
const SEARCH_RADIUS = 10;

function offsetFor(x, y, width, channels) {
  return (y * width + x) * channels;
}

function isLikelyWhiteMatte(red, green, blue, neighbor) {
  const spread = Math.max(red, green, blue) - Math.min(red, green, blue);
  if (red < 205 || green < 205 || blue < 205 || spread > 26) return false;
  const neighborLuma = (neighbor[0] + neighbor[1] + neighbor[2]) / 3;
  const distance = Math.hypot(
    red - neighbor[0],
    green - neighbor[1],
    blue - neighbor[2],
  );
  return neighborLuma < 205 && distance > 60;
}

function nearestOpaqueColor(data, info, x, y) {
  let match = null;
  let matchDistance = Number.POSITIVE_INFINITY;
  for (let deltaY = -SEARCH_RADIUS; deltaY <= SEARCH_RADIUS; deltaY += 1) {
    for (let deltaX = -SEARCH_RADIUS; deltaX <= SEARCH_RADIUS; deltaX += 1) {
      if (deltaX === 0 && deltaY === 0) continue;
      const neighborX = x + deltaX;
      const neighborY = y + deltaY;
      if (
        neighborX < 0 || neighborY < 0 ||
        neighborX >= info.width || neighborY >= info.height
      ) continue;
      const distance = deltaX * deltaX + deltaY * deltaY;
      if (distance >= matchDistance) continue;
      const neighborOffset = offsetFor(
        neighborX,
        neighborY,
        info.width,
        info.channels,
      );
      if (data[neighborOffset + 3] < OPAQUE_ALPHA) continue;
      matchDistance = distance;
      match = [
        data[neighborOffset],
        data[neighborOffset + 1],
        data[neighborOffset + 2],
      ];
    }
  }
  return match;
}

export async function decontaminateEventImageEdges(input) {
  const metadata = await sharp(input).metadata();
  if (!metadata.hasAlpha || metadata.channels !== 4) {
    throw new Error("Event-image edge cleanup requires a genuine RGBA PNG input");
  }
  if (metadata.width !== 1254 || metadata.height !== 1254) {
    throw new Error("Event-image edge cleanup requires the approved 1254x1254 canvas");
  }

  const { data, info } = await sharp(input)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });
  const output = Buffer.from(data);
  let changedPixels = 0;

  for (let y = 0; y < info.height; y += 1) {
    for (let x = 0; x < info.width; x += 1) {
      const offset = offsetFor(x, y, info.width, info.channels);
      const alpha = data[offset + 3];
      if (alpha === 0 || alpha === 255) continue;
      const neighbor = nearestOpaqueColor(data, info, x, y);
      if (!neighbor) continue;
      if (!isLikelyWhiteMatte(data[offset], data[offset + 1], data[offset + 2], neighbor)) {
        continue;
      }
      output[offset] = neighbor[0];
      output[offset + 1] = neighbor[1];
      output[offset + 2] = neighbor[2];
      changedPixels += 1;
    }
  }

  return {
    buffer: await sharp(output, {
      raw: { width: info.width, height: info.height, channels: info.channels },
    })
      .png({ compressionLevel: 9 })
      .toBuffer(),
    changedPixels,
  };
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const [inputPath, outputPath] = process.argv.slice(2);
  if (!inputPath || !outputPath) {
    throw new Error("Usage: node scripts/decontaminate-event-image-edges.mjs <input.png> <output.png>");
  }
  const { buffer, changedPixels } = await decontaminateEventImageEdges(await readFile(inputPath));
  await writeFile(outputPath, buffer);
  console.log(`Decontaminated ${changedPixels} likely white-matte edge pixels.`);
}
