import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import sharp from "sharp";

const expectedIDs = [
  "poker",
  "tennis",
  "board-games",
  "house-drinks",
  "restaurant",
  "cocktail-bar",
  "club-dancing",
  "movie-night",
  "park-picnic",
  "travel-airport",
  "camping",
  "fishing",
  "birthday-party",
  "jacuzzi",
  "skiing",
  "other",
];

const approvedSha256ForID = {
  poker: "0c2b735b59ec37df566bd375aba7fd947c7974769658e354a6283e965d925d5e",
  tennis: "04a2244dd34dcb9297df1dac83e85e64247452011efe6e31284913791c7df71d",
  "board-games": "ec30b0a2fb6004b7adb1c81b7d48c18685e6cc8f2cc0dd437c4d3ddfa9141a51",
  "house-drinks": "90d267ed220b5b214f2179a49d3c9f47c2cf5971c1d34c1bebd40033c03567fb",
  restaurant: "a540e700e842f0592c47a26f9fb874227142b4f514799ac3069e44d2cb59cddd",
  "cocktail-bar": "a796b65c20e385888757b34d105a621dc5e5bbe681c334f6a162e68255eed64e",
  "club-dancing": "64eb69378a6c2941f79b0e1d715ef4feb1d8673921fa1aa205bcbf3f7d918cfc",
  "movie-night": "38a14540f05d56d66989dc10d1ff75966ce4712fd58ee2e0780ecab557c60a40",
  "park-picnic": "2268d7bfaf3a0ad10061521144b814e3280c6477e5e429871d8749cd7d6a6382",
  "travel-airport": "ff822bc0d9ef9c447e60028b69850a8c26190de0be031f837f04ea22287065a6",
  camping: "e745dcea25e7f6644c0bd31c2a325003e4317189931f9a248070824e5b9317b1",
  fishing: "bb9af8dd5dc8feaf0b5c8bb01d60a3b163978d5f5017dea3d02045a4304534d5",
  "birthday-party": "cc86916cc6260db65321cd87ac5dd89a036e78de2ca2c7ebfe225fc4b0d28844",
  jacuzzi: "39cf9f11b8747e86cb1881dbf777b26044edd51b92e8054656b4a2c231439aec",
  skiing: "9febdc732490363b7747ae67e27c74271229a01f85f0f343fe29557b61ce704f",
  other: "6538310bb8f040ecd3c9f6b10f9252d7db9445cd042a7d502155ea8488640bf9",
};

function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

test("the web and iPhone event-image catalogs stay in parity", async () => {
  const [webCatalog, swiftCatalog] = await Promise.all([
    readFile(new URL("../lib/event-images.ts", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/EventImage.swift", import.meta.url), "utf8"),
  ]);

  assert.equal(expectedIDs.length, 16);
  assert.equal(expectedIDs.at(-1), "other");
  assert.match(webCatalog, /"skiing",\s*"other",\s*\] as const/u);
  assert.match(swiftCatalog, /case skiing\s+case other/u);

  for (const id of expectedIDs) {
    assert.match(webCatalog, new RegExp(`"${id}"`));
    assert.match(swiftCatalog, new RegExp(id.replace(/-([a-z])/gu, (_, letter) => letter.toUpperCase())));
  }
});

test("the host image selector uses the approved short labels", async () => {
  const swiftCatalog = await readFile(
    new URL("../../HerdHost/EventImage.swift", import.meta.url),
    "utf8",
  );

  assert.match(swiftCatalog, /case \.poker: "Poker"/u);
  assert.match(swiftCatalog, /case \.houseDrinks: "Hangout"/u);
  assert.match(swiftCatalog, /case \.clubDancing: "Club"/u);
  assert.match(swiftCatalog, /case \.birthdayParty: "Birthday"/u);
  assert.match(swiftCatalog, /case \.jacuzzi: "Hot tub"/u);
  assert.match(swiftCatalog, /case \.skiing: "Skiing"/u);
  assert.doesNotMatch(
    swiftCatalog,
    /case \.poker: "Cards"|case \.houseDrinks: "At home"|case \.clubDancing: "Dancing"/u,
  );
});

test("every production event image is the approved high-density transparent asset", async () => {
  for (const id of expectedIDs) {
    const [webImage, nativeImage] = await Promise.all([
      readFile(new URL(`../public/event-images/${id}.png`, import.meta.url)),
      readFile(new URL(`../../HerdHost/Assets.xcassets/EventScenes/event-scene-${id}.imageset/event-scene-${id}.png`, import.meta.url)),
    ]);
    assert.equal(webImage.subarray(1, 4).toString("ascii"), "PNG", `${id} must be a PNG`);
    assert.equal(webImage[25], 6, `${id} must use RGBA pixels instead of a baked checkerboard`);
    assert.equal(webImage.readUInt32BE(16), 1254, `${id} must retain the approved source width`);
    assert.equal(webImage.readUInt32BE(20), 1254, `${id} must retain the approved source height`);
    const { data: pixels, info } = await sharp(webImage)
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });
    const alphaAt = (x, y) => pixels[(y * info.width + x) * info.channels + 3];
    assert.equal(alphaAt(0, 0), 0, `${id} must have a genuinely transparent top-left corner`);
    assert.equal(alphaAt(info.width - 1, 0), 0, `${id} must have a genuinely transparent top-right corner`);
    assert.equal(alphaAt(0, info.height - 1), 0, `${id} must have a genuinely transparent bottom-left corner`);
    assert.equal(alphaAt(info.width - 1, info.height - 1), 0, `${id} must have a genuinely transparent bottom-right corner`);
    assert.equal(sha256(webImage), approvedSha256ForID[id], `${id} web art must match the approved clean-edge export`);
    assert.equal(sha256(nativeImage), approvedSha256ForID[id], `${id} iPhone art must match the approved clean-edge export`);
  }
});

test("cards, details, and the host editor expose the event image", async () => {
  const [page, styles, editor, nativeHome, nativeImage] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/EventEditorView.swift", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/HomeView.swift", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/EventImage.swift", import.meta.url), "utf8"),
  ]);

  assert.match(page, /className="event-card-image"/u);
  assert.match(page, /className="event-hero-image"/u);
  assert.match(styles, /grid-template-columns: minmax\(0, 1fr\) 144px/u);
  assert.match(styles, /\.event-card h2[\s\S]*-webkit-line-clamp: 3/u);
  assert.match(nativeHome, /EventSceneImage\(id: event\.resolvedEventImageID\)[\s\S]*\.frame\(width: 144, height: 144\)/u);
  assert.match(nativeHome, /\.lineLimit\(3\)[\s\S]*\.truncationMode\(\.tail\)/u);
  assert.match(nativeHome, /\.frame\([\s\S]*minHeight: max\(0, cardMinimumHeight - \(cardPadding \* 2\)\)[\s\S]*alignment: \.topLeading/u);
  assert.match(styles, /\.event-hero-image[\s\S]*width: min\(100%, 468px\)[\s\S]*height: 317px/u);
  assert.match(nativeHome, /event\.resolvedEventImageID\)[\s\S]*\.frame\(height: 317\)/u);
  assert.match(editor, /EditorGroup\(title: "Image"\)[\s\S]*EventImageID\.allCases/u);
  assert.match(editor, /event-image-preview-/u);
  assert.match(editor, /fullScreenCover\(item: \$previewedImageID\)/u);
  assert.match(editor, /EventImagePreviewView\(imageID: imageID\) \{ selectedImageID in[\s\S]*selectEventImage\(selectedImageID\)/u);
  assert.match(editor, /ScrollViewReader[\s\S]*imageCarousel\.scrollTo\(selectedImageID, anchor: \.center\)/u);
  assert.match(editor, /\.onAppear \{[\s\S]*imageCarousel\.scrollTo\(selectedImageID, anchor: \.center\)/u);
  assert.match(editor, /\.onChange\(of: previewedImageID\)[\s\S]*currentImageID == nil[\s\S]*imageCarousel\.scrollTo\(selectedImageID, anchor: \.center\)/u);
  assert.match(nativeImage, /TabView\(selection: \$selectedImageID\)[\s\S]*ForEach\(EventImageID\.allCases\)[\s\S]*\.tabViewStyle\(\.page\(indexDisplayMode: \.always\)\)/u);
  assert.match(nativeImage, /EventSceneImage\(id: imageID\)[\s\S]*Text\(imageID\.label\)[\s\S]*event-image-preview-name-/u);
  assert.match(nativeImage, /onDone\(selectedImageID\)[\s\S]*dismiss\(\)/u);
  assert.match(nativeImage, /Text\("Done"\)[\s\S]*\.frame\(minHeight: 50\)[\s\S]*\.tint\(\.white\)[\s\S]*\.foregroundStyle\(\.black\)/u);
});

test("Poker is the cross-platform fallback and save responses preserve the chosen image", async () => {
  const [webCatalog, models, apiClient] = await Promise.all([
    readFile(new URL("../lib/event-images.ts", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/Models.swift", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/APIClient.swift", import.meta.url), "utf8"),
  ]);

  assert.match(webCatalog, /DEFAULT_EVENT_IMAGE_ID: EventImageID = "poker"/u);
  assert.match(models, /var resolvedEventImageID:[\s\S]*eventImageID \?\? \.poker/u);
  assert.match(
    apiClient,
    /savedEvent\.eventImageID = response\.event\.eventImageID \?\? event\.resolvedEventImageID/u,
  );
});
