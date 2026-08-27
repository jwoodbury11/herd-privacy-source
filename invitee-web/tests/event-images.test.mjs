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
  poker: "c947503f99608d90b8eacf3babe6bfe38a1e2f1778579e1e589b2e2523f5211c",
  tennis: "9c7911a5646a523cad165d4dd71e87ee17583dd1c0c12ed0845545a2a0313cff",
  "board-games": "185054f39cc4bf5878fcb396780a48bba80afc0624187fa7ce937307e0c05d01",
  "house-drinks": "9d4675c2c454bf12bb499631b0baddbb157ba875fa95df512e4763e6898d7142",
  restaurant: "6bf9cfded6f34758cd87f9b8c2b2b30c1e3648d5db454f2237fc0dccab2ef22a",
  "cocktail-bar": "081a7e09c875a05a44ae18c95df4440f882f57f8b43e34c9b60e236394deb480",
  "club-dancing": "3e34e28a749610c87d7db92df849d25952b33fe3805e035ce71fef5b04a0e8c3",
  "movie-night": "587b9ae3966e77b1b1e9f093c9b22c9867b3088b94d937fa3ab7282288a2a45d",
  "park-picnic": "36481260865da60e1f68d3978715ca6dc177421887e84b14f0e71bd88845d85e",
  "travel-airport": "0ce380089342ed783d41ec0cf0c6d679bb5ef0073cec2deca7e1caad02518acb",
  camping: "821b7a142426d6e5be170acf3f0b8e5b861e3bebc6644e5ecef9de40eeb8a5eb",
  fishing: "2c97e421c0532eab61e3abdd76f4d37344ef49c0b84ce29e5b01fcfd295530fd",
  "birthday-party": "67d9f0f36d9b231ccedca9633078f7f90ec11050175560b5c744d9b9ad781d18",
  jacuzzi: "5e7dd2d05b2d8ea9d337212ac230bd466cd77825e0cc2330fe679b5964ece714",
  skiing: "a788d5fcd524f6222e28a22c291e4023dcf87ab58f4fe853e26b821baa4fb6fe",
  other: "4dc2946db572b78179a15c0fee81c1ef7817a7c22ac240fa9058fb00dd14484b",
};

const neverConfirmedSha256 = "65a6a15299f046abc2dbf267e3f5ebbe712f27f1976410b8872360dcc8391102";

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

test("never-confirmed events use the dedicated funeral artwork without making it selectable", async () => {
  const [webImage, nativeImage, webCatalog, page, nativeHome, nativeCatalog] = await Promise.all([
    readFile(new URL("../public/event-images/never-confirmed.png", import.meta.url)),
    readFile(new URL("../../HerdHost/Assets.xcassets/EventScenes/event-scene-never-confirmed.imageset/event-scene-never-confirmed.png", import.meta.url)),
    readFile(new URL("../lib/event-images.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/HomeView.swift", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/EventImage.swift", import.meta.url), "utf8"),
  ]);

  for (const [platform, image] of [["web", webImage], ["iPhone", nativeImage]]) {
    assert.equal(image.subarray(1, 4).toString("ascii"), "PNG", `${platform} funeral art must be a PNG`);
    assert.equal(image[25], 6, `${platform} funeral art must use RGBA pixels`);
    assert.equal(image.readUInt32BE(16), 1254, `${platform} funeral art must retain the native width`);
    assert.equal(image.readUInt32BE(20), 1254, `${platform} funeral art must retain the native height`);
    assert.equal(sha256(image), neverConfirmedSha256, `${platform} funeral art must match V1 exactly`);
  }

  assert.match(webCatalog, /NEVER_CONFIRMED_EVENT_IMAGE_PATH = "\/event-images\/never-confirmed\.png"/u);
  assert.doesNotMatch(webCatalog, /"never-confirmed",\s*\] as const/u);
  assert.match(page, /homeEventSection\(event, now\) === "unconfirmed"[\s\S]*NEVER_CONFIRMED_EVENT_IMAGE_PATH/u);
  assert.match(page, /className="event-card-image"[\s\S]*src=\{eventArtworkPath\(event, now\)\}/u);
  assert.match(page, /className="event-hero-image"[\s\S]*src=\{eventArtworkPath\(activeEvent, now\)\}/u);
  assert.match(nativeHome, /usesNeverConfirmedArtwork: true/u);
  assert.match(nativeHome, /usesNeverConfirmedArtwork: event\.homeSection\(\) == \.unconfirmed/u);
  assert.match(nativeCatalog, /"event-scene-never-confirmed"/u);
  assert.doesNotMatch(nativeCatalog, /case neverConfirmed/u);
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
  assert.match(
    page,
    /className="event-card-image"[\s\S]*?src=\{eventArtworkPath\(event, now\)\}[\s\S]*?unoptimized/u,
  );
  assert.match(
    page,
    /className="event-hero-image"[\s\S]*?src=\{eventArtworkPath\(activeEvent, now\)\}[\s\S]*?unoptimized/u,
  );
  assert.match(styles, /grid-template-columns: minmax\(0, 1fr\) 144px/u);
  assert.match(styles, /\.event-card h2[\s\S]*-webkit-line-clamp: 3/u);
  assert.match(nativeHome, /EventSceneImage\([\s\S]*id: event\.resolvedEventImageID,[\s\S]*usesNeverConfirmedArtwork: usesNeverConfirmedArtwork[\s\S]*\.frame\(width: 144, height: 144\)/u);
  assert.match(nativeHome, /\.lineLimit\(3\)[\s\S]*\.truncationMode\(\.tail\)/u);
  assert.match(nativeHome, /\.frame\([\s\S]*minHeight: max\(0, cardMinimumHeight - \(cardPadding \* 2\)\)[\s\S]*alignment: \.topLeading/u);
  assert.match(styles, /\.event-hero-image[\s\S]*width: min\(100%, 468px\)[\s\S]*height: 317px/u);
  assert.match(nativeHome, /id: event\.resolvedEventImageID,[\s\S]*usesNeverConfirmedArtwork: event\.homeSection\(\) == \.unconfirmed[\s\S]*\.frame\(height: 317\)/u);
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
