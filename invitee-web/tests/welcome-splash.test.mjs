import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

test("the welcome splash is transparent and shared by web and iPhone", async () => {
  const [image, page, styles, nativeView, assetCatalog] = await Promise.all([
    readFile(new URL("../public/brand/herd-welcome-splash.png", import.meta.url)),
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/AuthenticationView.swift", import.meta.url), "utf8"),
    readFile(
      new URL(
        "../../HerdHost/Assets.xcassets/HerdWelcomeSplash.imageset/Contents.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ]);

  assert.equal(image.subarray(1, 4).toString("ascii"), "PNG");
  assert.equal(image[25], 6, "the splash must use RGBA pixels");
  assert.match(
    page,
    /className="welcome-splash"[\s\S]*className="welcome-headline">\{AUTH_EXPERIENCE\.welcome\.title\}/u,
  );
  assert.doesNotMatch(page, /invitationPreview|inviteAccountMismatch|You’re invited/u);
  assert.match(styles, /\.welcome-splash[\s\S]*height: clamp\(165px, 24svh, 225px\)/u);
  assert.match(styles, /\.welcome-splash \+ \.welcome-copy \{[\s\S]*margin-top: 20px/u);
  assert.match(nativeView, /Image\("HerdWelcomeSplash"\)[\s\S]*geometry\.size\.height \* 0\.30/u);
  assert.match(nativeView, /VStack\(alignment: \.leading, spacing: 7\)[\s\S]*\.padding\(\.top, 20\)/u);
  assert.match(nativeView, /safeAreaInset\(edge: \.bottom, spacing: 0\)/u);
  assert.match(assetCatalog, /herd-welcome-splash\.png/u);
});
