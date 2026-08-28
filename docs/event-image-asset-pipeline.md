# Event image asset pipeline

This is the required path from generation to production for every Herd event image and the home splash illustration. It exists to prevent white, gray, colored, or checkerboard fringes on transparent artwork.

## The failure to avoid

A PNG can report an alpha channel and still be wrong. If its antialiased boundary pixels were blended against white before transparency was created, those partially transparent pixels retain white RGB. iOS and browsers interpolate those pixels while scaling, producing a visible light outline on dark surfaces.

The original never-confirmed V1 was exported from a checkerboard preview and had 2,278 strongly suspicious white-matte boundary pixels. The approved Hangout and Sports exports had 1 and 0 under the same test. A transparent corner check or file-type check alone cannot detect this problem.

## Required production flow

1. Generate or export from a clean source. Native RGBA is acceptable only when inspection confirms that the generator returned real transparency rather than a baked checkerboard.
2. If native RGBA is unreliable, render once against a single, flat, highly saturated chroma matte. Never use a checkerboard, white, gray, a gradient, or the intended app background as the extraction matte.
3. Convert the chroma render with `scripts/assets/chroma_matte_to_rgba.py`. The converter reconstructs partial coverage, removes matte color from antialiased pixels, and propagates trusted foreground colors into the boundary RGB. Set up its small, pinned environment once, then retain the JSON report beside the archival source:

   ```sh
   python3 -m pip install -r scripts/assets/requirements.txt
   python3 scripts/assets/chroma_matte_to_rgba.py source-matte.png output-rgba.png --report output-key-report.json
   ```
4. Preserve one named archival source and one production-sized 1254×1254 RGBA PNG. Do not repeatedly segment or resave a preview derivative.
5. Install the exact same production bytes in both locations:
   - `invitee-web/public/event-images/<id>.png`
   - `HerdHost/Assets.xcassets/EventScenes/event-scene-<id>.imageset/event-scene-<id>.png`
6. Run the automated gate and generate the review composites:

   ```sh
   cd invitee-web
   npm run qa:event-images -- --preview-dir ../build/event-image-edge-previews
   ```

7. Inspect the iOS-dark, web-dark, and light panels at 100% and at in-app thumbnail size. Explicitly inspect animal fur, feet and tails, lamp legs, tree gaps, chair gaps, wreath/easel openings, snow, rims, and the lower perimeter.
8. Only then update the approved digest in `invitee-web/tests/event-images.test.mjs` and run the affected web and iOS tests.

## Composition rule

Do not fade a complete rug, platform, or other manufactured object. Keep characters and meaningful props opaque. If the scene needs a soft footprint, make loose environmental material physically sparser toward the perimeter, then leave the outer 12–15% fully transparent. Do not put a blurred vignette or white haze over the flattened scene.

## Acceptance criteria

- Genuine RGBA PNG, 1254×1254 for production.
- Fully transparent canvas corners and breathing room around the scene.
- Identical web and iPhone bytes.
- Automated white-matte edge gate passes.
- No visible outline or filled transparent gap on `#1C1C1E`, `#171719`, or `#F2F2F7`.
- No checkerboard-derived source is promoted to production.
