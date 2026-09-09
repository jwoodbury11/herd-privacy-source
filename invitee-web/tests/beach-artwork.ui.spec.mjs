import { readFile } from "node:fs/promises";
import { expect, test } from "@playwright/test";
import { startBrowserAcceptanceHarness } from "../scripts/browser-acceptance-harness.mjs";

test("Beach artwork loads directly on web event cards and details", async ({ browser }, testInfo) => {
  const harness = await startBrowserAcceptanceHarness();
  const context = await browser.newContext({ viewport: { width: 430, height: 932 } });
  try {
    await harness.database.prepare("UPDATE events SET event_image_id = ? WHERE id = ?")
      .bind("beach", harness.scenario.eventId).run();
    const page = await context.newPage();
    await page.goto(harness.baseUrl.href);
    await page.getByLabel("Sign in with phone number").fill("1");
    await page.getByRole("button", { name: "Text me a code" }).click();
    await expect(page.getByRole("heading", { name: "Herd events" })).toBeVisible();
    const assetResponse = await page.request.get(new URL("/event-images/beach.png", harness.baseUrl).href);
    expect(assetResponse.ok()).toBe(true);
    expect(await assetResponse.body()).toEqual(await readFile(new URL("../public/event-images/beach.png", import.meta.url)));
    const card = page.locator('.event-card-image[src="/event-images/beach.png"]');
    await expect(card).toBeVisible();
    await expect.poll(() => card.evaluate((image) => image.complete && image.naturalWidth > 0)).toBe(true);
    await expect(card).toHaveCSS("background-color", "rgba(0, 0, 0, 0)");
    await page.screenshot({ path: testInfo.outputPath("beach-event-card.png") });
    await page.getByRole("button", { name: `Open ${harness.scenario.title}`, exact: true }).click();
    const hero = page.locator('.event-hero-image[src="/event-images/beach.png"]');
    await expect(hero).toBeVisible();
    await expect.poll(() => hero.evaluate((image) => image.complete && image.naturalWidth > 0)).toBe(true);
    await expect(hero).toHaveCSS("background-color", "rgba(0, 0, 0, 0)");
    await page.screenshot({ path: testInfo.outputPath("beach-event-detail.png") });
  } finally {
    await context.close();
    await harness.stop();
  }
});
