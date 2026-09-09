import { expect, test } from "@playwright/test";
import { startBrowserAcceptanceHarness } from "../scripts/browser-acceptance-harness.mjs";

test("privacy divider appears at the lettering, before the compact title, and resets", async ({ page }, testInfo) => {
  const harness = await startBrowserAcceptanceHarness();
  try {
    await page.goto(harness.baseUrl.href);
    await page.getByLabel("Sign in with phone number").fill("1");
    await page.getByRole("button", { name: "Text me a code" }).click();
    await page.getByRole("button", { name: `Open ${harness.scenario.title}` }).click();
    await page.getByRole("button", { name: /Prove it to me/ }).click();
    const header = page.locator(".app-header");
    const scroll = page.locator(".privacy-screen");
    const heading = page.locator("#privacy-heading");
    await expect(heading).toBeVisible();
    await expect(header).not.toHaveClass(/app-header-overlap|app-header-condensed/);
    await page.screenshot({ path: testInfo.outputPath("privacy-top.png") });

    // The heading box begins after 31px of padding; the H has additional font leading.
    await scroll.evaluate((element) => { element.scrollTop = 32; });
    await expect.poll(() => heading.evaluate((element) => element.getBoundingClientRect().top)).toBeLessThan(
      await scroll.evaluate((element) => element.getBoundingClientRect().top),
    );
    await expect(header).not.toHaveClass(/app-header-overlap|app-header-condensed/);
    await scroll.evaluate((element) => { element.scrollTop = 44; });
    await expect(header).toHaveClass(/app-header-overlap/);
    await expect(header).not.toHaveClass(/app-header-condensed/);
    await page.screenshot({ path: testInfo.outputPath("privacy-heading-overlap.png") });
    await scroll.evaluate((element) => { element.scrollTop = 100; });
    await expect(header).toHaveClass(/app-header-condensed/);
    await scroll.evaluate((element) => { element.scrollTop = 0; });
    await expect(header).not.toHaveClass(/app-header-overlap|app-header-condensed/);
  } finally {
    await harness.stop();
  }
});
