import { expect, test } from "@playwright/test";

import { startBrowserAcceptanceHarness } from "../scripts/browser-acceptance-harness.mjs";

test("hosting on web opens the approved Herd App Store listing", async ({
  browser,
}) => {
  const harness = await startBrowserAcceptanceHarness();
  const context = await browser.newContext();

  try {
    const page = await context.newPage();
    await page.goto(harness.baseUrl.href);
    await page.getByLabel("Sign in with phone number").fill("1");
    await page.getByRole("button", { name: "Text me a code" }).click();
    await expect(page.getByRole("heading", { name: "Herd events" })).toBeVisible();

    await page.getByRole("button", { name: "New event" }).click();

    const heading = page.getByRole("heading", { name: "Download Herd" });
    await expect(heading).toBeVisible();
    const headingBox = await heading.boundingBox();
    expect(headingBox?.height).toBeLessThan(48);
    await expect(page.getByText(/choose guests from your contacts and host an event/u)).toBeVisible();
    await expect(page.getByText(/coming soon|awaiting approval from Apple/u)).toHaveCount(0);
    const download = page.getByRole("link", { name: "Get Herd" });
    await expect(download).toHaveAttribute("href", "https://apps.apple.com/app/id6793711077");
    await expect(download).toBeVisible();
    await expect(page.locator(".host-app-back")).toBeEnabled();
    await page.route("https://apps.apple.com/**", (route) => route.fulfill({
      contentType: "text/html",
      body: "<h1>Herd App Store</h1>",
    }));
    await download.click();
    await expect(page).toHaveURL("https://apps.apple.com/app/id6793711077");

  } finally {
    await context.close();
    await harness.stop();
  }
});
