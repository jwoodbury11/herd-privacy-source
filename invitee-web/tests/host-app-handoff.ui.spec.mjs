import { expect, test } from "@playwright/test";

import { startBrowserAcceptanceHarness } from "../scripts/browser-acceptance-harness.mjs";

test("hosting on web explains the iPhone requirement without offering an unavailable download", async ({
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

    await page.getByRole("button", { name: "Host an event" }).click();

    const heading = page.getByRole("heading", { name: "Download Herd" });
    await expect(heading).toBeVisible();
    const headingBox = await heading.boundingBox();
    expect(headingBox?.height).toBeLessThan(48);
    await expect(page.getByText(/choose guests from your contacts and host an event/u)).toBeVisible();
    await expect(page.getByRole("status")).toContainText("iPhone app coming soon");
    await expect(page.getByRole("status")).toContainText("awaiting approval from Apple");
    await expect(page.getByRole("button", { name: "Download app" })).toBeDisabled();
    await expect(page.locator(".host-app-back")).toBeEnabled();
  } finally {
    await context.close();
    await harness.stop();
  }
});
