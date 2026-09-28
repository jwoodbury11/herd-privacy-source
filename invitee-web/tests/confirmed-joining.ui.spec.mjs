import { expect, test } from "@playwright/test";
import { startBrowserAcceptanceHarness } from "../scripts/browser-acceptance-harness.mjs";
import { testAccountNameForAlias } from "../lib/backend/test-accounts.mjs";

test("an open attendee screen picks up conditional promotion after a different guest joins", async ({ browser }) => {
  const harness = await startBrowserAcceptanceHarness();
  const context = await browser.newContext();
  const actorContext = await browser.newContext();
  const conditionalContext = await browser.newContext();
  try {
    const sessions = new Map();
    const views = new Map();
    const request = async (path, digit, body) => {
      const response = await fetch(new URL(path, harness.baseUrl), {
        method: body ? "PUT" : "GET",
        headers: { authorization: `Bearer ${sessions.get(digit)}`, "content-type": "application/json" },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      expect(response.ok, await response.clone().text()).toBeTruthy();
      return response.json();
    };
    for (const digit of ["2", "3", "4", "5", "6"]) {
      const response = await fetch(new URL("/api/auth/request-code", harness.baseUrl), {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ phoneNumber: digit }),
      });
      sessions.set(digit, (await response.json()).accessToken);
      const body = await request("/api/events", digit);
      views.set(digit, body.events.find((event) => event.title === harness.scenario.title));
    }
    const reply = (digit, minimumParticipants) => request(`/api/invites/${views.get(digit).inviteToken}/ballot`, digit, {
      response: "going", minimumParticipants, requiredGroups: [],
    });
    await reply("2", 6);
    for (const digit of ["3", "4", "5"]) await reply(digit, 2);
    const eventId = views.get("2").id;
    await harness.database.prepare("UPDATE events SET event_date = ?, rsvp_deadline = ? WHERE id = ?")
      .bind(new Date(Date.now() - 3600_000).toISOString(), new Date(Date.now() - 7200_000).toISOString(), eventId).run();
    const observer = await context.newPage();
    await observer.goto(harness.baseUrl.href);
    await observer.getByLabel("Sign in with phone number").fill("1");
    await observer.getByRole("button", { name: "Text me a code" }).click();
    await observer.getByRole("button", { name: `Open ${harness.scenario.title}` }).click();
    await expect(observer.getByTestId("unmet-requirements-callout")).toHaveCount(0);
    await observer.getByText("See the full guest list", { exact: true }).click();
    const conditionalRow = observer.locator(".person-row", { hasText: testAccountNameForAlias("2") });
    await expect(conditionalRow).toContainText("Can’t commit");
    await expect(observer.getByTestId("add-event-attendees")).toBeVisible();
    await conditionalContext.addCookies([{
      name: "herd_session", value: sessions.get("2"), url: harness.baseUrl.href,
      httpOnly: true, sameSite: "Lax",
    }]);
    const conditionalGuest = await conditionalContext.newPage();
    await conditionalGuest.goto(harness.baseUrl.href);
    await conditionalGuest.getByRole("button", { name: `Open ${harness.scenario.title}` }).click();
    const callout = conditionalGuest.getByTestId("unmet-requirements-callout");
    await expect(callout).toContainText("You’re not committed yet");
    await expect(callout).toContainText("your status will automatically change from “Can’t commit” to “Going.”");
    await callout.screenshot({ path: test.info().outputPath("unmet-requirements-card.png") });
    // Editing the unsaved choice must not change the notice about the saved reply.
    await conditionalGuest.getByRole("radio", { name: /Can’t commit/ }).click();
    await expect(callout).toBeVisible();
    await harness.database.prepare("UPDATE events SET event_date = ? WHERE id = ?")
      .bind(new Date(Date.now() - 86400_000).toISOString(), eventId).run();
    await expect(callout).toHaveCount(0, { timeout: 7000 });
    await harness.database.prepare("UPDATE events SET event_date = ? WHERE id = ?")
      .bind(new Date(Date.now() - 3600_000).toISOString(), eventId).run();
    await expect(callout).toBeVisible({ timeout: 7000 });
    await reply("6", 2);
    await expect(callout).toHaveCount(0, { timeout: 7000 });
    await expect(conditionalRow).toContainText("Going", { timeout: 7000 });
    await expect(observer.getByRole("heading", { name: "Attendees", exact: true })).toBeVisible();

    const lateGuest = await actorContext.newPage();
    await lateGuest.goto(harness.baseUrl.href);
    await lateGuest.getByLabel("Sign in with phone number").fill("9");
    await lateGuest.getByRole("button", { name: "Text me a code" }).click();
    await lateGuest.getByRole("button", { name: `Open ${harness.scenario.title}` }).click();
    await expect(lateGuest.getByTestId("unmet-requirements-callout")).toHaveCount(0);
    await expect(lateGuest.locator(".confirmed-reply-edit-guard")).toHaveCount(0);
    await lateGuest.getByRole("radio", { name: /Can’t commit/ }).click();
    await lateGuest.getByRole("button", { name: "Send my private reply", exact: true }).click();
    await expect(lateGuest.getByText("Thanks for responding", { exact: true })).toBeVisible();
    await lateGuest.getByRole("button", { name: "View invitation", exact: true }).click();
    await expect(lateGuest.getByRole("radio", { name: /Can’t commit/ })).toHaveAttribute("aria-checked", "true");
    await expect(lateGuest.getByTestId("unmet-requirements-callout")).toHaveCount(0);
  } finally {
    await context.close();
    await actorContext.close();
    await conditionalContext.close();
    await harness.stop();
  }
});
