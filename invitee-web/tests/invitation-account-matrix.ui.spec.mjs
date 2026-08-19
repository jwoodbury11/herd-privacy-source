import { expect, test } from "@playwright/test";

import { testAccountNameForAlias } from "../lib/backend/test-accounts.mjs";
import { startBrowserAcceptanceHarness } from "../scripts/browser-acceptance-harness.mjs";

test.describe.configure({ mode: "serial" });

let harness;
const authenticatedCookies = [];
const authenticatedContexts = [];
const authenticatedPages = [];
let authenticationBaseline;

test.beforeAll(async () => {
  harness = await startBrowserAcceptanceHarness();
  authenticationBaseline = await harness.database
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM users) AS userCount,
         (SELECT COUNT(*) FROM sessions) AS sessionCount,
         (SELECT COUNT(*) FROM challenges) AS challengeCount`,
    )
    .first();
});

test.afterAll(async () => {
  await Promise.all(authenticatedContexts.map((context) => context.close()));
  await harness?.stop();
});

async function expectInvitation(page) {
  await expect(
    page.getByRole("heading", { name: harness.scenario.title, level: 2 }),
  ).toBeVisible();
  await expect(page.getByRole("heading", {
    name: "Your reply",
    exact: true,
  })).toBeVisible();
}

async function chooseCondition(page, targetAlias) {
  const dialog = page.getByRole("dialog", { name: "Who needs to be there?" });
  await expect(dialog).toBeVisible();
  await dialog.locator(".sheet-list button", {
    hasText: testAccountNameForAlias(String(targetAlias)),
  }).click();
  await expect(dialog).toBeHidden();
}

async function addConditionGroup(page, aliases) {
  const addRequired = page.getByRole("button", {
    name: /Add (?:a|another) required person condition/u,
  });
  await addRequired.click();
  await chooseCondition(page, aliases[0]);
  for (const alias of aliases.slice(1)) {
    await page.getByRole("button", { name: "Add an OR alternative" }).last().click();
    await chooseCondition(page, alias);
  }
}

const acceptanceScenarios = [
  { reply: "no" },
  { reply: "yes", minimum: 4, groups: [] },
  { reply: "yes", minimum: 5, groups: [[1]] },
  { reply: "yes", minimum: 6, groups: [[1, 2]] },
  { reply: "yes", minimum: 7, groups: [[1], [2]] },
  { reply: "yes", minimum: 8, groups: [[1, 2], [3]] },
  { reply: "no" },
  { reply: "yes", minimum: 9, groups: [[1, 2, 3]] },
];
const inviteeAliases = Array.from({ length: 8 }, (_, index) => index + 2);

for (let accountIndex = 0; accountIndex < 9; accountIndex += 1) {
  test(`signed-out test account ${accountIndex + 1} is denied for another account's invitation`, async ({
    browser,
  }) => {
    const context = await browser.newContext();
    const page = await context.newPage();

    const accountAlias = accountIndex + 1;
    const inviteIndex = accountAlias === 1 ? 0 : accountIndex % inviteeAliases.length;
    const invitation = new URL(
      harness.scenario.invitePaths[inviteIndex],
      harness.baseUrl,
    );
    await page.goto(invitation.href);
    await expect(
      page.getByRole("heading", { name: harness.scenario.title, level: 1 }),
    ).toBeVisible();
    await page.getByLabel("Sign in with phone number").fill(String(accountAlias));
    await page.getByRole("button", { name: "Text me a code" }).click();
    await expect(page.getByRole("alert")).toHaveText(
      "This invitation and phone number don’t match. Open the original link and enter the number it was sent to.",
    );
    await expect(page).toHaveURL(invitation.href);

    await context.close();
  });
}

test("signed-out invitation mismatches create no user, session, or challenge", async () => {
  const current = await harness.database
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM users) AS userCount,
         (SELECT COUNT(*) FROM sessions) AS sessionCount,
         (SELECT COUNT(*) FROM challenges) AS challengeCount`,
    )
    .first();
  expect(current).toEqual(authenticationBaseline);
});

test("test account 1 signs in as the host and sees the production-shaped event", async ({
  browser,
}) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(harness.baseUrl.href);
  await page.getByLabel("Sign in with phone number").fill("1");
  await page.getByRole("button", { name: "Text me a code" }).click();
  await expect(page.getByRole("heading", { name: "Herd events" })).toBeVisible();
  await expect(page.getByText(harness.scenario.title, { exact: true })).toBeVisible();
  await context.close();
});

for (let index = 0; index < acceptanceScenarios.length; index += 1) {
  test(`test account ${inviteeAliases[index]} opens its own link and saves its private acceptance`, async ({
    browser,
  }) => {
    const alias = inviteeAliases[index];
    const scenario = acceptanceScenarios[index];
    const context = await browser.newContext();
    const page = await context.newPage();
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));

    await page.goto(
      new URL(harness.scenario.invitePaths[index], harness.baseUrl).href,
    );
    await expect(
      page.getByRole("heading", { name: harness.scenario.title, level: 1 }),
    ).toBeVisible();
    await page.getByLabel("Sign in with phone number").fill(String(alias));
    await page.getByRole("button", { name: "Text me a code" }).click();
    await expectInvitation(page);

    if (index === 0) {
      await test.step("the reply preview dismisses from the visible edge of OK", async () => {
        await page.getByRole("button", { name: "Preview how others see it" }).click();
        const dialog = page.getByRole("dialog", {
          name: "How your reply shows up to others",
        });
        await expect(dialog).toBeVisible();
        await expect(dialog.getByText(
          "This user has not responded to their only confirmed event invitation.",
          { exact: true },
        )).toBeVisible();
        await expect(dialog.getByText(
          "Avoid a no response at all costs. No responses are why fun events that could have happened don’t happen.",
          { exact: true },
        )).toBeVisible();
        const dismiss = page.getByTestId("reply-preview-dismiss");
        const box = await dismiss.boundingBox();
        expect(box).not.toBeNull();
        expect(box.width).toBeGreaterThan(300);
        await page.mouse.click(box.x + 8, box.y + box.height / 2);
        await expect(dialog).toBeHidden();
      });
    }

    if (scenario.reply === "no") {
      const cannotCommit = page.getByRole("radio", { name: /Can’t commit/u });
      await cannotCommit.click();
      await expect(cannotCommit).toHaveAttribute("aria-checked", "true");
    } else {
      const going = page.getByRole("radio", { name: /I’m down if/u });
      await going.click();
      await expect(going).toHaveAttribute("aria-checked", "true");
      for (
        let minimum = 4;
        minimum < scenario.minimum;
        minimum += 1
      ) {
        await page.getByRole("button", { name: "Increase minimum" }).click();
      }
      for (const group of scenario.groups) {
        const candidates = group.map(
          (offset) => inviteeAliases[(index + offset) % inviteeAliases.length],
        );
        await addConditionGroup(page, candidates);
      }
    }

    await page.getByRole("button", { name: "Send my private reply" }).click();
    await expect(
      page.getByRole("heading", { name: "Thanks for responding" }),
    ).toBeVisible();
    await expect(page.getByText(
      scenario.reply === "yes" ? "Going" : "Can’t commit",
      { exact: true },
    )).toBeVisible();
    await expect(page.getByRole("heading", {
      name: "This is how your saved reply will show up to others:",
    })).toBeVisible();
    await expect(page.getByText("If the event is confirmed:", { exact: true })).toBeVisible();
    await expect(page.getByText("This event was not confirmed", { exact: true })).toBeVisible();
    await expect(page.getByText("Zero information is shown to anybody.", { exact: true })).toBeVisible();
    expect(pageErrors, `browser errors for test account ${alias}`).toEqual([]);
    authenticatedCookies[index] = await context.cookies();
    authenticatedContexts[index] = context;
    authenticatedPages[index] = page;
  });
}

test("all eight invitee UI acceptances create one deidentified ballot each", async () => {
  const stored = await harness.database
    .prepare(
      `SELECT
         COUNT(*) AS revisionCount,
         COUNT(DISTINCT ballot_id) AS ballotCount,
         SUM(CASE WHEN revision = 1 THEN 1 ELSE 0 END) AS firstRevisionCount,
         SUM(CASE WHEN protocol_version = 2 AND key_version = 1
                   AND source = 'user' THEN 1 ELSE 0 END) AS validProtocolCount
       FROM ballot_revisions
       WHERE event_id = ?`,
    )
    .bind(harness.scenario.eventId)
    .first();
  expect(stored).toEqual({
    revisionCount: 8,
    ballotCount: 8,
    firstRevisionCount: 8,
    validProtocolCount: 8,
  });
});

for (let index = 0; index < acceptanceScenarios.length; index += 1) {
  test(`test account ${inviteeAliases[index]} revises its private reply`, async () => {
    const original = acceptanceScenarios[index];
    const page = authenticatedPages[index];
    await page.getByRole("button", { name: "View invitation" }).click();
    await expectInvitation(page);

    if (original.reply === "yes") {
      const cannotCommit = page.getByRole("radio", { name: /Can’t commit/u });
      await cannotCommit.click();
      await expect(cannotCommit).toHaveAttribute("aria-checked", "true");
    } else {
      const going = page.getByRole("radio", { name: /I’m down if/u });
      await going.click();
      await expect(going).toHaveAttribute("aria-checked", "true");
    }

    await page.getByRole("button", { name: "Update my private reply" }).click();
    await expect(
      page.getByRole("heading", { name: "Thanks for responding" }),
    ).toBeVisible();
    await expect(page.getByText(
      original.reply === "yes" ? "Can’t commit" : "Going",
      { exact: true },
    )).toBeVisible();
  });
}

test("all eight revisions append to the same eight ballots", async () => {
  const stored = await harness.database
    .prepare(
      `SELECT
         COUNT(*) AS revisionCount,
         COUNT(DISTINCT ballot_id) AS ballotCount,
         SUM(CASE WHEN revision = 2 THEN 1 ELSE 0 END) AS secondRevisionCount,
         SUM(CASE WHEN source = 'user' AND correction_reason IS NULL THEN 1 ELSE 0 END) AS userRevisionCount
       FROM ballot_revisions
       WHERE event_id = ?`,
    )
    .bind(harness.scenario.eventId)
    .first();
  expect(stored).toEqual({
    revisionCount: 16,
    ballotCount: 8,
    secondRevisionCount: 8,
    userRevisionCount: 16,
  });
});

for (let accountIndex = 0; accountIndex < acceptanceScenarios.length; accountIndex += 1) {
  test(`signed-in test account ${inviteeAliases[accountIndex]} is denied by another account's invitation link`, async ({
    browser,
  }) => {
    const context = await browser.newContext({
      storageState: {
        cookies: authenticatedCookies[accountIndex],
        origins: [],
      },
    });
    const page = await context.newPage();
    await page.goto(harness.baseUrl.href);
    await expect(page.getByRole("heading", { name: "Herd events" })).toBeVisible();

    const inviteIndex = (accountIndex + 1) % harness.scenario.invitePaths.length;
    await page.goto(
      new URL(harness.scenario.invitePaths[inviteIndex], harness.baseUrl).href,
    );
    await expect(page.getByRole("heading", {
      name: "Switch accounts to open this invitation",
    })).toBeVisible();
    await expect(page.getByRole("button", { name: "Switch account" })).toBeVisible();
    await context.close();
  });
}

test("switch account preserves the invitation and opens it with the matching account", async ({
  browser,
}) => {
  await harness.database.batch([
    harness.database.prepare("DELETE FROM auth_phone_rate_limits"),
    harness.database.prepare("DELETE FROM auth_ip_rate_limits"),
  ]);
  const context = await browser.newContext({
    storageState: { cookies: authenticatedCookies[0], origins: [] },
  });
  const page = await context.newPage();
  await page.goto(harness.baseUrl.href);
  await expect(page.getByRole("heading", { name: "Herd events" })).toBeVisible();
  let delayedSessionRestore = false;
  await page.route("**/api/me", async (route) => {
    if (delayedSessionRestore) {
      await route.continue();
      return;
    }
    delayedSessionRestore = true;
    await new Promise((resolve) => setTimeout(resolve, 500));
    await route.continue().catch(() => undefined);
  });
  const secondInvite = new URL(harness.scenario.invitePaths[1], harness.baseUrl);
  await page.goto(secondInvite.href);
  await expect(page.getByRole("button", { name: "Switch account" })).toBeVisible();
  await page.getByRole("button", { name: "Switch account" }).click();

  await expect(page).toHaveURL(secondInvite.href);
  await expect(
    page.getByRole("heading", { name: harness.scenario.title, level: 1 }),
  ).toBeVisible();
  await page.getByLabel("Sign in with phone number").fill("3");
  await page.getByRole("button", { name: "Text me a code" }).click();
  await expectInvitation(page);
  await context.close();
});

test("a fresh browser opens and revises the same account-wide ballot without device switching", async ({
  browser,
}) => {
  await harness.database.batch([
    harness.database.prepare("DELETE FROM auth_phone_rate_limits"),
    harness.database.prepare("DELETE FROM auth_ip_rate_limits"),
  ]);
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(
    new URL(harness.scenario.invitePaths[0], harness.baseUrl).href,
  );
  await page.getByLabel("Sign in with phone number").fill("2");
  await page.getByRole("button", { name: "Text me a code" }).click();
  await expectInvitation(page);
  const saved = page.getByRole("radio", { name: /I’m down if/u });
  await expect(saved).toHaveAttribute("aria-checked", "true");
  const cannotCommit = page.getByRole("radio", { name: /Can’t commit/u });
  await cannotCommit.click();
  await page.getByRole("button", { name: "Update my private reply" }).click();
  await expect(
    page.getByRole("heading", { name: "Thanks for responding" }),
  ).toBeVisible();

  const after = await harness.database
    .prepare(
      `SELECT COUNT(*) AS revisionCount,
              COUNT(DISTINCT ballot_id) AS ballotCount,
              SUM(CASE WHEN revision = 3 THEN 1 ELSE 0 END) AS thirdRevisionCount
       FROM ballot_revisions
       WHERE event_id = ?`,
    )
    .bind(harness.scenario.eventId)
    .first();
  expect(after).toEqual({
    revisionCount: 17,
    ballotCount: 8,
    thirdRevisionCount: 1,
  });
  await context.close();
});

test("an expired session returns to sign-in without losing the invitation", async ({
  browser,
}) => {
  await harness.database.batch([
    harness.database.prepare("DELETE FROM auth_phone_rate_limits"),
    harness.database.prepare("DELETE FROM auth_ip_rate_limits"),
  ]);
  const invitation = new URL(harness.scenario.invitePaths[2], harness.baseUrl);
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(invitation.href);
  await page.getByLabel("Sign in with phone number").fill("4");
  await page.getByRole("button", { name: "Text me a code" }).click();
  await expectInvitation(page);

  await harness.database
    .prepare(
      `UPDATE sessions
       SET revoked_at = datetime('now')
       WHERE user_id = (
         SELECT id FROM users WHERE phone_number = '+14155550104'
       ) AND revoked_at IS NULL`,
    )
    .run();
  await page.getByRole("radio", { name: /I’m down if/u }).click();
  await page.getByRole("button", { name: "Update my private reply" }).click();

  await expect(page).toHaveURL(invitation.href);
  await expect(page.getByRole("heading", {
    name: harness.scenario.title,
    level: 1,
  })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveText(
    "Your session expired. Sign in again to continue.",
  );
  await harness.database.batch([
    harness.database.prepare("DELETE FROM auth_phone_rate_limits"),
    harness.database.prepare("DELETE FROM auth_ip_rate_limits"),
  ]);
  await page.getByLabel("Sign in with phone number").fill("4");
  await page.getByRole("button", { name: "Text me a code" }).click();
  await expectInvitation(page);
  await context.close();
});
