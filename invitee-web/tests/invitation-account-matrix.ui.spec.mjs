import { expect, test } from "@playwright/test";

import { startBrowserQaHarness } from "../scripts/browser-qa-harness.mjs";

test.describe.configure({ mode: "serial" });

let harness;
const authenticatedCookies = [];
const authenticatedContexts = [];
const authenticatedPages = [];
let authenticationBaseline;

test.beforeAll(async () => {
  harness = await startBrowserQaHarness();
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
    hasText: `QA account ${targetAlias}`,
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
  { reply: "yes", minimum: 10, groups: [[1], [2, 3]] },
];

for (let accountIndex = 0; accountIndex < 9; accountIndex += 1) {
  test(`signed-out QA account ${accountIndex + 1} is denied during authentication for every other invitation`, async ({
    browser,
  }) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    let checkedPairs = 0;

    for (let inviteIndex = 0; inviteIndex < 9; inviteIndex += 1) {
      if (inviteIndex === accountIndex) continue;
      const invitation = new URL(
        harness.scenario.invitePaths[inviteIndex],
        harness.baseUrl,
      );
      await page.goto(invitation.href);
      await expect(
        page.getByRole("heading", { name: harness.scenario.title, level: 1 }),
      ).toBeVisible();
      await page.getByLabel("Phone number").fill(String(accountIndex + 1));
      await page.getByRole("button", { name: "Text me a code" }).click();
      await expect(page.getByRole("alert")).toHaveText(
        "This invitation and phone number don’t match. Open the original link and enter the number it was sent to.",
      );
      await expect(page).toHaveURL(invitation.href);
      checkedPairs += 1;
    }

    await context.close();
    expect(checkedPairs).toBe(8);
  });
}

test("all 72 signed-out invitation mismatches create no user, session, or challenge", async () => {
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

for (let index = 0; index < acceptanceScenarios.length; index += 1) {
  test(`QA account ${index + 1} opens its own link and saves its encrypted acceptance`, async ({
    browser,
  }) => {
    const alias = index + 1;
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
    await page.getByLabel("Phone number").fill(String(alias));
    await page.getByRole("button", { name: "Text me a code" }).click();
    await expectInvitation(page);

    if (scenario.reply === "no") {
      const cannotCommit = page.getByRole("radio", { name: /Can’t commit/u });
      await cannotCommit.click();
      await expect(cannotCommit).toHaveAttribute("aria-checked", "true");
    } else {
      const going = page.getByRole("radio", { name: /I’m down if at least/u });
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
        const candidates = group.map((offset) => ((alias + offset - 1) % 9) + 1);
        await addConditionGroup(page, candidates);
      }
    }

    await page.getByRole("button", { name: "Send my encrypted reply" }).click();
    await expect(
      page.getByRole("heading", { name: "Thanks for responding" }),
    ).toBeVisible();
    await expect(page.getByText(
      scenario.reply === "yes" ? "Going" : "Can’t commit",
      { exact: true },
    )).toBeVisible();
    expect(pageErrors, `browser errors for QA account ${alias}`).toEqual([]);
    authenticatedCookies[index] = await context.cookies();
    authenticatedContexts[index] = context;
    authenticatedPages[index] = page;
  });
}

test("all nine UI acceptances are authorized and published without a log gap", async () => {
  const stored = await harness.database
    .prepare(
      `SELECT
         COUNT(*) AS responseCount,
         COUNT(DISTINCT invitee_id) AS respondingInviteeCount,
         SUM(CASE WHEN revision = 1 THEN 1 ELSE 0 END) AS firstRevisionCount,
         SUM(CASE WHEN response_signing_public_key IS NOT NULL
                   AND response_signature IS NOT NULL THEN 1 ELSE 0 END) AS authorizedCount
       FROM response_envelopes
       WHERE event_id = ?`,
    )
    .bind(harness.scenario.eventId)
    .first();
  expect(stored).toEqual({
    responseCount: 9,
    respondingInviteeCount: 9,
    firstRevisionCount: 9,
    authorizedCount: 9,
  });

  const transparency = await harness.database
    .prepare(
      `SELECT
         COUNT(*) AS entryCount,
         COUNT(receipt_signature) AS signedEntryCount,
         MIN(log_index) AS firstIndex,
         MAX(log_index) AS lastIndex
       FROM response_transparency_entries`,
    )
    .first();
  expect(transparency).toEqual({
    entryCount: 9,
    signedEntryCount: 9,
    firstIndex: 1,
    lastIndex: 9,
  });
});

for (let index = 0; index < acceptanceScenarios.length; index += 1) {
  test(`QA account ${index + 1} revises its encrypted reply on the same device`, async () => {
    const original = acceptanceScenarios[index];
    const page = authenticatedPages[index];
    await page.getByRole("button", { name: "View invitation" }).click();
    await expectInvitation(page);

    if (original.reply === "yes") {
      const cannotCommit = page.getByRole("radio", { name: /Can’t commit/u });
      await cannotCommit.click();
      await expect(cannotCommit).toHaveAttribute("aria-checked", "true");
    } else {
      const going = page.getByRole("radio", { name: /I’m down if at least/u });
      await going.click();
      await expect(going).toHaveAttribute("aria-checked", "true");
    }

    await page.getByRole("button", { name: "Send my encrypted reply" }).click();
    await expect(
      page.getByRole("heading", { name: "Thanks for responding" }),
    ).toBeVisible();
    await expect(page.getByText(
      original.reply === "yes" ? "Can’t commit" : "Going",
      { exact: true },
    )).toBeVisible();
  });
}

test("all nine revisions are authorized and extend the signed log without a gap", async () => {
  const stored = await harness.database
    .prepare(
      `SELECT
         COUNT(*) AS responseCount,
         COUNT(DISTINCT invitee_id) AS respondingInviteeCount,
         SUM(CASE WHEN revision = 2 THEN 1 ELSE 0 END) AS secondRevisionCount,
         SUM(CASE WHEN response_signing_public_key IS NOT NULL
                   AND response_signature IS NOT NULL THEN 1 ELSE 0 END) AS authorizedCount
       FROM response_envelopes
       WHERE event_id = ?`,
    )
    .bind(harness.scenario.eventId)
    .first();
  expect(stored).toEqual({
    responseCount: 18,
    respondingInviteeCount: 9,
    secondRevisionCount: 9,
    authorizedCount: 18,
  });

  const transparency = await harness.database
    .prepare(
      `SELECT
         COUNT(*) AS entryCount,
         COUNT(receipt_signature) AS signedEntryCount,
         MIN(log_index) AS firstIndex,
         MAX(log_index) AS lastIndex
       FROM response_transparency_entries`,
    )
    .first();
  expect(transparency).toEqual({
    entryCount: 18,
    signedEntryCount: 18,
    firstIndex: 1,
    lastIndex: 18,
  });
});

for (let accountIndex = 0; accountIndex < 9; accountIndex += 1) {
  test(`QA account ${accountIndex + 1} is denied by every other invitation link`, async ({
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

    let checkedPairs = 0;
    for (let inviteIndex = 0; inviteIndex < 9; inviteIndex += 1) {
      if (inviteIndex === accountIndex) continue;
      await page.goto(
        new URL(harness.scenario.invitePaths[inviteIndex], harness.baseUrl).href,
      );
      await expect(page.getByRole("heading", {
        name: "Switch accounts to open this invitation",
      })).toBeVisible();
      await expect(page.getByRole("button", { name: "Switch account" })).toBeVisible();
      checkedPairs += 1;
    }
    await context.close();
    expect(checkedPairs).toBe(8);
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
  const secondInvite = new URL(harness.scenario.invitePaths[1], harness.baseUrl);
  await page.goto(secondInvite.href);
  await expect(page.getByRole("button", { name: "Switch account" })).toBeVisible();
  await page.getByRole("button", { name: "Switch account" }).click();

  await expect(page).toHaveURL(secondInvite.href);
  await expect(
    page.getByRole("heading", { name: harness.scenario.title, level: 1 }),
  ).toBeVisible();
  await page.getByLabel("Phone number").fill("2");
  await page.getByRole("button", { name: "Text me a code" }).click();
  await expectInvitation(page);
  await context.close();
});
