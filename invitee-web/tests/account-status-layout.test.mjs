import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("account status icons, titles, and state markers share one grid", async () => {
  const [page, css, swiftHome] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/HomeView.swift", import.meta.url), "utf8"),
  ]);

  assert.match(page, /className="account-status-summary-icon"/u);
  assert.match(css, /\.account-status-summary-icon \{[^}]*width: 34px;[^}]*height: 34px/u);
  assert.match(css, /\.account-status-summary-icon svg \{[^}]*width: 17px;[^}]*height: 17px/u);
  assert.match(css, /\.account-status-summary h2 \{[^}]*font-size: 13px/u);
  assert.match(css, /\.account-status-row-copy strong \{[^}]*font-size: 13px/u);
  assert.match(css, /\.account-status-state-icon \{[^}]*align-self: center/u);

  const summary = swiftHome.slice(
    swiftHome.indexOf("private var statusSummary"),
    swiftHome.indexOf("private var summaryDetail"),
  );
  const row = swiftHome.slice(
    swiftHome.indexOf("private struct StatusRow"),
    swiftHome.indexOf("private struct ProfileView"),
  );
  assert.match(summary, /font\(\.system\(size: 16, weight: \.medium\)\)[\s\S]*frame\(width: 34, height: 34\)/u);
  assert.match(summary, /font\(\.subheadline\.weight\(\.semibold\)\)/u);
  assert.match(row, /HStack\(alignment: \.center, spacing: 12\)/u);
  assert.match(row, /Spacer\(minLength: 8\)[\s\S]*Image\(systemName: state\.symbol\)[\s\S]*frame\(width: 18, height: 34\)/u);
});
