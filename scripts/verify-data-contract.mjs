#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

function fail(message) {
  process.stderr.write(`Data-contract verification failed: ${message}\n`);
  process.exitCode = 1;
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function sameValues(left, right) {
  const a = sorted(left);
  const b = sorted(right);
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

const inventoryPath = path.join(repositoryRoot, "security/data-inventory.json");
const inventory = JSON.parse(await readFile(inventoryPath, "utf8"));
if (inventory.schemaVersion !== 1 || !inventory.tables) {
  fail("the machine-readable inventory has an unsupported format");
} else {
  const snapshotPath = path.join(repositoryRoot, inventory.databaseSnapshot);
  const snapshot = JSON.parse(await readFile(snapshotPath, "utf8"));
  const schemaTables = Object.keys(snapshot.tables ?? {});
  const inventoryTables = Object.keys(inventory.tables);
  if (!sameValues(schemaTables, inventoryTables)) {
    fail("the inventory does not cover exactly every table in the release schema");
  }

  const classes = [
    "ordinaryMetadata",
    "pseudonymousOrHashed",
    "sensitivePlaintext",
    "sealed",
  ];
  for (const tableName of schemaTables) {
    const table = snapshot.tables[tableName];
    const entry = inventory.tables[tableName];
    if (!entry || typeof entry.purpose !== "string" || typeof entry.retention !== "string") {
      fail(`${tableName} has no purpose or retention policy`);
      continue;
    }
    const classified = [];
    for (const classification of classes) {
      if (!Array.isArray(entry[classification])) {
        fail(`${tableName}.${classification} is not an array`);
        continue;
      }
      classified.push(...entry[classification]);
    }
    if (new Set(classified).size !== classified.length) {
      fail(`${tableName} classifies at least one column more than once`);
    }
    if (!sameValues(classified, Object.keys(table.columns ?? {}))) {
      fail(`${tableName} does not classify exactly every schema column`);
    }
  }

  for (const forbiddenTable of ["rsvps", "private_responses", "response_conditions"]) {
    if (snapshot.tables?.[forbiddenTable]) {
      fail(`forbidden readable response table ${forbiddenTable} exists`);
    }
  }
  const responseColumns = Object.keys(
    snapshot.tables?.response_envelopes?.columns ?? {},
  );
  for (const forbiddenColumn of [
    "reply",
    "response",
    "answer",
    "minimum_participants",
    "condition_groups",
    "required_groups",
  ]) {
    if (responseColumns.includes(forbiddenColumn)) {
      fail(`response_envelopes contains readable column ${forbiddenColumn}`);
    }
  }
  const responseInventory = inventory.tables.response_envelopes;
  if (
    responseInventory.sensitivePlaintext.length !== 0 ||
    !sameValues(responseInventory.sealed, [
      "evaluator_key_wrap",
      "payload_ciphertext",
      "user_key_wrap",
    ])
  ) {
    fail("the private response inventory no longer matches the sealed-only contract");
  }
}

if (!process.exitCode) {
  process.stdout.write("Data-contract verification passed.\n");
}
