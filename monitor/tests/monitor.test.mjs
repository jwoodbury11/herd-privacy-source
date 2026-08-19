import assert from "node:assert/strict";
import { sign as cryptoSign } from "node:crypto";
import test from "node:test";

import { canonicalJson, verifyTarget } from "../src/core.mjs";
import { makeReleaseFixture } from "../../release/tests/fixture.mjs";

const LOG_ID = "herd-response-log-v1";
const LOG_HEAD_DOMAIN = "HERD-TRANSPARENCY-LOG-HEAD-SIGNATURE-V1";
const GENESIS_HASH = Buffer.alloc(32).toString("base64url");

function logEntry(index, previousEntryHash, entryHash, keyPair) {
  const unsignedHead = {
    protocolVersion: 1,
    logId: LOG_ID,
    treeSize: index,
    headEntryHash: entryHash,
    generatedAt: `2026-08-02T00:00:0${index}.000Z`,
    signingKeyId: keyPair.descriptor.keyId,
  };
  const signature = cryptoSign(
    "sha256",
    Buffer.from(`${LOG_HEAD_DOMAIN}\0${JSON.stringify(unsignedHead)}`),
    { key: keyPair.privatePem, dsaEncoding: "ieee-p1363" },
  ).toString("base64url");
  return {
    logIndex: index,
    previousEntryHash,
    entryHash,
    head: { ...unsignedHead, signature },
  };
}

function responseLogFixture(fixture) {
  const hashes = [1, 2, 3].map((value) => Buffer.alloc(32, value).toString("base64url"));
  const entries = [
    logEntry(1, GENESIS_HASH, hashes[0], fixture.keys.receiptTransparencySigning),
    logEntry(2, hashes[0], hashes[1], fixture.keys.receiptTransparencySigning),
    logEntry(3, hashes[1], hashes[2], fixture.keys.receiptTransparencySigning),
  ];
  const url = "https://app.herd.example/api/transparency/responses";
  fixture.target.responseTransparency = {
    url,
    logId: LOG_ID,
    signingKey: fixture.keys.receiptTransparencySigning.descriptor,
  };
  const page = (items) => {
    const bytes = Buffer.from(JSON.stringify({ protocolVersion: 1, logId: LOG_ID, entries: items }));
    return { bytes, mediaType: "application/json" };
  };
  fixture.responses.set(`${url}?after=0&limit=500`, page(entries));
  fixture.responses.set(`${url}?after=2&limit=500`, page([entries[2]]));
  return { url, hashes, entries, page };
}

function monitoredFixture(options = {}) {
  const fixture = makeReleaseFixture(options);
  fixture.responseLog = responseLogFixture(fixture);
  return fixture;
}

function mockFetch(responses, overrides = new Map()) {
  return async (input) => {
    const urlValue = new URL(String(input));
    urlValue.searchParams.delete("herd_sha256");
    const url = urlValue.toString();
    if (overrides.has(url)) return overrides.get(url);
    const record = responses.get(url);
    if (!record) return new Response("not found", { status: 404 });
    return new Response(record.bytes, {
      status: 200,
      headers: {
        "content-type": record.mediaType,
        "content-length": String(record.bytes.byteLength),
      },
    });
  };
}

async function successfulLiveAttestation(configuration, { now }) {
  assert.equal(configuration.origin, "https://evaluator.herd.example");
  assert.equal(
    configuration.manifest.trust.workload.attestationClaimPolicy.audience,
    "https://evaluator.herd.example/attestation",
  );
  assert.equal(
    configuration.rootCertificateDerBase64,
    Buffer.from("fixture-independent-attestation-root").toString("base64"),
  );
  return {
    verifiedAt: now().toISOString(),
    origin: configuration.origin,
    audience: configuration.manifest.trust.workload.attestationClaimPolicy.audience,
    imageDigest: `sha256:${configuration.manifest.trust.workload.imageDigest.value}`,
    keyBindingHash:
      configuration.manifest.trust.workload.attestationClaimPolicy.keyBindingHash,
    rootFingerprint:
      configuration.manifest.trust.workload.attestationRootFingerprint.value,
  };
}

function verifyMonitoredTarget(fixture, options = {}) {
  return verifyTarget(fixture.target, {
    liveAttestationVerifier: successfulLiveAttestation,
    ...options,
  });
}

test("verifies the independently pinned release, deployment, and deployed resource hashes", async () => {
  const fixture = monitoredFixture();
  const result = await verifyMonitoredTarget(fixture, {
    fetchImpl: mockFetch(fixture.responses),
    now: () => new Date("2026-08-02T12:00:00.000Z"),
  });
  assert.equal(result.ok, true);
  assert.equal(result.releaseId, fixture.releaseId);
  assert.equal(result.evaluatorKeyEpoch.identityBasis, "policy-measurement-v1");
  assert.equal(result.evaluatorAttestation.origin, "https://evaluator.herd.example");
  assert.equal(
    result.evaluatorKeyEpoch.workloadImageDigest,
    `sha256:${fixture.manifest.trust.workload.policyMeasurement.value}`,
  );
  assert.notEqual(
    result.evaluatorKeyEpoch.workloadImageDigest,
    `sha256:${fixture.manifest.trust.workload.imageDigest.value}`,
  );
  assert.deepEqual(result.resources.map(({ name }) => name), [
    "apple-app-site-association",
    "asset-manifest",
    "entry-document",
  ]);
  assert.deepEqual(
    result.releaseArtifacts.map(({ name }) => name),
    fixture.publishedArtifacts.map(([artifact]) => artifact.name).sort(),
  );
});

test("accepts a public release pointer from an explicitly pinned evidence origin", async () => {
  const fixture = monitoredFixture();
  const evidenceUrl = "https://evidence.example/releases/current/herd-release.json";
  fixture.responses.set(evidenceUrl, fixture.responses.get(fixture.wellKnownUrl));
  fixture.target.wellKnownUrl = evidenceUrl;
  const result = await verifyMonitoredTarget(fixture, {
    fetchImpl: mockFetch(fixture.responses),
    now: () => new Date("2026-08-02T12:00:00.000Z"),
  });
  assert.equal(result.ok, true);

  fixture.target.wellKnownUrl = "https://untrusted.example/herd-release.json";
  await assert.rejects(
    verifyMonitoredTarget(fixture, { fetchImpl: mockFetch(fixture.responses) }),
    /outside the configured web or evidence origins/u,
  );
});

test("production live attestation requires an independent root/origin and exact signed relay endpoint", async () => {
  const missing = monitoredFixture();
  delete missing.target.evaluatorAttestation;
  await assert.rejects(
    verifyTarget(missing.target, { fetchImpl: mockFetch(missing.responses) }),
    /requires an independently pinned evaluatorAttestation/u,
  );

  const malformedRoot = monitoredFixture();
  malformedRoot.target.evaluatorAttestation.rootCertificateDerBase64 = "not base64";
  await assert.rejects(
    verifyTarget(malformedRoot.target, { fetchImpl: mockFetch(malformedRoot.responses) }),
    /not canonical base64/u,
  );

  const wrongPath = monitoredFixture({
    evaluatorUrl: "https://evaluator.herd.example/api/v1/evaluate",
  });
  await assert.rejects(
    verifyMonitoredTarget(wrongPath, { fetchImpl: mockFetch(wrongPath.responses) }),
    /exact \/api\/v1\/relay\//u,
  );

  const wrongOrigin = monitoredFixture({
    evaluatorUrl: "https://other.herd.example/api/v1/relay/",
  });
  await assert.rejects(
    verifyMonitoredTarget(wrongOrigin, { fetchImpl: mockFetch(wrongOrigin.responses) }),
    /independently configured evaluator origin/u,
  );
});

test("fails closed when any signed-manifest artifact or evidence URL is dead", async () => {
  const fixture = monitoredFixture();
  for (const [artifact] of fixture.publishedArtifacts) {
    const responses = new Map(fixture.responses);
    responses.delete(artifact.url);
    await assert.rejects(
      verifyMonitoredTarget(fixture, { fetchImpl: mockFetch(responses) }),
      new RegExp(`(?:${artifact.name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}|returned HTTP 404)`, "u"),
    );
  }
});

test("fails closed when Rekor is dead or returns an unrelated entry", async () => {
  const fixture = monitoredFixture();
  const rekorUrl = fixture.manifest.evidence.transparency[0].url;
  await assert.rejects(
    verifyMonitoredTarget(fixture, {
      fetchImpl: mockFetch(fixture.responses, new Map([[rekorUrl, new Response("unavailable", { status: 503 })]])),
    }),
    /Rekor record returned HTTP 503/u,
  );
  const unrelated = Buffer.from(JSON.stringify({ unrelated: { logID: "other", logIndex: 8, integratedTime: 1 } }));
  await assert.rejects(
    verifyMonitoredTarget(fixture, {
      fetchImpl: mockFetch(fixture.responses, new Map([[rekorUrl, new Response(unrelated, {
        headers: { "content-type": "application/json", "content-length": String(unrelated.byteLength) },
      })]])),
    }),
    /Rekor response is unrelated/u,
  );
});

test("fails when a deployed resource changes without a release", async () => {
  const fixture = monitoredFixture();
  const resource = fixture.resources.find(({ name }) => name === "entry-document");
  const changed = Buffer.from("<!doctype html><title>Evil</title>\n");
  await assert.rejects(
    verifyMonitoredTarget(fixture, {
      fetchImpl: mockFetch(
        fixture.responses,
        new Map([
          [resource.url, new Response(changed, { headers: { "content-type": "text/html", "content-length": String(changed.byteLength) } })],
        ]),
      ),
    }),
    /differs from its release hash/u,
  );
});

test("fails when signed live AASA bytes authorize the wrong app or invite path", async () => {
  for (const appleAppSiteAssociationValue of [
    {
      applinks: {
        apps: [],
        details: [{ appID: "R4UPN8ZDV8.com.herd.wrong", paths: ["/invite/*"] }],
      },
    },
    {
      applinks: {
        apps: [],
        details: [{ appID: "R4UPN8ZDV8.com.herd.host", paths: ["/*"] }],
      },
    },
  ]) {
    const fixture = monitoredFixture({ appleAppSiteAssociationValue });
    await assert.rejects(
      verifyMonitoredTarget(fixture, { fetchImpl: mockFetch(fixture.responses) }),
      /exact production app and invitation path/u,
    );
  }
});

test("fails when the public pointer replaces the independently configured signing key", async () => {
  const fixture = monitoredFixture();
  const changed = structuredClone(fixture.wellKnown);
  changed.releaseSigningKey = fixture.keys.resultSigning.descriptor;
  const bytes = Buffer.from(canonicalJson(changed));
  await assert.rejects(
    verifyMonitoredTarget(fixture, {
      fetchImpl: mockFetch(
        fixture.responses,
        new Map([
          [fixture.wellKnownUrl, new Response(bytes, { headers: { "content-type": "application/json", "content-length": String(bytes.byteLength) } })],
        ]),
      ),
    }),
    /independently configured key/u,
  );
});

test("fails closed on redirects and oversized responses", async () => {
  const fixture = monitoredFixture();
  await assert.rejects(
    verifyMonitoredTarget(fixture, {
      fetchImpl: mockFetch(
        fixture.responses,
        new Map([[fixture.wellKnown.manifest.url, new Response(null, { status: 302, headers: { location: "https://evil.example/manifest" } })]]),
      ),
    }),
    /redirected/u,
  );
  await assert.rejects(
    verifyMonitoredTarget(fixture, {
      fetchImpl: mockFetch(
        fixture.responses,
        new Map([[fixture.wellKnownUrl, new Response("{}\n", { headers: { "content-type": "application/json", "content-length": String(300 * 1024) } })]]),
      ),
    }),
    /excessive content length/u,
  );
});

test("witnesses hash-only response-log pages and resumes from the persisted signed head", async () => {
  const fixture = monitoredFixture();
  const log = fixture.responseLog;
  const first = await verifyMonitoredTarget(fixture, {
    fetchImpl: mockFetch(fixture.responses),
    now: () => new Date("2026-08-02T12:00:00.000Z"),
  });
  assert.equal(first.responseTransparency.witnessedIndex, 3);
  assert.equal(first.responseTransparency.witnessedEntryHash, log.hashes[2]);
  const resumed = await verifyMonitoredTarget(fixture, {
    fetchImpl: mockFetch(fixture.responses),
    previousResponseTransparency: first.responseTransparency,
    now: () => new Date("2026-08-02T12:05:00.000Z"),
  });
  assert.equal(resumed.responseTransparency.witnessedIndex, 3);
  assert.equal(resumed.responseTransparency.witnessedEntryHash, log.hashes[2]);
});

test("response-log witness rejects a gap", async () => {
  const fixture = monitoredFixture();
  const log = fixture.responseLog;
  fixture.responses.set(`${log.url}?after=0&limit=500`, log.page([log.entries[0], log.entries[2]]));
  await assert.rejects(
    verifyMonitoredTarget(fixture, { fetchImpl: mockFetch(fixture.responses) }),
    /gap, fork, or key change/u,
  );
});

test("response-log witness rejects rollback and a signed fork at the persisted index", async () => {
  const fixture = monitoredFixture();
  const log = fixture.responseLog;
  const first = await verifyMonitoredTarget(fixture, { fetchImpl: mockFetch(fixture.responses) });
  fixture.responses.set(`${log.url}?after=2&limit=500`, log.page([]));
  await assert.rejects(
    verifyMonitoredTarget(fixture, {
      fetchImpl: mockFetch(fixture.responses),
      previousResponseTransparency: first.responseTransparency,
    }),
    /rewound/u,
  );

  const forkHash = Buffer.alloc(32, 9).toString("base64url");
  const fork = logEntry(3, log.hashes[1], forkHash, fixture.keys.receiptTransparencySigning);
  fixture.responses.set(`${log.url}?after=2&limit=500`, log.page([fork]));
  await assert.rejects(
    verifyMonitoredTarget(fixture, {
      fetchImpl: mockFetch(fixture.responses),
      previousResponseTransparency: first.responseTransparency,
    }),
    /forked/u,
  );
});

test("response-log witness rejects bad signatures and signing-key changes", async () => {
  const fixture = monitoredFixture();
  const log = fixture.responseLog;
  const badSignature = structuredClone(log.entries[0]);
  badSignature.head.signature = Buffer.alloc(64).toString("base64url");
  fixture.responses.set(`${log.url}?after=0&limit=500`, log.page([badSignature]));
  await assert.rejects(
    verifyMonitoredTarget(fixture, { fetchImpl: mockFetch(fixture.responses) }),
    /signature is invalid/u,
  );

  const changedKeyEntry = logEntry(
    1,
    GENESIS_HASH,
    log.hashes[0],
    fixture.keys.resultSigning,
  );
  fixture.responses.set(`${log.url}?after=0&limit=500`, log.page([changedKeyEntry]));
  await assert.rejects(
    verifyMonitoredTarget(fixture, { fetchImpl: mockFetch(fixture.responses) }),
    /gap, fork, or key change/u,
  );
});

test("response-log witness rejects receipt identifiers or other non-hash payload fields", async () => {
  const fixture = monitoredFixture();
  const log = fixture.responseLog;
  const leakingEntry = { ...log.entries[0], envelopeId: "00000000-0000-4000-8000-000000000001" };
  fixture.responses.set(`${log.url}?after=0&limit=500`, log.page([leakingEntry]));
  await assert.rejects(
    verifyMonitoredTarget(fixture, { fetchImpl: mockFetch(fixture.responses) }),
    /unsupported or missing fields/u,
  );
});
