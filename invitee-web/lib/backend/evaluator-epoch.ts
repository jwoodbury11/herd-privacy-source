import type { HerdBindings } from "@/db";

import {
  getAuthConfig,
  getDeploymentProfile,
  getEvaluatorResultSigningConfig,
  getEvaluatorTrustSigningConfig,
} from "./config";
import { ApiError } from "./http";

const RESPONSE_LOG_ID = "herd-response-log-v1";
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EPOCH_STATE_SELECT = `SELECT
  singleton_id AS singletonId,
  generation,
  mode,
  evaluator_key_epoch_id AS evaluatorKeyEpochId,
  epoch_descriptor_sha256 AS epochDescriptorSha256,
  transparency_identity_sha256 AS transparencyIdentitySha256,
  workload_image_digest AS workloadImageDigest,
  response_decryption_key_id AS responseDecryptionKeyId,
  evaluation_result_signing_key_id AS evaluationResultSigningKeyId,
  policy_signing_key_id AS policySigningKeyId,
  response_transparency_signing_key_id AS responseTransparencySigningKeyId,
  activated_at AS activatedAt,
  drain_started_at AS drainStartedAt,
  updated_at AS updatedAt
FROM evaluator_epoch_state
WHERE singleton_id = 1`;
const TRANSITION_SELECT = `SELECT
  transition_id AS transitionId,
  from_generation AS fromGeneration,
  from_evaluator_key_epoch_id AS fromEvaluatorKeyEpochId,
  from_epoch_descriptor_sha256 AS fromEpochDescriptorSha256,
  transparency_identity_sha256 AS transparencyIdentitySha256,
  drain_started_at AS drainStartedAt,
  unresolved_policy_count_at_drain AS unresolvedPolicyCountAtDrain,
  active_evaluation_lease_count_at_drain AS activeEvaluationLeaseCountAtDrain,
  active_evaluation_job_count_at_drain AS activeEvaluationJobCountAtDrain,
  uncertified_transparency_count_at_drain AS uncertifiedTransparencyCountAtDrain,
  to_generation AS toGeneration,
  to_evaluator_key_epoch_id AS toEvaluatorKeyEpochId,
  to_epoch_descriptor_sha256 AS toEpochDescriptorSha256,
  activated_at AS activatedAt,
  canonical_activation_evidence AS canonicalActivationEvidence,
  activation_evidence_sha256 AS activationEvidenceSha256
FROM evaluator_epoch_transitions`;

export const EVALUATOR_EPOCH_DRAIN_MINIMUM_MILLISECONDS = 90_000;

type RuntimeKey = { keyId: string; publicKey: string };

export type RuntimeEvaluatorEpoch = {
  artifactReleaseId: string | null;
  evaluatorKeyEpochId: string;
  workloadImageDigest: string;
  responseDecryption: RuntimeKey;
  evaluationResultSigning: RuntimeKey;
  policySigning: RuntimeKey;
  responseTransparency: {
    logId: typeof RESPONSE_LOG_ID;
    keyId: string;
    publicKey: string;
  };
  descriptorSha256: string;
  transparencyIdentitySha256: string;
};

type EpochStateRow = {
  singletonId: number;
  generation: number;
  mode: string;
  evaluatorKeyEpochId: string;
  epochDescriptorSha256: string;
  transparencyIdentitySha256: string;
  workloadImageDigest: string;
  responseDecryptionKeyId: string;
  evaluationResultSigningKeyId: string;
  policySigningKeyId: string;
  responseTransparencySigningKeyId: string;
  activatedAt: string;
  drainStartedAt: string | null;
  updatedAt: string;
};

type TransitionRow = {
  transitionId: string;
  fromGeneration: number;
  fromEvaluatorKeyEpochId: string;
  fromEpochDescriptorSha256: string;
  transparencyIdentitySha256: string;
  drainStartedAt: string;
  unresolvedPolicyCountAtDrain: number;
  activeEvaluationLeaseCountAtDrain: number;
  activeEvaluationJobCountAtDrain: number;
  uncertifiedTransparencyCountAtDrain: number;
  toGeneration: number | null;
  toEvaluatorKeyEpochId: string | null;
  toEpochDescriptorSha256: string | null;
  activatedAt: string | null;
  canonicalActivationEvidence: string | null;
  activationEvidenceSha256: string | null;
};

type DrainCounts = {
  unresolvedPolicyCount: number;
  activeEvaluationLeaseCount: number;
  activeEvaluationJobCount: number;
  uncertifiedTransparencyCount: number;
};

export type EvaluatorEpochTransitionRequest = {
  schemaVersion: 1;
  expectedGeneration: number;
  expectedEvaluatorKeyEpochId: string;
};

export type EvaluatorEpochRetirementRequest = {
  schemaVersion: 1;
  expectedGeneration: number;
  expectedEvaluatorKeyEpochId: string;
  expectedUnresolvedPolicyCount: number;
  confirmation: "RETIRE_UNRESOLVED_BETA_EVENTS";
};

function canonicalTimestamp(value: string, field: string): string {
  const instant = Date.parse(value);
  if (!Number.isFinite(instant) || new Date(instant).toISOString() !== value) {
    throw new ApiError(
      500,
      "evaluator_epoch_state_corrupt",
      `The evaluator epoch ${field} is invalid.`,
    );
  }
  return value;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new TypeError("Unsupported canonical JSON value.");
    return encoded;
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`);
  return `{${entries.join(",")}}`;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
  );
  return [...digest]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function configuredKey(
  keyId: string | undefined,
  publicKey: string | undefined,
  fallbackPurpose: string,
): RuntimeKey {
  const id = keyId?.trim();
  const key = publicKey?.trim();
  if (id && key) return { keyId: id, publicKey: key };
  return {
    keyId: `test-unconfigured-${fallbackPurpose}`,
    publicKey: `test-unconfigured-${fallbackPurpose}`,
  };
}

function drainMinimumMilliseconds(bindings: HerdBindings): number {
  const configured = bindings.HERD_EVALUATOR_EPOCH_DRAIN_MINIMUM_SECONDS?.trim();
  if (!configured) return EVALUATOR_EPOCH_DRAIN_MINIMUM_MILLISECONDS;
  if (getDeploymentProfile(bindings) === "production") {
    throw new ApiError(
      500,
      "server_misconfigured",
      "The evaluator epoch drain interval cannot be overridden in production.",
    );
  }
  if (!/^(?:0|[1-9][0-9]?)$/u.test(configured)) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "The test evaluator epoch drain interval is invalid.",
    );
  }
  return Number(configured) * 1_000;
}

/**
 * Computes the exact evaluator epoch descriptor emitted by the signed release
 * configuration. In production the independently generated digest is required
 * and compared byte-for-byte with this implementation.
 */
export async function getRuntimeEvaluatorEpoch(
  bindings: HerdBindings,
  { requireComplete = false }: { requireComplete?: boolean } = {},
): Promise<RuntimeEvaluatorEpoch> {
  const privateResponse = getAuthConfig(bindings).privateResponse;
  if (!privateResponse) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "The evaluator epoch is not configured.",
    );
  }

  const production = getDeploymentProfile(bindings) === "production";
  const artifactReleaseId = bindings.HERD_ARTIFACT_RELEASE_ID?.trim() || null;
  if (
    (artifactReleaseId !== null && !IDENTIFIER_PATTERN.test(artifactReleaseId)) ||
    (production && artifactReleaseId === null)
  ) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_ARTIFACT_RELEASE_ID must identify the signed production artifact.",
    );
  }
  if (!IDENTIFIER_PATTERN.test(privateResponse.releaseId)) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_RELEASE_ID must identify the evaluator key epoch.",
    );
  }
  const completeValues = [
    bindings.HERD_EVALUATOR_URL,
    bindings.HERD_EVALUATOR_TOKEN,
    bindings.HERD_EVALUATOR_RESULT_SIGNING_KEY_ID,
    bindings.HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY,
    bindings.HERD_EVALUATOR_POLICY_SIGNING_KEY_ID,
    bindings.HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY,
    bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID,
    bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY,
  ].every((value) => Boolean(value?.trim()));

  let evaluationResultSigning: RuntimeKey;
  let policySigning: RuntimeKey;
  let responseTransparency: RuntimeKey;
  if (completeValues) {
    const resultSigning = getEvaluatorResultSigningConfig(bindings);
    const trust = getEvaluatorTrustSigningConfig(bindings);
    if (!trust) {
      throw new ApiError(
        500,
        "server_misconfigured",
        "The evaluator epoch configuration is inconsistent.",
      );
    }
    evaluationResultSigning = {
      keyId: resultSigning.resultSigningKeyId,
      publicKey: resultSigning.resultSigningPublicKey,
    };
    policySigning = {
      keyId: trust.policySigningKeyId,
      publicKey: trust.policySigningPublicKey,
    };
    responseTransparency = {
      keyId: trust.transparencySigningKeyId,
      publicKey: trust.transparencySigningPublicKey,
    };
  } else {
    if (production || requireComplete) {
      throw new ApiError(
        500,
        "server_misconfigured",
        "The complete evaluator epoch trust configuration is required.",
      );
    }
    evaluationResultSigning = configuredKey(
      bindings.HERD_EVALUATOR_RESULT_SIGNING_KEY_ID,
      bindings.HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY,
      "result-signing",
    );
    policySigning = configuredKey(
      bindings.HERD_EVALUATOR_POLICY_SIGNING_KEY_ID,
      bindings.HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY,
      "policy-signing",
    );
    responseTransparency = configuredKey(
      bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID,
      bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY,
      "transparency-signing",
    );
  }

  const descriptor = {
    schemaVersion: 1,
    evaluatorKeyEpochId: privateResponse.releaseId,
    workloadImageDigest: privateResponse.evaluatorMeasurement,
    responseDecryption: {
      keyId: privateResponse.evaluatorKeyId,
      publicKey: privateResponse.evaluatorPublicKey,
    },
    evaluationResultSigning,
    policySigning,
    responseTransparency: {
      logId: RESPONSE_LOG_ID,
      keyId: responseTransparency.keyId,
      publicKey: responseTransparency.publicKey,
    },
  } as const;
  const descriptorSha256 = await sha256Hex(canonicalJson(descriptor));
  const transparencyIdentitySha256 = await sha256Hex(
    canonicalJson({
      schemaVersion: 1,
      logId: RESPONSE_LOG_ID,
      keyId: responseTransparency.keyId,
      publicKey: responseTransparency.publicKey,
    }),
  );
  const declaredDigest = bindings.HERD_EVALUATOR_KEY_EPOCH_SHA256?.trim();
  if (
    (declaredDigest &&
      (!SHA256_PATTERN.test(declaredDigest) || declaredDigest !== descriptorSha256)) ||
    ((production || requireComplete) && !declaredDigest)
  ) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "The signed evaluator epoch descriptor does not match the runtime configuration.",
    );
  }
  return {
    ...descriptor,
    artifactReleaseId,
    descriptorSha256,
    transparencyIdentitySha256,
  };
}

function validCount(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) >= 0;
}

function isEpochBatchAssertionFailure(error: unknown): boolean {
  let current: unknown = error;
  for (let depth = 0; depth < 5 && current !== undefined; depth += 1) {
    const message =
      current instanceof Error
        ? current.message
        : typeof current === "string"
          ? current
          : "";
    if (
      message.includes(
        "NOT NULL constraint failed: evaluator_epoch_transitions.from_generation",
      )
    ) {
      return true;
    }
    current =
      typeof current === "object" && current !== null && "cause" in current
        ? (current as { cause?: unknown }).cause
        : undefined;
  }
  return false;
}

function normalizeState(row: EpochStateRow | null): EpochStateRow | null {
  if (!row) return null;
  if (
    row.singletonId !== 1 ||
    !Number.isInteger(row.generation) ||
    row.generation < 1 ||
    !["active", "draining"].includes(row.mode) ||
    !IDENTIFIER_PATTERN.test(row.evaluatorKeyEpochId) ||
    !SHA256_PATTERN.test(row.epochDescriptorSha256) ||
    !SHA256_PATTERN.test(row.transparencyIdentitySha256) ||
    !row.workloadImageDigest ||
    !row.responseDecryptionKeyId ||
    !row.evaluationResultSigningKeyId ||
    !row.policySigningKeyId ||
    !row.responseTransparencySigningKeyId ||
    (row.mode === "active" && row.drainStartedAt !== null) ||
    (row.mode === "draining" && row.drainStartedAt === null)
  ) {
    throw new ApiError(
      500,
      "evaluator_epoch_state_corrupt",
      "The evaluator epoch state is invalid.",
    );
  }
  canonicalTimestamp(row.activatedAt, "activation time");
  canonicalTimestamp(row.updatedAt, "update time");
  if (row.drainStartedAt) canonicalTimestamp(row.drainStartedAt, "drain time");
  return row;
}

async function loadState(db: D1Database): Promise<EpochStateRow | null> {
  return normalizeState(await db.prepare(EPOCH_STATE_SELECT).first<EpochStateRow>());
}

async function ensureState(
  db: D1Database,
  runtime: RuntimeEvaluatorEpoch,
  nowIso: string,
): Promise<EpochStateRow> {
  await db
    .prepare(
      `INSERT OR IGNORE INTO evaluator_epoch_state
        (singleton_id, generation, mode, evaluator_key_epoch_id,
         epoch_descriptor_sha256, transparency_identity_sha256,
         workload_image_digest, response_decryption_key_id,
         evaluation_result_signing_key_id, policy_signing_key_id,
         response_transparency_signing_key_id, activated_at,
         drain_started_at, updated_at)
       SELECT 1, 1, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?
       WHERE NOT EXISTS (SELECT 1 FROM evaluator_epoch_state)
         AND NOT EXISTS (SELECT 1 FROM event_policies)
         AND NOT EXISTS (SELECT 1 FROM event_resolutions)
         AND NOT EXISTS (SELECT 1 FROM response_transparency_entries)
         AND NOT EXISTS (SELECT 1 FROM response_transparency_heads)`,
    )
    .bind(
      runtime.evaluatorKeyEpochId,
      runtime.descriptorSha256,
      runtime.transparencyIdentitySha256,
      runtime.workloadImageDigest,
      runtime.responseDecryption.keyId,
      runtime.evaluationResultSigning.keyId,
      runtime.policySigning.keyId,
      runtime.responseTransparency.keyId,
      nowIso,
      nowIso,
    )
    .run();
  const state = await loadState(db);
  if (!state) {
    throw new ApiError(
      503,
      "evaluator_epoch_bootstrap_required",
      "The evaluator epoch must be initialized before private events can be created.",
    );
  }
  return state;
}

function runtimeMatchesState(
  runtime: RuntimeEvaluatorEpoch,
  state: EpochStateRow,
): boolean {
  return (
    runtime.evaluatorKeyEpochId === state.evaluatorKeyEpochId &&
    runtime.descriptorSha256 === state.epochDescriptorSha256 &&
    runtime.transparencyIdentitySha256 === state.transparencyIdentitySha256 &&
    runtime.workloadImageDigest === state.workloadImageDigest &&
    runtime.responseDecryption.keyId === state.responseDecryptionKeyId &&
    runtime.evaluationResultSigning.keyId === state.evaluationResultSigningKeyId &&
    runtime.policySigning.keyId === state.policySigningKeyId &&
    runtime.responseTransparency.keyId ===
      state.responseTransparencySigningKeyId
  );
}

async function drainCounts(
  db: D1Database,
  nowIso: string,
): Promise<DrainCounts> {
  const row = await db
    .prepare(
      `SELECT
         (SELECT COUNT(*)
            FROM event_policies AS policies
            LEFT JOIN event_resolutions AS resolutions
              ON resolutions.event_id = policies.event_id
           WHERE resolutions.status IS NULL
              OR resolutions.status NOT IN ('confirmed', 'not_confirmed'))
           AS unresolvedPolicyCount,
         (SELECT COUNT(*)
            FROM event_resolutions
           WHERE status = 'evaluating'
             AND evaluation_lease_id IS NOT NULL
             AND evaluation_lease_expires_at IS NOT NULL
             AND evaluation_lease_expires_at > ?)
           AS activeEvaluationLeaseCount,
         (SELECT COUNT(*)
            FROM event_resolutions
           WHERE status = 'evaluating'
             AND evaluation_request_hash IS NOT NULL)
           AS activeEvaluationJobCount,
         ((SELECT COUNT(*)
            FROM response_transparency_entries AS entries
            LEFT JOIN response_transparency_heads AS heads
              ON heads.log_index = entries.log_index
           WHERE entries.log_id <> ?
              OR entries.signing_key_id <> (
                SELECT response_transparency_signing_key_id
                  FROM evaluator_epoch_state WHERE singleton_id = 1
              )
              OR entries.receipt_signature IS NULL
              OR entries.signed_at IS NULL
              OR heads.log_index IS NULL
              OR heads.log_id <> ?
              OR heads.signing_key_id <> (
                SELECT response_transparency_signing_key_id
                  FROM evaluator_epoch_state WHERE singleton_id = 1
              )
              OR heads.log_id <> entries.log_id
              OR heads.head_entry_hash <> entries.entry_hash
              OR heads.signing_key_id <> entries.signing_key_id)
          + (SELECT COUNT(*)
               FROM response_transparency_heads AS heads
               LEFT JOIN response_transparency_entries AS entries
                 ON entries.log_index = heads.log_index
              WHERE entries.log_index IS NULL
                 OR heads.log_id <> ?
                 OR heads.signing_key_id <> (
                   SELECT response_transparency_signing_key_id
                     FROM evaluator_epoch_state WHERE singleton_id = 1
                 )))
           AS uncertifiedTransparencyCount`,
    )
    .bind(nowIso, RESPONSE_LOG_ID, RESPONSE_LOG_ID, RESPONSE_LOG_ID)
    .first<DrainCounts>();
  if (
    !row ||
    !validCount(row.unresolvedPolicyCount) ||
    !validCount(row.activeEvaluationLeaseCount) ||
    !validCount(row.activeEvaluationJobCount) ||
    !validCount(row.uncertifiedTransparencyCount)
  ) {
    throw new ApiError(
      500,
      "evaluator_epoch_status_unavailable",
      "The evaluator epoch drain status could not be determined.",
    );
  }
  return row;
}

function normalizeTransition(row: TransitionRow | null): TransitionRow | null {
  if (!row) return null;
  if (
    !row.transitionId ||
    !Number.isInteger(row.fromGeneration) ||
    row.fromGeneration < 1 ||
    !IDENTIFIER_PATTERN.test(row.fromEvaluatorKeyEpochId) ||
    !SHA256_PATTERN.test(row.fromEpochDescriptorSha256) ||
    !SHA256_PATTERN.test(row.transparencyIdentitySha256) ||
    !validCount(row.unresolvedPolicyCountAtDrain) ||
    !validCount(row.activeEvaluationLeaseCountAtDrain) ||
    !validCount(row.activeEvaluationJobCountAtDrain) ||
    !validCount(row.uncertifiedTransparencyCountAtDrain)
  ) {
    throw new ApiError(
      500,
      "evaluator_epoch_state_corrupt",
      "The evaluator epoch transition record is invalid.",
    );
  }
  canonicalTimestamp(row.drainStartedAt, "transition drain time");
  const activationValues = [
    row.toGeneration,
    row.toEvaluatorKeyEpochId,
    row.toEpochDescriptorSha256,
    row.activatedAt,
    row.canonicalActivationEvidence,
    row.activationEvidenceSha256,
  ];
  const activated = activationValues.every((value) => value !== null);
  if (!activated && activationValues.some((value) => value !== null)) {
    throw new ApiError(
      500,
      "evaluator_epoch_state_corrupt",
      "The evaluator epoch activation evidence is incomplete.",
    );
  }
  if (activated) {
    if (
      !Number.isInteger(row.toGeneration) ||
      row.toGeneration !== row.fromGeneration + 1 ||
      !IDENTIFIER_PATTERN.test(row.toEvaluatorKeyEpochId!) ||
      !SHA256_PATTERN.test(row.toEpochDescriptorSha256!) ||
      !SHA256_PATTERN.test(row.activationEvidenceSha256!)
    ) {
      throw new ApiError(
        500,
        "evaluator_epoch_state_corrupt",
        "The evaluator epoch activation evidence is invalid.",
      );
    }
    canonicalTimestamp(row.activatedAt!, "transition activation time");
  }
  return row;
}

async function transitionForGeneration(
  db: D1Database,
  generation: number,
): Promise<TransitionRow | null> {
  return normalizeTransition(
    await db
      .prepare(`${TRANSITION_SELECT} WHERE from_generation = ?`)
      .bind(generation)
      .first<TransitionRow>(),
  );
}

async function requireActivatedTransitionEvidence(
  transition: TransitionRow,
  state: EpochStateRow,
): Promise<void> {
  if (
    transition.toGeneration !== state.generation ||
    transition.toEvaluatorKeyEpochId !== state.evaluatorKeyEpochId ||
    transition.toEpochDescriptorSha256 !== state.epochDescriptorSha256 ||
    transition.transparencyIdentitySha256 !== state.transparencyIdentitySha256 ||
    transition.activatedAt !== state.activatedAt ||
    !transition.activatedAt ||
    !transition.canonicalActivationEvidence ||
    !transition.activationEvidenceSha256
  ) {
    throw new ApiError(
      500,
      "evaluator_epoch_state_corrupt",
      "The active evaluator epoch has no matching transition evidence.",
    );
  }
  const expected = canonicalJson({
    schemaVersion: 1,
    transitionId: transition.transitionId,
    from: {
      generation: transition.fromGeneration,
      evaluatorKeyEpochId: transition.fromEvaluatorKeyEpochId,
      epochDescriptorSha256: transition.fromEpochDescriptorSha256,
    },
    to: {
      generation: transition.toGeneration,
      evaluatorKeyEpochId: transition.toEvaluatorKeyEpochId,
      epochDescriptorSha256: transition.toEpochDescriptorSha256,
    },
    transparencyIdentitySha256: transition.transparencyIdentitySha256,
    drainStartedAt: transition.drainStartedAt,
    activatedAt: transition.activatedAt,
    finalDrainCounts: {
      unresolvedPolicyCount: 0,
      activeEvaluationLeaseCount: 0,
      activeEvaluationJobCount: 0,
      uncertifiedTransparencyCount: 0,
    },
  });
  if (
    transition.canonicalActivationEvidence !== expected ||
    transition.activationEvidenceSha256 !== (await sha256Hex(expected))
  ) {
    throw new ApiError(
      500,
      "evaluator_epoch_state_corrupt",
      "The evaluator epoch transition evidence is invalid.",
    );
  }
}

function publicRuntime(runtime: RuntimeEvaluatorEpoch) {
  return {
    artifactReleaseId: runtime.artifactReleaseId,
    evaluatorKeyEpochId: runtime.evaluatorKeyEpochId,
    workloadImageDigest: runtime.workloadImageDigest,
    epochDescriptorSha256: runtime.descriptorSha256,
    transparencyIdentitySha256: runtime.transparencyIdentitySha256,
    keys: {
      responseDecryption: runtime.responseDecryption,
      evaluationResultSigning: runtime.evaluationResultSigning,
      policySigning: runtime.policySigning,
      responseTransparencySigning: {
        keyId: runtime.responseTransparency.keyId,
        publicKey: runtime.responseTransparency.publicKey,
      },
    },
  };
}

function publicState(state: EpochStateRow) {
  return {
    generation: state.generation,
    mode: state.mode as "active" | "draining",
    evaluatorKeyEpochId: state.evaluatorKeyEpochId,
    epochDescriptorSha256: state.epochDescriptorSha256,
    transparencyIdentitySha256: state.transparencyIdentitySha256,
    activatedAt: state.activatedAt,
    drainStartedAt: state.drainStartedAt,
    updatedAt: state.updatedAt,
  };
}

function publicTransition(row: TransitionRow | null) {
  if (!row) return null;
  return {
    transitionId: row.transitionId,
    fromGeneration: row.fromGeneration,
    fromEvaluatorKeyEpochId: row.fromEvaluatorKeyEpochId,
    fromEpochDescriptorSha256: row.fromEpochDescriptorSha256,
    transparencyIdentitySha256: row.transparencyIdentitySha256,
    drainStartedAt: row.drainStartedAt,
    drainCounts: {
      unresolvedPolicyCount: row.unresolvedPolicyCountAtDrain,
      activeEvaluationLeaseCount: row.activeEvaluationLeaseCountAtDrain,
      activeEvaluationJobCount: row.activeEvaluationJobCountAtDrain,
      uncertifiedTransparencyCount: row.uncertifiedTransparencyCountAtDrain,
    },
    toGeneration: row.toGeneration,
    toEvaluatorKeyEpochId: row.toEvaluatorKeyEpochId,
    toEpochDescriptorSha256: row.toEpochDescriptorSha256,
    activatedAt: row.activatedAt,
    canonicalActivationEvidence: row.canonicalActivationEvidence,
    activationEvidenceSha256: row.activationEvidenceSha256,
  };
}

export async function requireEvaluatorEpochPolicyFence(
  db: D1Database,
  bindings: HerdBindings,
  now = new Date(),
): Promise<{ evaluatorKeyEpochId: string; descriptorSha256: string }> {
  const runtime = await getRuntimeEvaluatorEpoch(bindings);
  const nowIso = now.toISOString();
  const state = await ensureState(db, runtime, nowIso);
  if (state.mode !== "active" || !runtimeMatchesState(runtime, state)) {
    throw new ApiError(
      503,
      "evaluator_epoch_draining",
      "Private invitations are paused while the confidential evaluator is being rotated.",
    );
  }
  return {
    evaluatorKeyEpochId: runtime.evaluatorKeyEpochId,
    descriptorSha256: runtime.descriptorSha256,
  };
}

export async function getEvaluatorEpochStatus(
  db: D1Database,
  bindings: HerdBindings,
  now = new Date(),
) {
  const runtime = await getRuntimeEvaluatorEpoch(bindings, {
    requireComplete: true,
  });
  const observedAt = now.toISOString();
  const state = await ensureState(db, runtime, observedAt);
  const counts = await drainCounts(db, observedAt);
  const transition =
    state.mode === "draining"
      ? await transitionForGeneration(db, state.generation)
      : state.generation > 1
        ? await transitionForGeneration(db, state.generation - 1)
        : null;
  if (state.mode === "active" && state.generation > 1) {
    if (!transition) {
      throw new ApiError(
        500,
        "evaluator_epoch_state_corrupt",
        "The active evaluator epoch is missing transition evidence.",
      );
    }
    await requireActivatedTransitionEvidence(transition, state);
  }
  const minimumDrainReached = Boolean(
    state.drainStartedAt &&
      Date.parse(state.drainStartedAt) <=
        now.getTime() - drainMinimumMilliseconds(bindings),
  );
  return {
    schemaVersion: 2 as const,
    ...publicRuntime(runtime),
    state: publicState(state),
    runtimeMatchesState: runtimeMatchesState(runtime, state),
    unresolvedPolicyCount: counts.unresolvedPolicyCount,
    activeEvaluationLeaseCount: counts.activeEvaluationLeaseCount,
    activeEvaluationJobCount: counts.activeEvaluationJobCount,
    uncertifiedTransparencyCount: counts.uncertifiedTransparencyCount,
    minimumDrainReached,
    drained:
      state.mode === "draining" &&
      minimumDrainReached &&
      Object.values(counts).every((value) => value === 0),
    transition: publicTransition(transition),
    observedAt,
  };
}

export function parseEvaluatorEpochTransitionRequest(
  value: Record<string, unknown>,
): EvaluatorEpochTransitionRequest {
  const keys = Object.keys(value).sort();
  const expected = [
    "expectedEvaluatorKeyEpochId",
    "expectedGeneration",
    "schemaVersion",
  ];
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index]) ||
    value.schemaVersion !== 1 ||
    !Number.isInteger(value.expectedGeneration) ||
    (value.expectedGeneration as number) < 1 ||
    (value.expectedGeneration as number) >= 2_147_483_647 ||
    typeof value.expectedEvaluatorKeyEpochId !== "string" ||
    !IDENTIFIER_PATTERN.test(value.expectedEvaluatorKeyEpochId)
  ) {
    throw new ApiError(
      400,
      "invalid_evaluator_epoch_transition",
      "The evaluator epoch transition request is invalid.",
    );
  }
  return {
    schemaVersion: 1,
    expectedGeneration: value.expectedGeneration as number,
    expectedEvaluatorKeyEpochId: value.expectedEvaluatorKeyEpochId,
  };
}

export function parseEvaluatorEpochRetirementRequest(
  value: Record<string, unknown>,
): EvaluatorEpochRetirementRequest {
  const keys = Object.keys(value).sort();
  const expected = [
    "confirmation",
    "expectedEvaluatorKeyEpochId",
    "expectedGeneration",
    "expectedUnresolvedPolicyCount",
    "schemaVersion",
  ];
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index]) ||
    value.schemaVersion !== 1 ||
    !Number.isInteger(value.expectedGeneration) ||
    (value.expectedGeneration as number) < 1 ||
    (value.expectedGeneration as number) >= 2_147_483_647 ||
    typeof value.expectedEvaluatorKeyEpochId !== "string" ||
    !IDENTIFIER_PATTERN.test(value.expectedEvaluatorKeyEpochId) ||
    !Number.isInteger(value.expectedUnresolvedPolicyCount) ||
    (value.expectedUnresolvedPolicyCount as number) < 1 ||
    (value.expectedUnresolvedPolicyCount as number) > 1_000 ||
    value.confirmation !== "RETIRE_UNRESOLVED_BETA_EVENTS"
  ) {
    throw new ApiError(
      400,
      "invalid_evaluator_epoch_retirement",
      "The evaluator epoch retirement request is invalid.",
    );
  }
  return {
    schemaVersion: 1,
    expectedGeneration: value.expectedGeneration as number,
    expectedEvaluatorKeyEpochId: value.expectedEvaluatorKeyEpochId,
    expectedUnresolvedPolicyCount: value.expectedUnresolvedPolicyCount as number,
    confirmation: "RETIRE_UNRESOLVED_BETA_EVENTS",
  };
}

export async function retireUnresolvedEvaluatorEpochEvents(
  db: D1Database,
  bindings: HerdBindings,
  request: EvaluatorEpochRetirementRequest,
  now = new Date(),
) {
  const runtime = await getRuntimeEvaluatorEpoch(bindings, {
    requireComplete: true,
  });
  const nowIso = now.toISOString();
  const state = await ensureState(db, runtime, nowIso);
  if (
    state.mode !== "active" ||
    state.generation !== request.expectedGeneration ||
    state.evaluatorKeyEpochId !== request.expectedEvaluatorKeyEpochId ||
    state.transparencyIdentitySha256 !== runtime.transparencyIdentitySha256
  ) {
    throw new ApiError(
      409,
      "evaluator_epoch_retirement_conflict",
      "The evaluator epoch changed before its unresolved events could be retired.",
    );
  }
  const before = await drainCounts(db, nowIso);
  if (
    before.unresolvedPolicyCount !== request.expectedUnresolvedPolicyCount ||
    before.activeEvaluationLeaseCount !== 0 ||
    before.uncertifiedTransparencyCount !== 0
  ) {
    throw new ApiError(
      409,
      "evaluator_epoch_retirement_conflict",
      "The unresolved evaluator work changed before retirement.",
    );
  }
  const rows = await db
    .prepare(
      `SELECT policies.event_id AS eventId
         FROM event_policies AS policies
         LEFT JOIN event_resolutions AS resolutions
           ON resolutions.event_id = policies.event_id
        WHERE policies.release_id = ?
          AND policies.evaluator_epoch_descriptor_sha256 = ?
          AND (resolutions.status IS NULL
            OR resolutions.status NOT IN ('confirmed', 'not_confirmed'))
        ORDER BY policies.event_id`,
    )
    .bind(state.evaluatorKeyEpochId, state.epochDescriptorSha256)
    .all<{ eventId: string }>();
  const eventIds = rows.results.map((row) => row.eventId);
  if (
    eventIds.length !== request.expectedUnresolvedPolicyCount ||
    eventIds.some((eventId) => !UUID_PATTERN.test(eventId))
  ) {
    throw new ApiError(
      409,
      "evaluator_epoch_retirement_conflict",
      "The unresolved events do not exactly match the active evaluator epoch.",
    );
  }
  await db.batch(
    eventIds.map((eventId) =>
      db.prepare("DELETE FROM events WHERE id = ?").bind(eventId),
    ),
  );
  const after = await drainCounts(db, nowIso);
  if (Object.values(after).some((value) => value !== 0)) {
    throw new ApiError(
      500,
      "evaluator_epoch_retirement_failed",
      "Evaluator work remained after event retirement.",
    );
  }
  return {
    schemaVersion: 1 as const,
    generation: state.generation,
    evaluatorKeyEpochId: state.evaluatorKeyEpochId,
    retiredEventCount: eventIds.length,
    retiredEventSetSha256: await sha256Hex(canonicalJson(eventIds)),
    remaining: after,
    retiredAt: nowIso,
  };
}

export async function beginEvaluatorEpochDrain(
  db: D1Database,
  bindings: HerdBindings,
  request: EvaluatorEpochTransitionRequest,
  now = new Date(),
) {
  const runtime = await getRuntimeEvaluatorEpoch(bindings, {
    requireComplete: true,
  });
  const nowIso = now.toISOString();
  const initial = await ensureState(db, runtime, nowIso);
  const runtimeIsActiveState = runtimeMatchesState(runtime, initial);
  const runtimeIsServingOffSuccessor =
    runtime.evaluatorKeyEpochId !== initial.evaluatorKeyEpochId &&
    runtime.descriptorSha256 !== initial.epochDescriptorSha256 &&
    runtime.transparencyIdentitySha256 === initial.transparencyIdentitySha256;
  if (
    request.expectedGeneration !== initial.generation ||
    request.expectedEvaluatorKeyEpochId !== initial.evaluatorKeyEpochId ||
    (!runtimeIsActiveState && !runtimeIsServingOffSuccessor)
  ) {
    throw new ApiError(
      409,
      "evaluator_epoch_transition_conflict",
      "The evaluator epoch changed before the drain could begin.",
    );
  }
  if (initial.mode === "active") {
    const transitionId = crypto.randomUUID();
    try {
      await db.batch([
      db
        .prepare(
          `UPDATE evaluator_epoch_state
              SET mode = 'draining', drain_started_at = ?, updated_at = ?
            WHERE singleton_id = 1
              AND generation = ?
              AND mode = 'active'
              AND evaluator_key_epoch_id = ?
              AND epoch_descriptor_sha256 = ?`,
        )
        .bind(
          nowIso,
          nowIso,
          initial.generation,
          initial.evaluatorKeyEpochId,
          initial.epochDescriptorSha256,
        ),
      db
        .prepare(
          `INSERT OR IGNORE INTO evaluator_epoch_transitions
            (transition_id, from_generation, from_evaluator_key_epoch_id,
             from_epoch_descriptor_sha256, transparency_identity_sha256,
             drain_started_at, unresolved_policy_count_at_drain,
             active_evaluation_lease_count_at_drain,
             active_evaluation_job_count_at_drain,
             uncertified_transparency_count_at_drain)
           SELECT ?, generation, evaluator_key_epoch_id,
                  epoch_descriptor_sha256, transparency_identity_sha256,
                  drain_started_at,
                  (SELECT COUNT(*)
                     FROM event_policies AS policies
                     LEFT JOIN event_resolutions AS resolutions
                       ON resolutions.event_id = policies.event_id
                    WHERE resolutions.status IS NULL
                       OR resolutions.status NOT IN ('confirmed', 'not_confirmed')),
                  (SELECT COUNT(*) FROM event_resolutions
                    WHERE status = 'evaluating'
                      AND evaluation_lease_id IS NOT NULL
                      AND evaluation_lease_expires_at > ?),
                  (SELECT COUNT(*) FROM event_resolutions
                    WHERE status = 'evaluating'
                      AND evaluation_request_hash IS NOT NULL),
                  ((SELECT COUNT(*)
                     FROM response_transparency_entries AS entries
                     LEFT JOIN response_transparency_heads AS heads
                       ON heads.log_index = entries.log_index
                    WHERE entries.log_id <> ?
                       OR entries.signing_key_id <> (
                         SELECT response_transparency_signing_key_id
                           FROM evaluator_epoch_state WHERE singleton_id = 1
                       )
                       OR entries.receipt_signature IS NULL
                       OR entries.signed_at IS NULL
                       OR heads.log_index IS NULL
                       OR heads.log_id <> ?
                       OR heads.signing_key_id <> (
                         SELECT response_transparency_signing_key_id
                           FROM evaluator_epoch_state WHERE singleton_id = 1
                       )
                       OR heads.log_id <> entries.log_id
                       OR heads.head_entry_hash <> entries.entry_hash
                       OR heads.signing_key_id <> entries.signing_key_id)
                   + (SELECT COUNT(*)
                        FROM response_transparency_heads AS heads
                        LEFT JOIN response_transparency_entries AS entries
                          ON entries.log_index = heads.log_index
                       WHERE entries.log_index IS NULL
                          OR heads.log_id <> ?
                          OR heads.signing_key_id <> (
                            SELECT response_transparency_signing_key_id
                              FROM evaluator_epoch_state WHERE singleton_id = 1
                          )))
             FROM evaluator_epoch_state
            WHERE singleton_id = 1
              AND generation = ?
              AND mode = 'draining'
              AND evaluator_key_epoch_id = ?
              AND epoch_descriptor_sha256 = ?`,
        )
        .bind(
          transitionId,
          nowIso,
          RESPONSE_LOG_ID,
          RESPONSE_LOG_ID,
          RESPONSE_LOG_ID,
          initial.generation,
          initial.evaluatorKeyEpochId,
          initial.epochDescriptorSha256,
        ),
      db
        .prepare(
          `INSERT INTO evaluator_epoch_transitions (transition_id)
           SELECT ?
            WHERE NOT EXISTS (
              SELECT 1
                FROM evaluator_epoch_state AS state
                JOIN evaluator_epoch_transitions AS transition
                  ON transition.from_generation = state.generation
               WHERE state.singleton_id = 1
                 AND state.generation = ?
                 AND state.mode = 'draining'
                 AND state.evaluator_key_epoch_id = ?
                 AND state.epoch_descriptor_sha256 = ?
                 AND transition.from_evaluator_key_epoch_id =
                   state.evaluator_key_epoch_id
                 AND transition.from_epoch_descriptor_sha256 =
                   state.epoch_descriptor_sha256
                 AND transition.transparency_identity_sha256 =
                   state.transparency_identity_sha256
                 AND transition.drain_started_at = state.drain_started_at
                 AND transition.activated_at IS NULL
                 AND transition.to_generation IS NULL
                 AND transition.to_evaluator_key_epoch_id IS NULL
                 AND transition.to_epoch_descriptor_sha256 IS NULL
                 AND transition.canonical_activation_evidence IS NULL
                 AND transition.activation_evidence_sha256 IS NULL
            )`,
        )
        .bind(
          `epoch-drain-assertion-${crypto.randomUUID()}`,
          initial.generation,
          initial.evaluatorKeyEpochId,
          initial.epochDescriptorSha256,
        ),
      ]);
    } catch (error) {
      if (!isEpochBatchAssertionFailure(error)) throw error;
      throw new ApiError(
        409,
        "evaluator_epoch_transition_conflict",
        "The evaluator epoch drain could not be started atomically.",
      );
    }
  }
  const state = await loadState(db);
  const transition = await transitionForGeneration(db, initial.generation);
  if (
    !state ||
    state.mode !== "draining" ||
    state.generation !== initial.generation ||
    state.evaluatorKeyEpochId !== initial.evaluatorKeyEpochId ||
    state.epochDescriptorSha256 !== initial.epochDescriptorSha256 ||
    state.transparencyIdentitySha256 !== initial.transparencyIdentitySha256 ||
    !transition ||
    transition.fromGeneration !== state.generation ||
    transition.fromEvaluatorKeyEpochId !== state.evaluatorKeyEpochId ||
    transition.fromEpochDescriptorSha256 !== state.epochDescriptorSha256 ||
    transition.transparencyIdentitySha256 !== state.transparencyIdentitySha256 ||
    transition.drainStartedAt !== state.drainStartedAt
  ) {
    throw new ApiError(
      409,
      "evaluator_epoch_transition_conflict",
      "The evaluator epoch drain could not be started atomically.",
    );
  }
  return getEvaluatorEpochStatus(db, bindings, now);
}

export async function activateEvaluatorEpoch(
  db: D1Database,
  bindings: HerdBindings,
  request: EvaluatorEpochTransitionRequest,
  now = new Date(),
) {
  const runtime = await getRuntimeEvaluatorEpoch(bindings, {
    requireComplete: true,
  });
  const nowIso = now.toISOString();
  const state = await loadState(db);
  const existingTransition = await transitionForGeneration(
    db,
    request.expectedGeneration,
  );

  if (
    state &&
    state.mode === "active" &&
    state.generation === request.expectedGeneration + 1 &&
    runtimeMatchesState(runtime, state) &&
    existingTransition?.toGeneration === state.generation
  ) {
    return getEvaluatorEpochStatus(db, bindings, now);
  }
  if (
    !state ||
    state.mode !== "draining" ||
    state.generation !== request.expectedGeneration ||
    state.evaluatorKeyEpochId !== request.expectedEvaluatorKeyEpochId ||
    !existingTransition ||
    existingTransition.activatedAt !== null ||
    existingTransition.fromEvaluatorKeyEpochId !== state.evaluatorKeyEpochId ||
    existingTransition.fromEpochDescriptorSha256 !==
      state.epochDescriptorSha256 ||
    existingTransition.transparencyIdentitySha256 !==
      state.transparencyIdentitySha256 ||
    existingTransition.drainStartedAt !== state.drainStartedAt ||
    runtime.evaluatorKeyEpochId === state.evaluatorKeyEpochId ||
    runtime.descriptorSha256 === state.epochDescriptorSha256 ||
    runtime.transparencyIdentitySha256 !== state.transparencyIdentitySha256
  ) {
    throw new ApiError(
      409,
      "evaluator_epoch_transition_conflict",
      "The evaluator epoch is not in the expected drained state.",
    );
  }
  const counts = await drainCounts(db, nowIso);
  const minimumDrainReached = Boolean(
    state.drainStartedAt &&
      Date.parse(state.drainStartedAt) <=
        now.getTime() - drainMinimumMilliseconds(bindings),
  );
  if (!minimumDrainReached || Object.values(counts).some((value) => value !== 0)) {
    throw new ApiError(
      409,
      "evaluator_epoch_not_drained",
      "The evaluator epoch still has work that must finish before rotation.",
      { ...counts, minimumDrainReached },
    );
  }

  const toGeneration = state.generation + 1;
  const evidence = {
    schemaVersion: 1,
    transitionId: existingTransition.transitionId,
    from: {
      generation: state.generation,
      evaluatorKeyEpochId: state.evaluatorKeyEpochId,
      epochDescriptorSha256: state.epochDescriptorSha256,
    },
    to: {
      generation: toGeneration,
      evaluatorKeyEpochId: runtime.evaluatorKeyEpochId,
      epochDescriptorSha256: runtime.descriptorSha256,
    },
    transparencyIdentitySha256: state.transparencyIdentitySha256,
    drainStartedAt: state.drainStartedAt,
    activatedAt: nowIso,
    finalDrainCounts: counts,
  };
  const canonicalEvidence = canonicalJson(evidence);
  const evidenceSha256 = await sha256Hex(canonicalEvidence);
  const cutoff = new Date(
    now.getTime() - drainMinimumMilliseconds(bindings),
  ).toISOString();
  try {
    await db.batch([
    db
      .prepare(
        `UPDATE evaluator_epoch_state
            SET generation = ?, mode = 'active', evaluator_key_epoch_id = ?,
                epoch_descriptor_sha256 = ?, workload_image_digest = ?,
                response_decryption_key_id = ?,
                evaluation_result_signing_key_id = ?, policy_signing_key_id = ?,
                response_transparency_signing_key_id = ?, activated_at = ?,
                drain_started_at = NULL, updated_at = ?
          WHERE singleton_id = 1
            AND generation = ?
            AND mode = 'draining'
            AND evaluator_key_epoch_id = ?
            AND epoch_descriptor_sha256 = ?
            AND transparency_identity_sha256 = ?
            AND drain_started_at <= ?
            AND NOT EXISTS (
              SELECT 1
                FROM event_policies AS policies
                LEFT JOIN event_resolutions AS resolutions
                  ON resolutions.event_id = policies.event_id
               WHERE resolutions.status IS NULL
                  OR resolutions.status NOT IN ('confirmed', 'not_confirmed')
            )
            AND NOT EXISTS (
              SELECT 1 FROM event_resolutions
               WHERE status = 'evaluating'
            )
            AND NOT EXISTS (
              SELECT 1
                FROM response_transparency_entries AS entries
                LEFT JOIN response_transparency_heads AS heads
                  ON heads.log_index = entries.log_index
               WHERE entries.log_id <> ?
                  OR entries.signing_key_id <> (
                    SELECT response_transparency_signing_key_id
                      FROM evaluator_epoch_state WHERE singleton_id = 1
                  )
                  OR entries.receipt_signature IS NULL
                  OR entries.signed_at IS NULL
                  OR heads.log_index IS NULL
                  OR heads.log_id <> ?
                  OR heads.signing_key_id <> (
                    SELECT response_transparency_signing_key_id
                      FROM evaluator_epoch_state WHERE singleton_id = 1
                  )
                  OR heads.log_id <> entries.log_id
                  OR heads.head_entry_hash <> entries.entry_hash
                  OR heads.signing_key_id <> entries.signing_key_id
            )
            AND NOT EXISTS (
              SELECT 1
                FROM response_transparency_heads AS heads
                LEFT JOIN response_transparency_entries AS entries
                  ON entries.log_index = heads.log_index
               WHERE entries.log_index IS NULL
                  OR heads.log_id <> ?
                  OR heads.signing_key_id <> (
                    SELECT response_transparency_signing_key_id
                      FROM evaluator_epoch_state WHERE singleton_id = 1
                  )
            )`,
      )
      .bind(
        toGeneration,
        runtime.evaluatorKeyEpochId,
        runtime.descriptorSha256,
        runtime.workloadImageDigest,
        runtime.responseDecryption.keyId,
        runtime.evaluationResultSigning.keyId,
        runtime.policySigning.keyId,
        runtime.responseTransparency.keyId,
        nowIso,
        nowIso,
        state.generation,
        state.evaluatorKeyEpochId,
        state.epochDescriptorSha256,
        state.transparencyIdentitySha256,
        cutoff,
        RESPONSE_LOG_ID,
        RESPONSE_LOG_ID,
        RESPONSE_LOG_ID,
      ),
    db
      .prepare(
        `UPDATE evaluator_epoch_transitions
            SET to_generation = ?, to_evaluator_key_epoch_id = ?,
                to_epoch_descriptor_sha256 = ?, activated_at = ?,
                canonical_activation_evidence = ?, activation_evidence_sha256 = ?
          WHERE transition_id = ?
            AND from_generation = ?
            AND from_evaluator_key_epoch_id = ?
            AND from_epoch_descriptor_sha256 = ?
            AND transparency_identity_sha256 = ?
            AND drain_started_at = ?
            AND activated_at IS NULL
            AND EXISTS (
              SELECT 1 FROM evaluator_epoch_state
               WHERE singleton_id = 1
                 AND generation = ?
                 AND mode = 'active'
                 AND evaluator_key_epoch_id = ?
                 AND epoch_descriptor_sha256 = ?
            )`,
      )
      .bind(
        toGeneration,
        runtime.evaluatorKeyEpochId,
        runtime.descriptorSha256,
        nowIso,
        canonicalEvidence,
        evidenceSha256,
        existingTransition.transitionId,
        state.generation,
        state.evaluatorKeyEpochId,
        state.epochDescriptorSha256,
        state.transparencyIdentitySha256,
        state.drainStartedAt,
        toGeneration,
        runtime.evaluatorKeyEpochId,
        runtime.descriptorSha256,
      ),
    db
      .prepare(
        `INSERT INTO evaluator_epoch_transitions (transition_id)
         SELECT ?
          WHERE NOT EXISTS (
            SELECT 1
              FROM evaluator_epoch_state AS state
              JOIN evaluator_epoch_transitions AS transition
                ON transition.from_generation = ?
             WHERE state.singleton_id = 1
               AND state.generation = ?
               AND state.mode = 'active'
               AND state.evaluator_key_epoch_id = ?
               AND state.epoch_descriptor_sha256 = ?
               AND state.transparency_identity_sha256 = ?
               AND state.workload_image_digest = ?
               AND state.response_decryption_key_id = ?
               AND state.evaluation_result_signing_key_id = ?
               AND state.policy_signing_key_id = ?
               AND state.response_transparency_signing_key_id = ?
               AND transition.transition_id = ?
               AND transition.from_generation = ?
               AND transition.from_evaluator_key_epoch_id = ?
               AND transition.from_epoch_descriptor_sha256 = ?
               AND transition.transparency_identity_sha256 = ?
               AND transition.drain_started_at = ?
               AND transition.to_generation = state.generation
               AND transition.to_evaluator_key_epoch_id =
                 state.evaluator_key_epoch_id
               AND transition.to_epoch_descriptor_sha256 =
                 state.epoch_descriptor_sha256
               AND transition.activated_at = state.activated_at
               AND transition.canonical_activation_evidence IS NOT NULL
               AND length(transition.activation_evidence_sha256) = 64
          )`,
      )
      .bind(
        `epoch-activation-assertion-${crypto.randomUUID()}`,
        state.generation,
        toGeneration,
        runtime.evaluatorKeyEpochId,
        runtime.descriptorSha256,
        state.transparencyIdentitySha256,
        runtime.workloadImageDigest,
        runtime.responseDecryption.keyId,
        runtime.evaluationResultSigning.keyId,
        runtime.policySigning.keyId,
        runtime.responseTransparency.keyId,
        existingTransition.transitionId,
        state.generation,
        state.evaluatorKeyEpochId,
        state.epochDescriptorSha256,
        state.transparencyIdentitySha256,
        state.drainStartedAt,
      ),
    ]);
  } catch (error) {
    if (!isEpochBatchAssertionFailure(error)) throw error;
    throw new ApiError(
      409,
      "evaluator_epoch_transition_conflict",
      "The evaluator epoch activation could not be committed atomically.",
    );
  }
  const activated = await loadState(db);
  const transition = await transitionForGeneration(db, state.generation);
  if (
    !activated ||
    activated.mode !== "active" ||
    activated.generation !== toGeneration ||
    !runtimeMatchesState(runtime, activated) ||
    !transition
  ) {
    throw new ApiError(
      409,
      "evaluator_epoch_transition_conflict",
      "The evaluator epoch activation lost an atomic state transition.",
    );
  }
  await requireActivatedTransitionEvidence(transition, activated);
  return getEvaluatorEpochStatus(db, bindings, now);
}
