import type { HerdBindings } from "@/db";

import { getDeploymentProfile } from "./config";
import { ApiError } from "./http";

export const QA_RESET_CONFIRMATION = "RESET HERD QA DATA";

const RESTORE_EPOCH_STATE_DELETE_GUARD = `CREATE TRIGGER evaluator_epoch_state_delete_guard
BEFORE DELETE ON evaluator_epoch_state
BEGIN
  SELECT RAISE(ABORT, 'evaluator_epoch_state_is_immutable');
END`;

const RESTORE_EPOCH_TRANSITION_DELETE_GUARD = `CREATE TRIGGER evaluator_epoch_transition_delete_guard
BEFORE DELETE ON evaluator_epoch_transitions
BEGIN
  SELECT RAISE(ABORT, 'evaluator_epoch_transition_is_immutable');
END`;

function explicitlyTrue(value: string | undefined): boolean {
  return value?.trim().toLowerCase() === "true";
}

export function requireQaResetEnabled(bindings: HerdBindings): void {
  if (
    getDeploymentProfile(bindings) !== "test" ||
    !explicitlyTrue(bindings.HERD_TEST_BYPASS_ENABLED) ||
    !explicitlyTrue(bindings.HERD_ALLOW_INSECURE_QA_BYPASS) ||
    !explicitlyTrue(bindings.HERD_QA_RESET_ENABLED)
  ) {
    throw new ApiError(404, "not_found", "The requested resource was not found.");
  }
}

export function requireQaResetConfirmation(
  value: Record<string, unknown>,
): void {
  if (
    Object.keys(value).length !== 1 ||
    value.confirmation !== QA_RESET_CONFIRMATION
  ) {
    throw new ApiError(
      400,
      "qa_reset_not_confirmed",
      `The exact confirmation ${QA_RESET_CONFIRMATION} is required.`,
    );
  }
}

/**
 * Atomically resets only the explicitly marked QA database. The immutable
 * evaluator-epoch delete guards are removed and recreated in the same D1
 * transaction; D1 rolls the whole batch back if any statement fails.
 */
export async function resetQaDatabase(db: D1Database): Promise<void> {
  await db.batch([
    db.prepare("DROP TRIGGER evaluator_epoch_state_delete_guard"),
    db.prepare("DROP TRIGGER evaluator_epoch_transition_delete_guard"),
    db.prepare("DELETE FROM response_transparency_heads"),
    db.prepare("DELETE FROM response_transparency_entries"),
    db.prepare("DELETE FROM event_resolutions"),
    db.prepare("DELETE FROM response_envelopes"),
    db.prepare("DELETE FROM invitation_deliveries"),
    db.prepare("DELETE FROM group_members"),
    db.prepare("DELETE FROM event_policies"),
    db.prepare("DELETE FROM groups"),
    db.prepare("DELETE FROM invitees"),
    db.prepare("DELETE FROM events"),
    db.prepare("DELETE FROM account_key_epochs"),
    db.prepare("DELETE FROM sessions"),
    db.prepare("DELETE FROM users"),
    db.prepare("DELETE FROM challenges"),
    db.prepare("DELETE FROM auth_phone_rate_limits"),
    db.prepare("DELETE FROM auth_ip_rate_limits"),
    db.prepare("DELETE FROM evaluator_epoch_transitions"),
    db.prepare("DELETE FROM evaluator_epoch_state"),
    db.prepare(
      "DELETE FROM sqlite_sequence WHERE name = 'response_transparency_entries'",
    ),
    db.prepare(RESTORE_EPOCH_STATE_DELETE_GUARD),
    db.prepare(RESTORE_EPOCH_TRANSITION_DELETE_GUARD),
  ]);
}
