import { index, integer, primaryKey, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const users = sqliteTable(
  "users",
  {
    id: text("id").primaryKey(),
    phoneNumber: text("phone_number").notNull(),
    phoneHash: text("phone_hash").notNull(),
    name: text("name").notNull().default(""),
    address: text("address").notNull().default(""),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    uniqueIndex("users_phone_number_unique").on(table.phoneNumber),
    uniqueIndex("users_phone_hash_unique").on(table.phoneHash),
  ],
);

export const accountKeyEpochs = sqliteTable(
  "account_key_epochs",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    epochNumber: integer("epoch_number").notNull(),
    keyCommitment: text("key_commitment"),
    createdAt: text("created_at").notNull(),
    supersededAt: text("superseded_at"),
  },
  (table) => [
    uniqueIndex("account_key_epochs_user_number_unique").on(
      table.userId,
      table.epochNumber,
    ),
    index("account_key_epochs_user_active_idx").on(table.userId, table.supersededAt),
  ],
);

export const sessions = sqliteTable(
  "sessions",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    authMode: text("auth_mode", { enum: ["twilio", "test"] })
      .notNull()
      .default("twilio"),
    testAccessGeneration: text("test_access_generation"),
    createdAt: text("created_at").notNull(),
    expiresAt: text("expires_at").notNull(),
    lastSeenAt: text("last_seen_at").notNull(),
    revokedAt: text("revoked_at"),
  },
  (table) => [
    uniqueIndex("sessions_token_hash_unique").on(table.tokenHash),
    index("sessions_user_id_idx").on(table.userId),
    index("sessions_expires_at_idx").on(table.expiresAt),
  ],
);

export const challenges = sqliteTable(
  "challenges",
  {
    id: text("id").primaryKey(),
    phoneNumber: text("phone_number").notNull(),
    phoneHash: text("phone_hash").notNull(),
    codeHash: text("code_hash"),
    providerSid: text("provider_sid"),
    delivery: text("delivery", { enum: ["sms", "test"] }).notNull(),
    status: text("status", {
      enum: ["pending", "verified", "expired", "locked", "provider_error"],
    })
      .notNull()
      .default("pending"),
    requestIpHash: text("request_ip_hash").notNull(),
    attemptCount: integer("attempt_count").notNull().default(0),
    maxAttempts: integer("max_attempts").notNull().default(5),
    createdAt: text("created_at").notNull(),
    expiresAt: text("expires_at").notNull(),
    resendAt: text("resend_at").notNull(),
    verifiedAt: text("verified_at"),
  },
  (table) => [
    index("challenges_phone_created_idx").on(table.phoneHash, table.createdAt),
    index("challenges_expires_at_idx").on(table.expiresAt),
    index("challenges_status_idx").on(table.status),
  ],
);

export const authPhoneRateLimits = sqliteTable("auth_phone_rate_limits", {
  phoneHash: text("phone_hash").primaryKey(),
  windowStartedAt: text("window_started_at").notNull(),
  requestCount: integer("request_count").notNull(),
  lastRequestedAt: text("last_requested_at").notNull(),
});

export const authIpRateLimits = sqliteTable("auth_ip_rate_limits", {
  ipHash: text("ip_hash").primaryKey(),
  windowStartedAt: text("window_started_at").notNull(),
  requestCount: integer("request_count").notNull(),
  lastRequestedAt: text("last_requested_at").notNull(),
});

// Privacy-preserving operational telemetry. This table intentionally contains
// aggregate counters only: no request, account, event, invitation, device, IP,
// or correlation identifiers are durable.
export const operationalMetrics = sqliteTable(
  "operational_metrics",
  {
    bucketStartedAt: text("bucket_started_at").notNull(),
    component: text("component").notNull(),
    signal: text("signal").notNull(),
    operation: text("operation").notNull(),
    outcome: text("outcome").notNull(),
    statusClass: text("status_class").notNull(),
    errorCode: text("error_code").notNull(),
    latencyBucket: text("latency_bucket").notNull(),
    releaseId: text("release_id").notNull(),
    count: integer("count").notNull().default(0),
    latencyTotalMs: integer("latency_total_ms").notNull().default(0),
    latencyMaxMs: integer("latency_max_ms").notNull().default(0),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    primaryKey({
      columns: [
        table.bucketStartedAt,
        table.component,
        table.signal,
        table.operation,
        table.outcome,
        table.statusClass,
        table.errorCode,
        table.latencyBucket,
        table.releaseId,
      ],
    }),
    index("operational_metrics_bucket_idx").on(table.bucketStartedAt),
    index("operational_metrics_signal_idx").on(
      table.signal,
      table.bucketStartedAt,
    ),
  ],
);

export const operationalAlerts = sqliteTable(
  "operational_alerts",
  {
    id: text("id").primaryKey(),
    recordedAt: text("recorded_at").notNull(),
    recovered: integer("recovered", { mode: "boolean" }).notNull(),
    target: text("target").notNull(),
    failureClass: text("failure_class").notNull(),
    releaseId: text("release_id").notNull(),
    durationMs: integer("duration_ms"),
  },
  (table) => [
    index("operational_alerts_recorded_idx").on(table.recordedAt),
    index("operational_alerts_failure_idx").on(table.failureClass, table.recordedAt),
  ],
);

export const events = sqliteTable(
  "events",
  {
    id: text("id").primaryKey(),
    hostUserId: text("host_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    title: text("title").notNull(),
    eventDate: text("event_date"),
    endDate: text("end_date"),
    hostName: text("host_name").notNull(),
    locationName: text("location_name").notNull().default(""),
    locationAddress: text("location_address").notNull().default(""),
    minimumParticipants: integer("minimum_participants").notNull(),
    allowsAttendeesToAddGuests: integer("allows_attendees_to_add_guests", {
      mode: "boolean",
    }).notNull().default(true),
    rsvpDeadline: text("rsvp_deadline"),
    eventDescription: text("event_description").notNull().default(""),
    eventImageID: text("event_image_id").notNull().default("poker"),
    invitationsSent: integer("invitations_sent", { mode: "boolean" }).notNull().default(false),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    index("events_host_user_id_idx").on(table.hostUserId),
    index("events_event_date_idx").on(table.eventDate),
    index("events_due_resolution_idx").on(
      table.invitationsSent,
      table.rsvpDeadline,
      table.id,
    ),
  ],
);

export const eventPolicies = sqliteTable(
  "event_policies",
  {
    eventId: text("event_id")
      .primaryKey()
      .references(() => events.id, { onDelete: "cascade" }),
    protocolVersion: integer("protocol_version").notNull(),
    cipherSuite: text("cipher_suite").notNull(),
    policyHash: text("policy_hash").notNull(),
    canonicalDocument: text("canonical_document").notNull(),
    evaluatorKeyId: text("evaluator_key_id").notNull(),
    evaluatorPublicKey: text("evaluator_public_key").notNull(),
    evaluatorMeasurement: text("evaluator_measurement").notNull(),
    releaseId: text("release_id").notNull(),
    evaluatorEpochDescriptorSha256: text("evaluator_epoch_descriptor_sha256"),
    paddedPlaintextBytes: integer("padded_plaintext_bytes").notNull(),
    frozenAt: text("frozen_at").notNull(),
    policySigningKeyId: text("policy_signing_key_id"),
    policySignature: text("policy_signature"),
  },
  (table) => [uniqueIndex("event_policies_policy_hash_unique").on(table.policyHash)],
);

export const evaluatorEpochState = sqliteTable("evaluator_epoch_state", {
  singletonId: integer("singleton_id").primaryKey(),
  generation: integer("generation").notNull(),
  mode: text("mode", { enum: ["active", "draining"] }).notNull(),
  evaluatorKeyEpochId: text("evaluator_key_epoch_id").notNull(),
  epochDescriptorSha256: text("epoch_descriptor_sha256").notNull(),
  transparencyIdentitySha256: text("transparency_identity_sha256").notNull(),
  workloadImageDigest: text("workload_image_digest").notNull(),
  responseDecryptionKeyId: text("response_decryption_key_id").notNull(),
  evaluationResultSigningKeyId: text("evaluation_result_signing_key_id").notNull(),
  policySigningKeyId: text("policy_signing_key_id").notNull(),
  responseTransparencySigningKeyId: text(
    "response_transparency_signing_key_id",
  ).notNull(),
  activatedAt: text("activated_at").notNull(),
  drainStartedAt: text("drain_started_at"),
  updatedAt: text("updated_at").notNull(),
});

export const evaluatorEpochTransitions = sqliteTable(
  "evaluator_epoch_transitions",
  {
    transitionId: text("transition_id").primaryKey(),
    fromGeneration: integer("from_generation").notNull(),
    fromEvaluatorKeyEpochId: text("from_evaluator_key_epoch_id").notNull(),
    fromEpochDescriptorSha256: text("from_epoch_descriptor_sha256").notNull(),
    transparencyIdentitySha256: text("transparency_identity_sha256").notNull(),
    drainStartedAt: text("drain_started_at").notNull(),
    unresolvedPolicyCountAtDrain: integer(
      "unresolved_policy_count_at_drain",
    ).notNull(),
    activeEvaluationLeaseCountAtDrain: integer(
      "active_evaluation_lease_count_at_drain",
    ).notNull(),
    activeEvaluationJobCountAtDrain: integer(
      "active_evaluation_job_count_at_drain",
    ).notNull(),
    uncertifiedTransparencyCountAtDrain: integer(
      "uncertified_transparency_count_at_drain",
    ).notNull(),
    toGeneration: integer("to_generation"),
    toEvaluatorKeyEpochId: text("to_evaluator_key_epoch_id"),
    toEpochDescriptorSha256: text("to_epoch_descriptor_sha256"),
    activatedAt: text("activated_at"),
    canonicalActivationEvidence: text("canonical_activation_evidence"),
    activationEvidenceSha256: text("activation_evidence_sha256"),
  },
  (table) => [
    uniqueIndex("evaluator_epoch_transitions_generation_unique").on(
      table.fromGeneration,
    ),
  ],
);

export const invitees = sqliteTable(
  "invitees",
  {
    id: text("id").primaryKey(),
    eventId: text("event_id")
      .notNull()
      .references(() => events.id, { onDelete: "cascade" }),
    userId: text("user_id").references(() => users.id, { onDelete: "set null" }),
    displayName: text("display_name").notNull(),
    phoneNumber: text("phone_number").notNull(),
    phoneHash: text("phone_hash").notNull(),
    tokenHash: text("token_hash").notNull(),
    tokenCiphertext: text("token_ciphertext"),
    tokenNonce: text("token_nonce"),
    tokenStorageVersion: integer("token_storage_version"),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    uniqueIndex("invitees_event_phone_unique").on(table.eventId, table.phoneHash),
    uniqueIndex("invitees_token_hash_unique").on(table.tokenHash),
    index("invitees_event_id_idx").on(table.eventId),
    index("invitees_user_id_idx").on(table.userId),
    index("invitees_phone_hash_idx").on(table.phoneHash),
  ],
);

export const groups = sqliteTable(
  "groups",
  {
    id: text("id").primaryKey(),
    eventId: text("event_id")
      .notNull()
      .references(() => events.id, { onDelete: "cascade" }),
    position: integer("position").notNull(),
  },
  (table) => [
    uniqueIndex("groups_event_position_unique").on(table.eventId, table.position),
    index("groups_event_id_idx").on(table.eventId),
  ],
);

export const groupMembers = sqliteTable(
  "group_members",
  {
    groupId: text("group_id")
      .notNull()
      .references(() => groups.id, { onDelete: "cascade" }),
    inviteeId: text("invitee_id")
      .notNull()
      .references(() => invitees.id, { onDelete: "cascade" }),
    position: integer("position").notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.groupId, table.inviteeId] }),
    uniqueIndex("group_members_group_position_unique").on(table.groupId, table.position),
    index("group_members_invitee_id_idx").on(table.inviteeId),
  ],
);

export const responseEnvelopes = sqliteTable(
  "response_envelopes",
  {
    id: text("id").primaryKey(),
    eventId: text("event_id")
      .notNull()
      .references(() => events.id, { onDelete: "cascade" }),
    inviteeId: text("invitee_id")
      .notNull()
      .references(() => invitees.id, { onDelete: "cascade" }),
    accountKeyEpochId: text("account_key_epoch_id")
      .notNull()
      .references(() => accountKeyEpochs.id, { onDelete: "cascade" }),
    policyHash: text("policy_hash").notNull(),
    protocolVersion: integer("protocol_version").notNull(),
    cipherSuite: text("cipher_suite").notNull(),
    evaluatorKeyId: text("evaluator_key_id").notNull(),
    revision: integer("revision").notNull(),
    payloadCiphertext: text("payload_ciphertext").notNull(),
    userKeyWrap: text("user_key_wrap").notNull(),
    evaluatorKeyWrap: text("evaluator_key_wrap").notNull(),
    responseSigningPublicKey: text("response_signing_public_key"),
    responseSignature: text("response_signature"),
    ciphertextHash: text("ciphertext_hash").notNull(),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    uniqueIndex("response_envelopes_invitee_revision_unique").on(
      table.inviteeId,
      table.revision,
    ),
    uniqueIndex("response_envelopes_ciphertext_hash_unique").on(table.ciphertextHash),
    index("response_envelopes_event_id_idx").on(table.eventId),
    index("response_envelopes_invitee_revision_idx").on(
      table.inviteeId,
      table.revision,
    ),
    index("response_envelopes_account_epoch_idx").on(table.accountKeyEpochId),
    index("response_envelopes_policy_hash_idx").on(table.policyHash),
  ],
);

// Protocol-v2 ballots intentionally have no foreign key or identifying field for
// an invitee, user, account, phone number, session, or invitation token.
export const ballotRevisions = sqliteTable(
  "ballot_revisions",
  {
    ballotId: text("ballot_id").notNull(),
    revision: integer("revision").notNull(),
    protocolVersion: integer("protocol_version").notNull().default(2),
    keyVersion: integer("key_version").notNull().default(1),
    eventId: text("event_id")
      .notNull()
      .references(() => events.id, { onDelete: "cascade" }),
    response: text("response", { enum: ["going", "cant_commit"] }).notNull(),
    minimumParticipants: integer("minimum_participants"),
    requiredGroups: text("required_groups").notNull().default("[]"),
    source: text("source", {
      enum: ["user", "support_correction", "legacy_migration"],
    }).notNull().default("user"),
    correctionReason: text("correction_reason"),
    contentDigest: text("content_digest").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.ballotId, table.revision] }),
    uniqueIndex("ballot_revisions_digest_unique").on(table.contentDigest),
    index("ballot_revisions_event_idx").on(table.eventId, table.ballotId, table.revision),
  ],
);

export const ballotEvaluationRuns = sqliteTable(
  "ballot_evaluation_runs",
  {
    id: text("id").primaryKey(),
    eventId: text("event_id")
      .notNull()
      .references(() => events.id, { onDelete: "cascade" }),
    inputDigest: text("input_digest").notNull(),
    inputRevisions: text("input_revisions").notNull(),
    status: text("status", { enum: ["confirmed", "not_confirmed", "failed"] }).notNull(),
    attendingMemberIds: text("attending_member_ids"),
    errorCode: text("error_code"),
    source: text("source", { enum: ["automatic", "operator_replay", "operator_override"] })
      .notNull(),
    reason: text("reason"),
    createdAt: text("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("ballot_evaluation_runs_input_unique").on(table.eventId, table.inputDigest),
    index("ballot_evaluation_runs_event_idx").on(table.eventId, table.createdAt),
  ],
);

// Cached evaluator envelopes make retries deterministic. They are keyed only
// by the event-scoped ballot pseudonym and revision; no account identity is
// stored beside the readable ballot record.
export const ballotEvaluationSlots = sqliteTable(
  "ballot_evaluation_slots",
  {
    ballotId: text("ballot_id").notNull(),
    revision: integer("revision").notNull(),
    eventId: text("event_id")
      .notNull()
      .references(() => events.id, { onDelete: "cascade" }),
    envelope: text("envelope").notNull(),
    envelopeHash: text("envelope_hash").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => [
    primaryKey({ columns: [table.ballotId, table.revision] }),
    uniqueIndex("ballot_evaluation_slots_hash_unique").on(table.envelopeHash),
    index("ballot_evaluation_slots_event_idx").on(table.eventId),
  ],
);

export const ballotOperatorActions = sqliteTable(
  "ballot_operator_actions",
  {
    id: text("id").primaryKey(),
    eventId: text("event_id").notNull(),
    ballotId: text("ballot_id"),
    action: text("action").notNull(),
    actor: text("actor").notNull(),
    reason: text("reason").notNull(),
    previousDigest: text("previous_digest"),
    nextDigest: text("next_digest"),
    correlationId: text("correlation_id").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => [index("ballot_operator_actions_event_idx").on(table.eventId, table.createdAt)],
);

export const responseTransparencyEntries = sqliteTable(
  "response_transparency_entries",
  {
    logIndex: integer("log_index").primaryKey({ autoIncrement: true }),
    logId: text("log_id").notNull(),
    previousEntryHash: text("previous_entry_hash").notNull(),
    entryHash: text("entry_hash").notNull(),
    // This is intentionally a commitment reference rather than a foreign key:
    // response data can be erased without deleting or rewriting the public,
    // append-only transparency history.
    envelopeId: text("envelope_id").notNull(),
    canonicalReceiptPayload: text("canonical_receipt_payload").notNull(),
    signingKeyId: text("signing_key_id").notNull(),
    receiptSignature: text("receipt_signature"),
    createdAt: text("created_at").notNull(),
    signedAt: text("signed_at"),
  },
  (table) => [
    uniqueIndex("response_transparency_entries_previous_unique").on(
      table.previousEntryHash,
    ),
    uniqueIndex("response_transparency_entries_hash_unique").on(table.entryHash),
    uniqueIndex("response_transparency_entries_envelope_unique").on(table.envelopeId),
    index("response_transparency_entries_log_idx").on(table.logId, table.logIndex),
  ],
);

export const responseTransparencyHeads = sqliteTable(
  "response_transparency_heads",
  {
    logIndex: integer("log_index")
      .primaryKey()
      .references(() => responseTransparencyEntries.logIndex, { onDelete: "cascade" }),
    logId: text("log_id").notNull(),
    headEntryHash: text("head_entry_hash").notNull(),
    canonicalPayload: text("canonical_payload").notNull(),
    signingKeyId: text("signing_key_id").notNull(),
    signature: text("signature").notNull(),
    generatedAt: text("generated_at").notNull(),
  },
  (table) => [
    uniqueIndex("response_transparency_heads_hash_unique").on(table.headEntryHash),
    index("response_transparency_heads_log_idx").on(table.logId, table.logIndex),
  ],
);

export const eventResolutions = sqliteTable(
  "event_resolutions",
  {
    eventId: text("event_id")
      .primaryKey()
      .references(() => events.id, { onDelete: "cascade" }),
    policyHash: text("policy_hash").notNull(),
    status: text("status", {
      enum: ["pending", "evaluating", "confirmed", "not_confirmed"],
    })
      .notNull()
      .default("pending"),
    batchHash: text("batch_hash"),
    attendingMemberIds: text("attending_member_ids"),
    resolvedAt: text("resolved_at"),
    evaluationLeaseId: text("evaluation_lease_id"),
    evaluationLeaseExpiresAt: text("evaluation_lease_expires_at"),
    evaluationRequestHash: text("evaluation_request_hash"),
    resultAttestationProtocolVersion: integer("result_attestation_protocol_version"),
    resultAttestationSigningKeyId: text("result_attestation_signing_key_id"),
    resultAttestationEvaluatedAt: text("result_attestation_evaluated_at"),
    resultAttestationCanonicalDocument: text("result_attestation_canonical_document"),
    resultAttestationSignature: text("result_attestation_signature"),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    uniqueIndex("event_resolutions_batch_hash_unique").on(table.batchHash),
    index("event_resolutions_status_idx").on(table.status),
    index("event_resolutions_policy_hash_idx").on(table.policyHash),
  ],
);

export const resolutionNotifications = sqliteTable(
  "resolution_notifications",
  {
    id: text("id").primaryKey(),
    eventId: text("event_id")
      .notNull()
      .references(() => events.id, { onDelete: "cascade" }),
    batchHash: text("batch_hash").notNull(),
    status: text("status", { enum: ["confirmed", "not_confirmed"] }).notNull(),
    phoneNumber: text("phone_number").notNull(),
    deliveryStatus: text("delivery_status", {
      enum: ["dispatching", "sent", "failed", "unknown", "suppressed"],
    }).notNull(),
    providerMessageSid: text("provider_message_sid"),
    errorCode: text("error_code"),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    uniqueIndex("resolution_notifications_event_batch_phone_unique").on(
      table.eventId,
      table.batchHash,
      table.phoneNumber,
    ),
    index("resolution_notifications_event_created_idx").on(
      table.eventId,
      table.createdAt,
    ),
  ],
);

export const invitationDeliveries = sqliteTable(
  "invitation_deliveries",
  {
    id: text("id").primaryKey(),
    eventId: text("event_id")
      .notNull()
      .references(() => events.id, { onDelete: "cascade" }),
    inviteeId: text("invitee_id")
      .notNull()
      .references(() => invitees.id, { onDelete: "cascade" }),
    status: text("status", {
      enum: [
        "pending",
        "dispatching",
        "sent",
        "failed",
        "unknown",
        "suppressed",
      ],
    }).notNull(),
    providerMessageSid: text("provider_message_sid"),
    providerStatus: text("provider_status"),
    attemptCount: integer("attempt_count").notNull().default(0),
    dispatchStartedAt: text("dispatch_started_at"),
    sentAt: text("sent_at"),
    failedAt: text("failed_at"),
    lastErrorCode: text("last_error_code"),
    lastErrorMessage: text("last_error_message"),
    suppressedReason: text("suppressed_reason"),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    uniqueIndex("invitation_deliveries_event_invitee_unique").on(
      table.eventId,
      table.inviteeId,
    ),
    uniqueIndex("invitation_deliveries_provider_sid_unique").on(
      table.providerMessageSid,
    ),
    index("invitation_deliveries_event_status_idx").on(table.eventId, table.status),
    index("invitation_deliveries_dispatch_started_idx").on(
      table.status,
      table.dispatchStartedAt,
    ),
  ],
);
