CREATE TABLE `evaluator_epoch_state` (
	`singleton_id` integer PRIMARY KEY NOT NULL,
	`generation` integer NOT NULL,
	`mode` text NOT NULL,
	`evaluator_key_epoch_id` text NOT NULL,
	`epoch_descriptor_sha256` text NOT NULL,
	`transparency_identity_sha256` text NOT NULL,
	`workload_image_digest` text NOT NULL,
	`response_decryption_key_id` text NOT NULL,
	`evaluation_result_signing_key_id` text NOT NULL,
	`policy_signing_key_id` text NOT NULL,
	`response_transparency_signing_key_id` text NOT NULL,
	`activated_at` text NOT NULL,
	`drain_started_at` text,
	`updated_at` text NOT NULL,
	CONSTRAINT `evaluator_epoch_state_singleton_check` CHECK (`singleton_id` = 1),
	CONSTRAINT `evaluator_epoch_state_generation_check` CHECK (`generation` >= 1),
	CONSTRAINT `evaluator_epoch_state_mode_check` CHECK (`mode` IN ('active', 'draining')),
	CONSTRAINT `evaluator_epoch_state_drain_check` CHECK (
		(`mode` = 'active' AND `drain_started_at` IS NULL) OR
		(`mode` = 'draining' AND `drain_started_at` IS NOT NULL)
	),
	CONSTRAINT `evaluator_epoch_state_digest_check` CHECK (
		length(`epoch_descriptor_sha256`) = 64 AND
		length(`transparency_identity_sha256`) = 64
	)
);
--> statement-breakpoint
CREATE TABLE `evaluator_epoch_transitions` (
	`transition_id` text PRIMARY KEY NOT NULL,
	`from_generation` integer NOT NULL,
	`from_evaluator_key_epoch_id` text NOT NULL,
	`from_epoch_descriptor_sha256` text NOT NULL,
	`transparency_identity_sha256` text NOT NULL,
	`drain_started_at` text NOT NULL,
	`unresolved_policy_count_at_drain` integer NOT NULL,
	`active_evaluation_lease_count_at_drain` integer NOT NULL,
	`active_evaluation_job_count_at_drain` integer NOT NULL,
	`uncertified_transparency_count_at_drain` integer NOT NULL,
	`to_generation` integer,
	`to_evaluator_key_epoch_id` text,
	`to_epoch_descriptor_sha256` text,
	`activated_at` text,
	`canonical_activation_evidence` text,
	`activation_evidence_sha256` text,
	CONSTRAINT `evaluator_epoch_transition_generation_check` CHECK (`from_generation` >= 1),
	CONSTRAINT `evaluator_epoch_transition_counts_check` CHECK (
		`unresolved_policy_count_at_drain` >= 0 AND
		`active_evaluation_lease_count_at_drain` >= 0 AND
		`active_evaluation_job_count_at_drain` >= 0 AND
		`uncertified_transparency_count_at_drain` >= 0
	),
	CONSTRAINT `evaluator_epoch_transition_activation_check` CHECK (
		(
			`to_generation` IS NULL AND
			`to_evaluator_key_epoch_id` IS NULL AND
			`to_epoch_descriptor_sha256` IS NULL AND
			`activated_at` IS NULL AND
			`canonical_activation_evidence` IS NULL AND
			`activation_evidence_sha256` IS NULL
		) OR (
			`to_generation` = `from_generation` + 1 AND
			`to_evaluator_key_epoch_id` IS NOT NULL AND
			`to_epoch_descriptor_sha256` IS NOT NULL AND
			`activated_at` IS NOT NULL AND
			`canonical_activation_evidence` IS NOT NULL AND
			length(`activation_evidence_sha256`) = 64
		)
	)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `evaluator_epoch_transitions_generation_unique` ON `evaluator_epoch_transitions` (`from_generation`);--> statement-breakpoint
ALTER TABLE `event_policies` ADD `evaluator_epoch_descriptor_sha256` text;--> statement-breakpoint
CREATE TRIGGER `evaluator_epoch_state_insert_guard`
BEFORE INSERT ON `evaluator_epoch_state`
WHEN NEW.`singleton_id` <> 1
  OR (
    NOT EXISTS (SELECT 1 FROM `evaluator_epoch_state`) AND (
      EXISTS (SELECT 1 FROM `event_policies`) OR
      EXISTS (SELECT 1 FROM `event_resolutions`) OR
      EXISTS (SELECT 1 FROM `response_transparency_entries`) OR
      EXISTS (SELECT 1 FROM `response_transparency_heads`)
    )
  )
BEGIN
	SELECT RAISE(ABORT, 'evaluator_epoch_bootstrap_conflict');
END;--> statement-breakpoint
CREATE TRIGGER `evaluator_epoch_state_update_guard`
BEFORE UPDATE ON `evaluator_epoch_state`
WHEN NOT (
	(
		OLD.`mode` = 'active' AND NEW.`mode` = 'draining' AND
		NEW.`generation` = OLD.`generation` AND
		NEW.`evaluator_key_epoch_id` = OLD.`evaluator_key_epoch_id` AND
		NEW.`epoch_descriptor_sha256` = OLD.`epoch_descriptor_sha256` AND
		NEW.`transparency_identity_sha256` = OLD.`transparency_identity_sha256` AND
		NEW.`workload_image_digest` = OLD.`workload_image_digest` AND
		NEW.`response_decryption_key_id` = OLD.`response_decryption_key_id` AND
		NEW.`evaluation_result_signing_key_id` = OLD.`evaluation_result_signing_key_id` AND
		NEW.`policy_signing_key_id` = OLD.`policy_signing_key_id` AND
		NEW.`response_transparency_signing_key_id` = OLD.`response_transparency_signing_key_id` AND
		NEW.`activated_at` = OLD.`activated_at` AND
		NEW.`drain_started_at` IS NOT NULL
	) OR (
		OLD.`mode` = 'draining' AND NEW.`mode` = 'active' AND
		NEW.`generation` = OLD.`generation` + 1 AND
		NEW.`evaluator_key_epoch_id` <> OLD.`evaluator_key_epoch_id` AND
		NEW.`epoch_descriptor_sha256` <> OLD.`epoch_descriptor_sha256` AND
		NEW.`transparency_identity_sha256` = OLD.`transparency_identity_sha256` AND
		NEW.`drain_started_at` IS NULL AND
		NOT EXISTS (
			SELECT 1
			FROM `event_policies` AS policies
			LEFT JOIN `event_resolutions` AS resolutions
				ON resolutions.`event_id` = policies.`event_id`
			WHERE resolutions.`status` IS NULL
				OR resolutions.`status` NOT IN ('confirmed', 'not_confirmed')
		) AND
		NOT EXISTS (
			SELECT 1 FROM `event_resolutions`
			WHERE `status` = 'evaluating'
		) AND
		NOT EXISTS (
			SELECT 1
			FROM `response_transparency_entries` AS entries
			LEFT JOIN `response_transparency_heads` AS heads
				ON heads.`log_index` = entries.`log_index`
			WHERE entries.`log_id` <> 'herd-response-log-v1'
				OR entries.`signing_key_id` <>
					OLD.`response_transparency_signing_key_id`
				OR entries.`receipt_signature` IS NULL
				OR entries.`signed_at` IS NULL
				OR heads.`log_index` IS NULL
				OR heads.`log_id` <> 'herd-response-log-v1'
				OR heads.`signing_key_id` <>
					OLD.`response_transparency_signing_key_id`
				OR heads.`log_id` <> entries.`log_id`
				OR heads.`head_entry_hash` <> entries.`entry_hash`
				OR heads.`signing_key_id` <> entries.`signing_key_id`
		) AND
		NOT EXISTS (
			SELECT 1
			FROM `response_transparency_heads` AS heads
			LEFT JOIN `response_transparency_entries` AS entries
				ON entries.`log_index` = heads.`log_index`
			WHERE entries.`log_index` IS NULL
				OR heads.`log_id` <> 'herd-response-log-v1'
				OR heads.`signing_key_id` <>
					OLD.`response_transparency_signing_key_id`
		)
	)
)
BEGIN
	SELECT RAISE(ABORT, 'invalid_evaluator_epoch_state_transition');
END;--> statement-breakpoint
CREATE TRIGGER `evaluator_epoch_state_delete_guard`
BEFORE DELETE ON `evaluator_epoch_state`
BEGIN
	SELECT RAISE(ABORT, 'evaluator_epoch_state_is_immutable');
END;--> statement-breakpoint
CREATE TRIGGER `evaluator_epoch_transition_update_guard`
BEFORE UPDATE ON `evaluator_epoch_transitions`
WHEN OLD.`activated_at` IS NOT NULL
  OR NEW.`transition_id` <> OLD.`transition_id`
  OR NEW.`from_generation` <> OLD.`from_generation`
  OR NEW.`from_evaluator_key_epoch_id` <> OLD.`from_evaluator_key_epoch_id`
  OR NEW.`from_epoch_descriptor_sha256` <> OLD.`from_epoch_descriptor_sha256`
  OR NEW.`transparency_identity_sha256` <> OLD.`transparency_identity_sha256`
  OR NEW.`drain_started_at` <> OLD.`drain_started_at`
  OR NEW.`unresolved_policy_count_at_drain` <> OLD.`unresolved_policy_count_at_drain`
  OR NEW.`active_evaluation_lease_count_at_drain` <> OLD.`active_evaluation_lease_count_at_drain`
  OR NEW.`active_evaluation_job_count_at_drain` <> OLD.`active_evaluation_job_count_at_drain`
  OR NEW.`uncertified_transparency_count_at_drain` <> OLD.`uncertified_transparency_count_at_drain`
BEGIN
	SELECT RAISE(ABORT, 'evaluator_epoch_transition_is_immutable');
END;--> statement-breakpoint
CREATE TRIGGER `evaluator_epoch_transition_delete_guard`
BEFORE DELETE ON `evaluator_epoch_transitions`
BEGIN
	SELECT RAISE(ABORT, 'evaluator_epoch_transition_is_immutable');
END;--> statement-breakpoint
CREATE TRIGGER `event_policy_evaluator_epoch_fence`
BEFORE INSERT ON `event_policies`
WHEN NEW.`evaluator_epoch_descriptor_sha256` IS NULL
  OR NOT EXISTS (
	SELECT 1 FROM `evaluator_epoch_state`
	WHERE `singleton_id` = 1
	  AND `mode` = 'active'
	  AND `evaluator_key_epoch_id` = NEW.`release_id`
	  AND `epoch_descriptor_sha256` = NEW.`evaluator_epoch_descriptor_sha256`
  )
BEGIN
	SELECT RAISE(ABORT, 'evaluator_epoch_policy_freeze_blocked');
END;
