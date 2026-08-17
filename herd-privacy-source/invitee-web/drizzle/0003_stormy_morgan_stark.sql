CREATE TABLE `account_key_epochs` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`epoch_number` integer NOT NULL,
	`key_commitment` text,
	`created_at` text NOT NULL,
	`superseded_at` text,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `account_key_epochs_user_number_unique` ON `account_key_epochs` (`user_id`,`epoch_number`);--> statement-breakpoint
CREATE INDEX `account_key_epochs_user_active_idx` ON `account_key_epochs` (`user_id`,`superseded_at`);--> statement-breakpoint
CREATE TABLE `event_policies` (
	`event_id` text PRIMARY KEY NOT NULL,
	`protocol_version` integer NOT NULL,
	`cipher_suite` text NOT NULL,
	`policy_hash` text NOT NULL,
	`canonical_document` text NOT NULL,
	`evaluator_key_id` text NOT NULL,
	`evaluator_public_key` text NOT NULL,
	`evaluator_measurement` text NOT NULL,
	`release_id` text NOT NULL,
	`padded_plaintext_bytes` integer NOT NULL,
	`frozen_at` text NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `event_policies_policy_hash_unique` ON `event_policies` (`policy_hash`);--> statement-breakpoint
CREATE TABLE `response_envelopes` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`invitee_id` text NOT NULL,
	`account_key_epoch_id` text NOT NULL,
	`policy_hash` text NOT NULL,
	`protocol_version` integer NOT NULL,
	`cipher_suite` text NOT NULL,
	`evaluator_key_id` text NOT NULL,
	`revision` integer NOT NULL,
	`payload_ciphertext` text NOT NULL,
	`user_key_wrap` text NOT NULL,
	`evaluator_key_wrap` text NOT NULL,
	`ciphertext_hash` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`invitee_id`) REFERENCES `invitees`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`account_key_epoch_id`) REFERENCES `account_key_epochs`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `response_envelopes_invitee_id_unique` ON `response_envelopes` (`invitee_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `response_envelopes_ciphertext_hash_unique` ON `response_envelopes` (`ciphertext_hash`);--> statement-breakpoint
CREATE INDEX `response_envelopes_event_id_idx` ON `response_envelopes` (`event_id`);--> statement-breakpoint
CREATE INDEX `response_envelopes_account_epoch_idx` ON `response_envelopes` (`account_key_epoch_id`);--> statement-breakpoint
CREATE INDEX `response_envelopes_policy_hash_idx` ON `response_envelopes` (`policy_hash`);--> statement-breakpoint
DROP TABLE `rsvps`;