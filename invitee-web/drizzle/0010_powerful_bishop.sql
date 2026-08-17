CREATE TABLE `response_transparency_entries` (
	`log_index` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`log_id` text NOT NULL,
	`previous_entry_hash` text NOT NULL,
	`entry_hash` text NOT NULL,
	`envelope_id` text NOT NULL,
	`canonical_receipt_payload` text NOT NULL,
	`signing_key_id` text NOT NULL,
	`receipt_signature` text,
	`created_at` text NOT NULL,
	`signed_at` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `response_transparency_entries_previous_unique` ON `response_transparency_entries` (`previous_entry_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `response_transparency_entries_hash_unique` ON `response_transparency_entries` (`entry_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `response_transparency_entries_envelope_unique` ON `response_transparency_entries` (`envelope_id`);--> statement-breakpoint
CREATE INDEX `response_transparency_entries_log_idx` ON `response_transparency_entries` (`log_id`,`log_index`);--> statement-breakpoint
CREATE TABLE `response_transparency_heads` (
	`log_index` integer PRIMARY KEY NOT NULL,
	`log_id` text NOT NULL,
	`head_entry_hash` text NOT NULL,
	`canonical_payload` text NOT NULL,
	`signing_key_id` text NOT NULL,
	`signature` text NOT NULL,
	`generated_at` text NOT NULL,
	FOREIGN KEY (`log_index`) REFERENCES `response_transparency_entries`(`log_index`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `response_transparency_heads_hash_unique` ON `response_transparency_heads` (`head_entry_hash`);--> statement-breakpoint
CREATE INDEX `response_transparency_heads_log_idx` ON `response_transparency_heads` (`log_id`,`log_index`);--> statement-breakpoint
ALTER TABLE `event_policies` ADD `policy_signing_key_id` text;--> statement-breakpoint
ALTER TABLE `event_policies` ADD `policy_signature` text;