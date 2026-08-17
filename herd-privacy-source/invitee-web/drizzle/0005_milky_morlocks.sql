CREATE TABLE `invitation_deliveries` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`invitee_id` text NOT NULL,
	`status` text NOT NULL,
	`provider_message_sid` text,
	`provider_status` text,
	`attempt_count` integer DEFAULT 0 NOT NULL,
	`dispatch_started_at` text,
	`sent_at` text,
	`failed_at` text,
	`last_error_code` text,
	`last_error_message` text,
	`suppressed_reason` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`invitee_id`) REFERENCES `invitees`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `invitation_deliveries_event_invitee_unique` ON `invitation_deliveries` (`event_id`,`invitee_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `invitation_deliveries_provider_sid_unique` ON `invitation_deliveries` (`provider_message_sid`);--> statement-breakpoint
CREATE INDEX `invitation_deliveries_event_status_idx` ON `invitation_deliveries` (`event_id`,`status`);--> statement-breakpoint
CREATE INDEX `invitation_deliveries_dispatch_started_idx` ON `invitation_deliveries` (`status`,`dispatch_started_at`);--> statement-breakpoint
ALTER TABLE `invitees` ADD `token_ciphertext` text;--> statement-breakpoint
ALTER TABLE `invitees` ADD `token_nonce` text;--> statement-breakpoint
ALTER TABLE `invitees` ADD `token_storage_version` integer;