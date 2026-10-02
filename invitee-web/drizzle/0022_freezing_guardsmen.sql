CREATE TABLE `sms_rsvp_prompts` (
	`id` text PRIMARY KEY NOT NULL,
	`batch_id` text NOT NULL,
	`event_id` text NOT NULL,
	`invitee_id` text NOT NULL,
	`status` text NOT NULL,
	`provider_message_sid` text,
	`created_at` text NOT NULL,
	`expires_at` text NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`invitee_id`) REFERENCES `invitees`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `sms_rsvp_prompts_batch_guest_unique` ON `sms_rsvp_prompts` (`batch_id`,`invitee_id`);--> statement-breakpoint
CREATE INDEX `sms_rsvp_prompts_event_idx` ON `sms_rsvp_prompts` (`event_id`);--> statement-breakpoint
CREATE TABLE `sms_rsvp_receipts` (
	`message_hash` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE cascade
);
