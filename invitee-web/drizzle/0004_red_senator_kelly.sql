CREATE TABLE `event_resolutions` (
	`event_id` text PRIMARY KEY NOT NULL,
	`policy_hash` text NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`batch_hash` text,
	`attending_member_ids` text,
	`resolved_at` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `event_resolutions_batch_hash_unique` ON `event_resolutions` (`batch_hash`);--> statement-breakpoint
CREATE INDEX `event_resolutions_status_idx` ON `event_resolutions` (`status`);--> statement-breakpoint
CREATE INDEX `event_resolutions_policy_hash_idx` ON `event_resolutions` (`policy_hash`);--> statement-breakpoint
INSERT INTO `event_resolutions`
	(`event_id`, `policy_hash`, `status`, `batch_hash`, `attending_member_ids`,
	 `resolved_at`, `created_at`, `updated_at`)
SELECT `event_id`, `policy_hash`, 'pending', NULL, NULL, NULL, `frozen_at`, `frozen_at`
FROM `event_policies`;--> statement-breakpoint
DROP INDEX `response_envelopes_invitee_id_unique`;--> statement-breakpoint
CREATE UNIQUE INDEX `response_envelopes_invitee_revision_unique` ON `response_envelopes` (`invitee_id`,`revision`);--> statement-breakpoint
CREATE INDEX `response_envelopes_invitee_revision_idx` ON `response_envelopes` (`invitee_id`,`revision`);
