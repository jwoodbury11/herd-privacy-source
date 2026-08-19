CREATE TABLE `ballot_revisions` (
	`ballot_id` text NOT NULL,
	`revision` integer NOT NULL,
	`protocol_version` integer DEFAULT 2 NOT NULL,
	`key_version` integer DEFAULT 1 NOT NULL,
	`event_id` text NOT NULL,
	`response` text NOT NULL,
	`minimum_participants` integer,
	`required_groups` text DEFAULT '[]' NOT NULL,
	`source` text DEFAULT 'user' NOT NULL,
	`correction_reason` text,
	`content_digest` text NOT NULL,
	`created_at` text NOT NULL,
	PRIMARY KEY(`ballot_id`, `revision`),
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `ballot_revisions_digest_unique` ON `ballot_revisions` (`content_digest`);--> statement-breakpoint
CREATE INDEX `ballot_revisions_event_idx` ON `ballot_revisions` (`event_id`,`ballot_id`,`revision`);--> statement-breakpoint
CREATE TABLE `ballot_evaluation_runs` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`input_digest` text NOT NULL,
	`input_revisions` text NOT NULL,
	`status` text NOT NULL,
	`attending_member_ids` text,
	`error_code` text,
	`source` text NOT NULL,
	`reason` text,
	`created_at` text NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `ballot_evaluation_runs_input_unique` ON `ballot_evaluation_runs` (`event_id`,`input_digest`);--> statement-breakpoint
CREATE INDEX `ballot_evaluation_runs_event_idx` ON `ballot_evaluation_runs` (`event_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `ballot_evaluation_slots` (
	`ballot_id` text NOT NULL,
	`revision` integer NOT NULL,
	`event_id` text NOT NULL,
	`envelope` text NOT NULL,
	`envelope_hash` text NOT NULL,
	`created_at` text NOT NULL,
	PRIMARY KEY(`ballot_id`, `revision`),
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `ballot_evaluation_slots_hash_unique` ON `ballot_evaluation_slots` (`envelope_hash`);--> statement-breakpoint
CREATE INDEX `ballot_evaluation_slots_event_idx` ON `ballot_evaluation_slots` (`event_id`);--> statement-breakpoint
CREATE TABLE `ballot_operator_actions` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`ballot_id` text,
	`action` text NOT NULL,
	`actor` text NOT NULL,
	`reason` text NOT NULL,
	`previous_digest` text,
	`next_digest` text,
	`correlation_id` text NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `ballot_operator_actions_event_idx` ON `ballot_operator_actions` (`event_id`,`created_at`);
