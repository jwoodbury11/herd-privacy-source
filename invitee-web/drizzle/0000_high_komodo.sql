CREATE TABLE `auth_phone_rate_limits` (
	`phone_hash` text PRIMARY KEY NOT NULL,
	`window_started_at` text NOT NULL,
	`request_count` integer NOT NULL,
	`last_requested_at` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `challenges` (
	`id` text PRIMARY KEY NOT NULL,
	`phone_number` text NOT NULL,
	`phone_hash` text NOT NULL,
	`code_hash` text,
	`provider_sid` text,
	`delivery` text NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`request_ip_hash` text NOT NULL,
	`attempt_count` integer DEFAULT 0 NOT NULL,
	`max_attempts` integer DEFAULT 5 NOT NULL,
	`created_at` text NOT NULL,
	`expires_at` text NOT NULL,
	`resend_at` text NOT NULL,
	`verified_at` text
);
--> statement-breakpoint
CREATE INDEX `challenges_phone_created_idx` ON `challenges` (`phone_hash`,`created_at`);--> statement-breakpoint
CREATE INDEX `challenges_expires_at_idx` ON `challenges` (`expires_at`);--> statement-breakpoint
CREATE INDEX `challenges_status_idx` ON `challenges` (`status`);--> statement-breakpoint
CREATE TABLE `events` (
	`id` text PRIMARY KEY NOT NULL,
	`host_user_id` text NOT NULL,
	`title` text NOT NULL,
	`event_date` text,
	`end_date` text,
	`host_name` text NOT NULL,
	`location_name` text DEFAULT '' NOT NULL,
	`location_address` text DEFAULT '' NOT NULL,
	`minimum_participants` integer NOT NULL,
	`rsvp_deadline` text,
	`event_description` text DEFAULT '' NOT NULL,
	`invitations_sent` integer DEFAULT false NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`host_user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `events_host_user_id_idx` ON `events` (`host_user_id`);--> statement-breakpoint
CREATE INDEX `events_event_date_idx` ON `events` (`event_date`);--> statement-breakpoint
CREATE TABLE `group_members` (
	`group_id` text NOT NULL,
	`invitee_id` text NOT NULL,
	`position` integer NOT NULL,
	PRIMARY KEY(`group_id`, `invitee_id`),
	FOREIGN KEY (`group_id`) REFERENCES `groups`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`invitee_id`) REFERENCES `invitees`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `group_members_group_position_unique` ON `group_members` (`group_id`,`position`);--> statement-breakpoint
CREATE INDEX `group_members_invitee_id_idx` ON `group_members` (`invitee_id`);--> statement-breakpoint
CREATE TABLE `groups` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`position` integer NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `groups_event_position_unique` ON `groups` (`event_id`,`position`);--> statement-breakpoint
CREATE INDEX `groups_event_id_idx` ON `groups` (`event_id`);--> statement-breakpoint
CREATE TABLE `invitees` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`user_id` text,
	`display_name` text NOT NULL,
	`phone_number` text NOT NULL,
	`phone_hash` text NOT NULL,
	`token_hash` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE UNIQUE INDEX `invitees_event_phone_unique` ON `invitees` (`event_id`,`phone_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `invitees_token_hash_unique` ON `invitees` (`token_hash`);--> statement-breakpoint
CREATE INDEX `invitees_event_id_idx` ON `invitees` (`event_id`);--> statement-breakpoint
CREATE INDEX `invitees_user_id_idx` ON `invitees` (`user_id`);--> statement-breakpoint
CREATE INDEX `invitees_phone_hash_idx` ON `invitees` (`phone_hash`);--> statement-breakpoint
CREATE TABLE `rsvps` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`invitee_id` text NOT NULL,
	`user_id` text NOT NULL,
	`reply` text NOT NULL,
	`minimum_participants` integer NOT NULL,
	`condition_groups` text DEFAULT '[]' NOT NULL,
	`sequence` integer DEFAULT 1 NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`invitee_id`) REFERENCES `invitees`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `rsvps_invitee_id_unique` ON `rsvps` (`invitee_id`);--> statement-breakpoint
CREATE INDEX `rsvps_event_id_idx` ON `rsvps` (`event_id`);--> statement-breakpoint
CREATE INDEX `rsvps_user_id_idx` ON `rsvps` (`user_id`);--> statement-breakpoint
CREATE TABLE `sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`token_hash` text NOT NULL,
	`created_at` text NOT NULL,
	`expires_at` text NOT NULL,
	`last_seen_at` text NOT NULL,
	`revoked_at` text,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `sessions_token_hash_unique` ON `sessions` (`token_hash`);--> statement-breakpoint
CREATE INDEX `sessions_user_id_idx` ON `sessions` (`user_id`);--> statement-breakpoint
CREATE INDEX `sessions_expires_at_idx` ON `sessions` (`expires_at`);--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY NOT NULL,
	`phone_number` text NOT NULL,
	`phone_hash` text NOT NULL,
	`name` text DEFAULT '' NOT NULL,
	`address` text DEFAULT '' NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_phone_number_unique` ON `users` (`phone_number`);--> statement-breakpoint
CREATE UNIQUE INDEX `users_phone_hash_unique` ON `users` (`phone_hash`);