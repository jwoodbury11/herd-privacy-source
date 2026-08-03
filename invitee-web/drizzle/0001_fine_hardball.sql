CREATE TABLE `auth_ip_rate_limits` (
	`ip_hash` text PRIMARY KEY NOT NULL,
	`window_started_at` text NOT NULL,
	`request_count` integer NOT NULL,
	`last_requested_at` text NOT NULL
);
--> statement-breakpoint
ALTER TABLE `sessions` ADD `auth_mode` text DEFAULT 'twilio' NOT NULL;