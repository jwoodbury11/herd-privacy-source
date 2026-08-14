CREATE TABLE `resolution_notifications` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`batch_hash` text NOT NULL,
	`status` text NOT NULL,
	`phone_number` text NOT NULL,
	`delivery_status` text NOT NULL,
	`provider_message_sid` text,
	`error_code` text,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `events`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `resolution_notifications_event_batch_phone_unique` ON `resolution_notifications` (`event_id`,`batch_hash`,`phone_number`);--> statement-breakpoint
CREATE INDEX `resolution_notifications_event_created_idx` ON `resolution_notifications` (`event_id`,`created_at`);