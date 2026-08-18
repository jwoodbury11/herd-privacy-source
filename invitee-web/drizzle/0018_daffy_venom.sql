CREATE TABLE `operational_alerts` (
	`id` text PRIMARY KEY NOT NULL,
	`recorded_at` text NOT NULL,
	`recovered` integer NOT NULL,
	`target` text NOT NULL,
	`failure_class` text NOT NULL,
	`release_id` text NOT NULL,
	`duration_ms` integer
);
--> statement-breakpoint
CREATE INDEX `operational_alerts_recorded_idx` ON `operational_alerts` (`recorded_at`);--> statement-breakpoint
CREATE INDEX `operational_alerts_failure_idx` ON `operational_alerts` (`failure_class`,`recorded_at`);