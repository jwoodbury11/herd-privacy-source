CREATE TABLE `operational_metrics` (
	`bucket_started_at` text NOT NULL,
	`component` text NOT NULL,
	`signal` text NOT NULL,
	`operation` text NOT NULL,
	`outcome` text NOT NULL,
	`status_class` text NOT NULL,
	`error_code` text NOT NULL,
	`latency_bucket` text NOT NULL,
	`release_id` text NOT NULL,
	`count` integer DEFAULT 0 NOT NULL,
	`latency_total_ms` integer DEFAULT 0 NOT NULL,
	`latency_max_ms` integer DEFAULT 0 NOT NULL,
	`updated_at` text NOT NULL,
	PRIMARY KEY(`bucket_started_at`, `component`, `signal`, `operation`, `outcome`, `status_class`, `error_code`, `latency_bucket`, `release_id`)
);
--> statement-breakpoint
CREATE INDEX `operational_metrics_bucket_idx` ON `operational_metrics` (`bucket_started_at`);--> statement-breakpoint
CREATE INDEX `operational_metrics_signal_idx` ON `operational_metrics` (`signal`,`bucket_started_at`);