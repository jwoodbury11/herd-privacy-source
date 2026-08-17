ALTER TABLE `event_resolutions` ADD `result_attestation_protocol_version` integer;--> statement-breakpoint
ALTER TABLE `event_resolutions` ADD `result_attestation_signing_key_id` text;--> statement-breakpoint
ALTER TABLE `event_resolutions` ADD `result_attestation_evaluated_at` text;--> statement-breakpoint
ALTER TABLE `event_resolutions` ADD `result_attestation_canonical_document` text;--> statement-breakpoint
ALTER TABLE `event_resolutions` ADD `result_attestation_signature` text;