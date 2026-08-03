UPDATE `sessions`
SET `revoked_at` = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE `revoked_at` IS NULL;
