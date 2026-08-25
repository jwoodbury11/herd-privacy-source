import { getBindings, getD1, type HerdBindings } from "@/db";

import { ensureActiveAccountKeyEpoch } from "./account-keys";
import { getAuthConfig } from "./config";
import { pepperedHash, randomId, randomToken } from "./crypto";
import { ApiError } from "./http";
import { normalizePhoneNumber } from "./phone";
import {
  isTestAccountPhoneNumber,
  testAccountNameForPhoneNumber,
  testAccountPhoneNumberForAlias,
} from "./test-accounts.mjs";
import { checkTwilioVerification, sendTwilioVerification } from "./twilio";
import type { AuthenticatedSession, HerdUser } from "./types";
import { upsertUserForVerifiedChallenge } from "./verified-user-guard.mjs";

export const SESSION_COOKIE_NAME = "herd_session";

function testAccountPhoneNumber(input: unknown): string | null {
  return typeof input === "string" ? testAccountPhoneNumberForAlias(input) : null;
}

type ChallengeRow = {
  id: string;
  phoneNumber: string;
  phoneHash: string;
  delivery: "sms" | "test";
  status: "pending" | "verified" | "expired" | "locked" | "provider_error";
  attemptCount: number;
  maxAttempts: number;
  expiresAt: string;
  resendAt: string;
};

function isoAfter(seconds: number, from = Date.now()): string {
  return new Date(from + seconds * 1_000).toISOString();
}

function requestIp(request: Request): string {
  return (
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-real-ip") ??
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "unknown"
  );
}

function resultChanged(result: { meta?: { changes?: number } }): boolean {
  return (result.meta?.changes ?? 0) > 0;
}

async function consumePhoneRequestBudget(
  db: D1Database,
  phoneHash: string,
  now: number,
  resendSeconds: number,
  hourlyLimit: number,
): Promise<void> {
  const nowIso = new Date(now).toISOString();
  const windowCutoff = new Date(now - 3_600_000).toISOString();
  const resendCutoff = new Date(now - resendSeconds * 1_000).toISOString();
  const result = await db
    .prepare(
      `INSERT INTO auth_phone_rate_limits
        (phone_hash, window_started_at, request_count, last_requested_at)
       VALUES (?, ?, 1, ?)
       ON CONFLICT(phone_hash) DO UPDATE SET
         window_started_at = CASE
           WHEN auth_phone_rate_limits.window_started_at < ?
             THEN excluded.window_started_at
           ELSE auth_phone_rate_limits.window_started_at
         END,
         request_count = CASE
           WHEN auth_phone_rate_limits.window_started_at < ?
             THEN 1
           ELSE auth_phone_rate_limits.request_count + 1
         END,
         last_requested_at = excluded.last_requested_at
       WHERE
         (
           auth_phone_rate_limits.window_started_at < ?
           OR auth_phone_rate_limits.request_count < ?
         )
         AND auth_phone_rate_limits.last_requested_at <= ?`,
    )
    .bind(
      phoneHash,
      nowIso,
      nowIso,
      windowCutoff,
      windowCutoff,
      windowCutoff,
      hourlyLimit,
      resendCutoff,
    )
    .run();

  if (resultChanged(result)) return;

  const rate = await db
    .prepare(
      `SELECT window_started_at AS windowStartedAt,
              request_count AS requestCount,
              last_requested_at AS lastRequestedAt
       FROM auth_phone_rate_limits
       WHERE phone_hash = ?`,
    )
    .bind(phoneHash)
    .first<{ windowStartedAt: string; requestCount: number; lastRequestedAt: string }>();
  const retryAt =
    rate && rate.requestCount >= hourlyLimit
      ? new Date(new Date(rate.windowStartedAt).getTime() + 3_600_000).toISOString()
      : new Date(
          new Date(rate?.lastRequestedAt ?? nowIso).getTime() + resendSeconds * 1_000,
        ).toISOString();
  throw new ApiError(
    429,
    "code_request_throttled",
    "Please wait before requesting another code.",
    { retryAt },
  );
}

async function consumeIpRequestBudget(
  db: D1Database,
  ipHash: string,
  now: number,
  hourlyLimit: number,
): Promise<void> {
  const nowIso = new Date(now).toISOString();
  const windowCutoff = new Date(now - 3_600_000).toISOString();
  const result = await db
    .prepare(
      `INSERT INTO auth_ip_rate_limits
        (ip_hash, window_started_at, request_count, last_requested_at)
       VALUES (?, ?, 1, ?)
       ON CONFLICT(ip_hash) DO UPDATE SET
         window_started_at = CASE
           WHEN auth_ip_rate_limits.window_started_at < ?
             THEN excluded.window_started_at
           ELSE auth_ip_rate_limits.window_started_at
         END,
         request_count = CASE
           WHEN auth_ip_rate_limits.window_started_at < ?
             THEN 1
           ELSE auth_ip_rate_limits.request_count + 1
         END,
         last_requested_at = excluded.last_requested_at
       WHERE
         auth_ip_rate_limits.window_started_at < ?
         OR auth_ip_rate_limits.request_count < ?`,
    )
    .bind(
      ipHash,
      nowIso,
      nowIso,
      windowCutoff,
      windowCutoff,
      windowCutoff,
      hourlyLimit,
    )
    .run();
  if (resultChanged(result)) return;

  const rate = await db
    .prepare(
      `SELECT window_started_at AS windowStartedAt
       FROM auth_ip_rate_limits
       WHERE ip_hash = ?`,
    )
    .bind(ipHash)
    .first<{ windowStartedAt: string }>();
  const retryAt = new Date(
    new Date(rate?.windowStartedAt ?? nowIso).getTime() + 3_600_000,
  ).toISOString();
  throw new ApiError(
    429,
    "ip_request_throttled",
    "Too many verification requests came from this network.",
    { retryAt },
  );
}

export async function requestAuthCode(
  request: Request,
  phoneInput: unknown,
  db?: D1Database,
  bindings?: HerdBindings,
  currentSession?: AuthenticatedSession | null,
) {
  db ??= await getD1();
  bindings ??= await getBindings();
  const config = getAuthConfig(bindings);
  const requestedTestAlias = config.testAccountAccessEnabled
    ? testAccountPhoneNumber(phoneInput)
    : null;
  let testPhoneNumber = requestedTestAlias;
  const normalizedInput = testPhoneNumber ?? normalizePhoneNumber(phoneInput);
  // Test aliases are intentionally the only signed-out bypass. Once a valid
  // test session exists, internal reauthentication flows use the account's
  // canonical 555 number; allow that same authenticated account to refresh its
  // test session instead of sending an impossible Twilio SMS to the fake line.
  if (
    !testPhoneNumber &&
    config.testAccountAccessEnabled &&
    currentSession?.authMode === "test" &&
    currentSession.user.phoneNumber === normalizedInput &&
    isTestAccountPhoneNumber(normalizedInput)
  ) {
    testPhoneNumber = normalizedInput;
  }
  const isAuthenticatedTestReverification =
    requestedTestAlias === null &&
    testPhoneNumber !== null &&
    currentSession?.authMode === "test";
  const phoneNumber = normalizedInput;
  const now = Date.now();
  const createdAt = new Date(now).toISOString();
  const expiresAt = isoAfter(config.challengeTtlSeconds, now);
  const resendAt = isoAfter(config.resendSeconds, now);
  const challengeId = randomId("challenge");
  const phoneHash = await pepperedHash(config.pepper, "phone", phoneNumber);
  const requestIpHash = await pepperedHash(
    config.pepper,
    "request-ip",
    requestIp(request),
  );

  if (!isAuthenticatedTestReverification) {
    await consumeIpRequestBudget(
      db,
      requestIpHash,
      now,
      config.ipRequestsPerHour,
    );
  }

  // An authenticated test session re-verifies its own canonical fake number
  // during private-key recovery. No SMS is sent, so the SMS resend cooldown
  // must not strand the device-switch flow immediately after login or a switch
  // on another device. Keep normal alias logins and real phone numbers on both
  // abuse budgets; only an already authenticated internal session skips them.
  if (!isAuthenticatedTestReverification) {
    await consumePhoneRequestBudget(
      db,
      phoneHash,
      now,
      config.resendSeconds,
      config.phoneRequestsPerHour,
    );
  }

  const usesBypass = config.testAccountAccessEnabled && Boolean(testPhoneNumber);
  if (usesBypass) {
    await db
      .prepare(
        `UPDATE challenges
         SET status = 'expired'
         WHERE phone_hash = ? AND status = 'pending'`,
      )
      .bind(phoneHash)
      .run();
    const user = await upsertVerifiedUser(
      db,
      config.pepper,
      phoneNumber,
      phoneHash,
      createdAt,
    );
    return createUserSession(
      db,
      config.pepper,
      config.sessionTtlSeconds,
      user,
      "test",
      config.testAccountAccessGeneration,
      createdAt,
    );
  }

  if (!config.twilio) {
    throw new ApiError(
      503,
      "sms_unavailable",
      "Phone verification is temporarily unavailable. Try again shortly.",
    );
  }
  const providerSid = await sendTwilioVerification(config.twilio, phoneNumber);

  await db.batch([
    db
      .prepare(
        `UPDATE challenges
         SET status = 'expired'
         WHERE phone_hash = ? AND status = 'pending'`,
      )
      .bind(phoneHash),
    db
      .prepare(
        `INSERT INTO challenges
          (id, phone_number, phone_hash, code_hash, provider_sid, delivery, status,
           request_ip_hash, attempt_count, max_attempts, created_at, expires_at, resend_at)
         VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, 0, ?, ?, ?, ?)`,
      )
      .bind(
        challengeId,
        phoneNumber,
        phoneHash,
        null,
        providerSid,
        "sms",
        requestIpHash,
        config.maxCodeAttempts,
        createdAt,
        expiresAt,
        resendAt,
      ),
  ]);

  return {
    challengeId,
    phoneNumber,
    expiresAt,
    resendAt,
    delivery: "sms" as const,
  };
}

async function loadChallenge(db: D1Database, challengeId: string): Promise<ChallengeRow | null> {
  return db
    .prepare(
      `SELECT id,
              phone_number AS phoneNumber,
              phone_hash AS phoneHash,
              delivery,
              status,
              attempt_count AS attemptCount,
              max_attempts AS maxAttempts,
              expires_at AS expiresAt,
              resend_at AS resendAt
       FROM challenges
       WHERE id = ?`,
    )
    .bind(challengeId)
    .first<ChallengeRow>();
}

function challengeStateError(challenge: ChallengeRow | null, nowIso: string): ApiError {
  if (!challenge) {
    return new ApiError(400, "invalid_challenge", "The verification challenge is invalid.");
  }
  if (challenge.expiresAt <= nowIso || challenge.status === "expired") {
    return new ApiError(
      410,
      "challenge_expired",
      "The verification code expired. Request a new code.",
    );
  }
  if (challenge.status === "locked" || challenge.attemptCount >= challenge.maxAttempts) {
    return new ApiError(
      429,
      "challenge_locked",
      "Too many incorrect attempts. Request a new code.",
    );
  }
  return new ApiError(
    409,
    "challenge_unavailable",
    "This verification challenge can no longer be used.",
  );
}

async function upsertVerifiedUser(
  db: D1Database,
  pepper: string,
  phoneNumber: string,
  phoneHash: string,
  nowIso: string,
  challengeGuard?: { challengeId: string; verifiedAt: string },
): Promise<HerdUser> {
  const suggestedProfile = await db
    .prepare(
      `SELECT display_name AS displayName
       FROM invitees
       WHERE phone_hash = ?
       ORDER BY created_at ASC
       LIMIT 1`,
    )
    .bind(phoneHash)
    .first<{ displayName: string }>();
  const userId = randomId("user");
  const testAccountName = testAccountNameForPhoneNumber(phoneNumber);
  const suggestedName = testAccountName ?? suggestedProfile?.displayName ?? "";
  let user: HerdUser | null;
  if (challengeGuard) {
    user = (await upsertUserForVerifiedChallenge(db, {
      ...challengeGuard,
      phoneNumber,
      phoneHash,
      userId,
      suggestedName,
      nowIso,
    })) as HerdUser | null;
    if (!user) {
      throw new ApiError(
        409,
        "challenge_unavailable",
        "This verification challenge can no longer be used.",
      );
    }
  } else {
    await db
      .prepare(
        `INSERT INTO users
          (id, phone_number, phone_hash, name, address, created_at, updated_at)
         VALUES (?, ?, ?, ?, '', ?, ?)
         ON CONFLICT(phone_number) DO UPDATE SET
           phone_hash = excluded.phone_hash,
           name = CASE WHEN ? = 1 THEN excluded.name ELSE users.name END,
           updated_at = excluded.updated_at`,
      )
      .bind(
        userId,
        phoneNumber,
        phoneHash,
        suggestedName,
        nowIso,
        nowIso,
        testAccountName === null ? 0 : 1,
      )
      .run();

    user = await db
      .prepare(
        `SELECT id, phone_number AS phoneNumber, name, address
         FROM users
         WHERE phone_number = ?`,
      )
      .bind(phoneNumber)
      .first<HerdUser>();
    if (!user) {
      throw new ApiError(
        500,
        "user_creation_failed",
        "The account could not be created.",
      );
    }
  }

  await db
    .prepare(
      `UPDATE invitees
       SET user_id = ?, updated_at = ?
       WHERE phone_hash = ?`,
    )
    .bind(user.id, nowIso, await pepperedHash(pepper, "phone", phoneNumber))
    .run();
  return user;
}

async function createUserSession(
  db: D1Database,
  pepper: string,
  sessionTtlSeconds: number,
  user: HerdUser,
  authMode: "twilio" | "test",
  testAccessGeneration: string | null,
  nowIso = new Date().toISOString(),
) {
  const accountKeyEpoch = await ensureActiveAccountKeyEpoch(db, user.id, nowIso);
  const accessToken = randomToken(32);
  const tokenHash = await pepperedHash(pepper, "session-token", accessToken);
  const sessionId = randomId("session");
  const expiresAt = isoAfter(sessionTtlSeconds);
  await db
    .prepare(
      `INSERT INTO sessions
        (id, user_id, token_hash, auth_mode, test_access_generation,
         created_at, expires_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      sessionId,
      user.id,
      tokenHash,
      authMode,
      authMode === "test" ? testAccessGeneration : null,
      nowIso,
      expiresAt,
      nowIso,
    )
    .run();
  return {
    user: {
      ...user,
      accountKeyEpochId: accountKeyEpoch.id,
      accountKeyCommitment: accountKeyEpoch.keyCommitment,
    },
    accountKeyEpochId: accountKeyEpoch.id,
    accountKeyCommitment: accountKeyEpoch.keyCommitment,
    accessToken,
    expiresAt,
  };
}

export async function verifyAuthCode(
  challengeIdInput: unknown,
  codeInput: unknown,
  db?: D1Database,
  bindings?: HerdBindings,
) {
  db ??= await getD1();
  bindings ??= await getBindings();
  const config = getAuthConfig(bindings);
  if (typeof challengeIdInput !== "string" || challengeIdInput.length > 160) {
    throw new ApiError(400, "invalid_challenge", "The verification challenge is invalid.");
  }
  if (typeof codeInput !== "string" || !/^\d{4}$/.test(codeInput.trim())) {
    throw new ApiError(400, "invalid_code", "Enter the verification code.");
  }
  const challengeId = challengeIdInput.trim();
  const code = codeInput.trim();
  const nowIso = new Date().toISOString();
  let challenge = await loadChallenge(db, challengeId);
  if (
    !challenge ||
    challenge.status !== "pending" ||
    challenge.expiresAt <= nowIso ||
    challenge.attemptCount >= challenge.maxAttempts
  ) {
    if (
      challenge &&
      challenge.expiresAt <= nowIso &&
      challenge.status === "pending"
    ) {
      await db
        .prepare("UPDATE challenges SET status = 'expired' WHERE id = ? AND status = 'pending'")
        .bind(challengeId)
        .run();
    }
    throw challengeStateError(challenge, nowIso);
  }

  const attempt = await db
    .prepare(
      `UPDATE challenges
       SET attempt_count = attempt_count + 1
       WHERE id = ?
         AND status = 'pending'
         AND expires_at > ?
         AND attempt_count < max_attempts`,
    )
    .bind(challengeId, nowIso)
    .run();
  if (!resultChanged(attempt)) {
    challenge = await loadChallenge(db, challengeId);
    throw challengeStateError(challenge, nowIso);
  }
  challenge = await loadChallenge(db, challengeId);
  if (!challenge) throw challengeStateError(null, nowIso);

  if (challenge.delivery !== "sms" || !config.twilio) {
    await db
      .prepare(
        `UPDATE challenges
         SET status = 'expired'
         WHERE id = ? AND status = 'pending'`,
      )
      .bind(challengeId)
      .run();
    throw new ApiError(
      410,
      "challenge_expired",
      "The verification code expired. Request a new code.",
    );
  }
  const approved = await checkTwilioVerification(
    config.twilio,
    challenge.phoneNumber,
    code,
  );

  if (!approved) {
    if (challenge.attemptCount >= challenge.maxAttempts) {
      await db
        .prepare(
          `UPDATE challenges
           SET status = 'locked'
           WHERE id = ? AND status = 'pending'`,
        )
        .bind(challengeId)
        .run();
    }
    throw new ApiError(
      challenge.attemptCount >= challenge.maxAttempts ? 429 : 401,
      challenge.attemptCount >= challenge.maxAttempts
        ? "challenge_locked"
        : "incorrect_code",
      challenge.attemptCount >= challenge.maxAttempts
        ? "Too many incorrect attempts. Request a new code."
        : "That verification code is incorrect.",
      {
        attemptsRemaining: Math.max(
          0,
          challenge.maxAttempts - challenge.attemptCount,
        ),
      },
    );
  }

  const verified = await db
    .prepare(
      `UPDATE challenges
       SET status = 'verified', verified_at = ?
       WHERE id = ? AND status = 'pending'`,
    )
    .bind(nowIso, challengeId)
    .run();
  if (!resultChanged(verified)) {
    throw new ApiError(
      409,
      "challenge_unavailable",
      "This verification challenge can no longer be used.",
    );
  }

  const user = await upsertVerifiedUser(
    db,
    config.pepper,
    challenge.phoneNumber,
    challenge.phoneHash,
    nowIso,
    { challengeId, verifiedAt: nowIso },
  );
  return createUserSession(
    db,
    config.pepper,
    config.sessionTtlSeconds,
    user,
    "twilio",
    null,
    nowIso,
  );
}

function bearerOrCookieToken(request: Request): string | null {
  const authorization = request.headers.get("authorization");
  const bearer = authorization?.match(/^Bearer\s+([A-Za-z0-9_-]{20,})$/i);
  if (bearer) return bearer[1];

  const cookieHeader = request.headers.get("cookie") ?? "";
  for (const part of cookieHeader.split(";")) {
    const [name, ...valueParts] = part.trim().split("=");
    if (name === SESSION_COOKIE_NAME) return valueParts.join("=") || null;
  }
  return null;
}

export function sessionCookie(token: string, expiresAt: string): string {
  const maxAge = Math.max(
    0,
    Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1_000),
  );
  return [
    `${SESSION_COOKIE_NAME}=${token}`,
    "Path=/",
    `Max-Age=${maxAge}`,
    `Expires=${new Date(expiresAt).toUTCString()}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
  ].join("; ");
}

export function clearSessionCookie(): string {
  return [
    `${SESSION_COOKIE_NAME}=`,
    "Path=/",
    "Max-Age=0",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
  ].join("; ");
}

export async function getAuthenticatedSession(
  request: Request,
  options: { required?: boolean; db?: D1Database; bindings?: HerdBindings } = {},
): Promise<AuthenticatedSession | null> {
  const token = bearerOrCookieToken(request);
  if (!token) {
    if (options.required !== false) {
      throw new ApiError(401, "authentication_required", "Sign in to continue.");
    }
    return null;
  }

  const db = options.db ?? (await getD1());
  const bindings = options.bindings ?? (await getBindings());
  const config = getAuthConfig(bindings);
  const tokenHash = await pepperedHash(config.pepper, "session-token", token);
  const nowIso = new Date().toISOString();
  const session = await db
    .prepare(
      `SELECT
         sessions.id AS sessionId,
         sessions.token_hash AS tokenHash,
         sessions.auth_mode AS authMode,
         sessions.test_access_generation AS testAccessGeneration,
         sessions.created_at AS createdAt,
         sessions.expires_at AS expiresAt,
         account_key_epochs.id AS accountKeyEpochId,
         account_key_epochs.key_commitment AS accountKeyCommitment,
         users.id AS userId,
         users.phone_number AS phoneNumber,
         users.name AS name,
         users.address AS address
       FROM sessions
       JOIN users ON users.id = sessions.user_id
       JOIN account_key_epochs
         ON account_key_epochs.user_id = users.id
        AND account_key_epochs.superseded_at IS NULL
       WHERE sessions.token_hash = ?
         AND sessions.revoked_at IS NULL
         AND sessions.expires_at > ?`,
    )
    .bind(tokenHash, nowIso)
    .first<{
      sessionId: string;
      tokenHash: string;
      authMode: "twilio" | "test";
      testAccessGeneration: string | null;
      createdAt: string;
      expiresAt: string;
      accountKeyEpochId: string;
      accountKeyCommitment: string | null;
      userId: string;
      phoneNumber: string;
      name: string;
      address: string;
    }>();
  const sessionModeIsAllowed = Boolean(
    session &&
      (session.authMode === "twilio" ||
        (session.authMode === "test" &&
          config.testAccountAccessEnabled &&
          session.testAccessGeneration === config.testAccountAccessGeneration &&
          isTestAccountPhoneNumber(session.phoneNumber))),
  );
  if (
    session?.authMode === "test" &&
    session.testAccessGeneration !== config.testAccountAccessGeneration
  ) {
    await db
      .prepare(
        `UPDATE sessions
         SET revoked_at = ?
         WHERE id = ? AND revoked_at IS NULL`,
      )
      .bind(nowIso, session.sessionId)
      .run();
  }
  if (!session || !sessionModeIsAllowed) {
    if (options.required !== false) {
      throw new ApiError(401, "invalid_session", "Your session expired. Sign in again.");
    }
    return null;
  }

  await db
    .prepare("UPDATE sessions SET last_seen_at = ? WHERE id = ?")
    .bind(nowIso, session.sessionId)
    .run();
  return {
    sessionId: session.sessionId,
    tokenHash: session.tokenHash,
    authMode: session.authMode,
    createdAt: session.createdAt,
    expiresAt: session.expiresAt,
    accountKeyEpochId: session.accountKeyEpochId,
    accountKeyCommitment: session.accountKeyCommitment,
    user: {
      id: session.userId,
      phoneNumber: session.phoneNumber,
      name: session.name,
      address: session.address,
      accountKeyEpochId: session.accountKeyEpochId,
      accountKeyCommitment: session.accountKeyCommitment,
    },
  };
}

export async function revokeRequestSession(request: Request): Promise<void> {
  const token = bearerOrCookieToken(request);
  if (!token) return;
  const db = await getD1();
  const config = getAuthConfig(await getBindings());
  const tokenHash = await pepperedHash(config.pepper, "session-token", token);
  await db
    .prepare(
      `UPDATE sessions
       SET revoked_at = ?
       WHERE token_hash = ? AND revoked_at IS NULL`,
    )
    .bind(new Date().toISOString(), tokenHash)
    .run();
}
