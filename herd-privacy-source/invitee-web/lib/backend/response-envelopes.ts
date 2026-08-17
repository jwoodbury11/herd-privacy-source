import {
  bytesToBase64Url,
  canonicalEnvelopeJson,
  normalizePrivateResponseEnvelope,
  type PrivateResponseEnvelopeV1,
  type StoredPrivateResponseEnvelopeV1,
} from "@/lib/privacy/protocol";

export type ResponseEnvelopeRow = {
  id: string;
  eventId: string;
  inviteeId: string;
  policyHash: string;
  protocolVersion: number;
  cipherSuite: string;
  accountKeyEpochId: string;
  evaluatorKeyId: string;
  revision: number;
  payloadCiphertext: string;
  userKeyWrap: string;
  evaluatorKeyWrap: string;
  responseSigningPublicKey: string | null;
  responseSignature: string | null;
  ciphertextHash: string;
  createdAt: string;
  updatedAt: string;
};

export const RESPONSE_ENVELOPE_SELECT = `SELECT
  id,
  event_id AS eventId,
  invitee_id AS inviteeId,
  policy_hash AS policyHash,
  protocol_version AS protocolVersion,
  cipher_suite AS cipherSuite,
  account_key_epoch_id AS accountKeyEpochId,
  evaluator_key_id AS evaluatorKeyId,
  revision,
  payload_ciphertext AS payloadCiphertext,
  user_key_wrap AS userKeyWrap,
  evaluator_key_wrap AS evaluatorKeyWrap,
  response_signing_public_key AS responseSigningPublicKey,
  response_signature AS responseSignature,
  ciphertext_hash AS ciphertextHash,
  created_at AS createdAt,
  updated_at AS updatedAt
FROM response_envelopes`;

export function parseResponseEnvelope(
  row: ResponseEnvelopeRow | null,
): StoredPrivateResponseEnvelopeV1 | null {
  if (!row) return null;
  try {
    const envelope = normalizePrivateResponseEnvelope({
      protocolVersion: row.protocolVersion,
      cipherSuite: row.cipherSuite,
      envelopeId: row.id,
      eventId: row.eventId,
      inviteeId: row.inviteeId,
      policyHash: row.policyHash,
      revision: row.revision,
      accountKeyEpochId: row.accountKeyEpochId,
      evaluatorKeyId: row.evaluatorKeyId,
      payloadCiphertext: row.payloadCiphertext,
      userKeyWrap: row.userKeyWrap,
      evaluatorKeyWrap: row.evaluatorKeyWrap,
      responseSigningPublicKey: row.responseSigningPublicKey,
      responseSignature: row.responseSignature,
    });
    return {
      ...envelope,
      ciphertextHash: row.ciphertextHash,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  } catch {
    return null;
  }
}

export function unstoredResponseEnvelope(
  envelope: StoredPrivateResponseEnvelopeV1,
): PrivateResponseEnvelopeV1 {
  const {
    ciphertextHash: _ciphertextHash,
    createdAt: _createdAt,
    updatedAt: _updatedAt,
    ...storedEnvelope
  } = envelope;
  void _ciphertextHash;
  void _createdAt;
  void _updatedAt;
  return storedEnvelope;
}

export async function responseEnvelopeHash(
  envelope: PrivateResponseEnvelopeV1,
): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalEnvelopeJson(envelope)),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

export async function getLatestValidResponseEnvelope(
  db: D1Database,
  inviteeId: string,
): Promise<StoredPrivateResponseEnvelopeV1 | null> {
  const rows = await db
    .prepare(
      `${RESPONSE_ENVELOPE_SELECT}
       WHERE invitee_id = ?
       ORDER BY revision DESC, created_at DESC
       LIMIT 100`,
    )
    .bind(inviteeId)
    .all<ResponseEnvelopeRow>();
  for (const row of rows.results) {
    const parsed = parseResponseEnvelope(row);
    if (parsed) return parsed;
  }
  return null;
}
