import type { PrivateResponse } from "./fixed-point.mjs";

export type PrivateResponseEnvelope = {
  protocolVersion: 1;
  cipherSuite: "P256_HKDF_SHA256_AES256_GCM";
  envelopeId: string;
  eventId: string;
  inviteeId: string;
  policyHash: string;
  revision: number;
  accountKeyEpochId: string;
  evaluatorKeyId: string;
  payloadCiphertext: string;
  userKeyWrap: string;
  evaluatorKeyWrap: string;
  responseSigningPublicKey: string;
  responseSignature: string;
};

export type OpenedPrivateResponse = PrivateResponse & {
  protocolVersion: 1;
  eventId: string;
  policyHash: string;
  envelopeId: string;
  accountKeyEpochId: string;
  revision: number;
  nonce: string;
};

export function openPrivateResponseEnvelope(input: {
  envelope: PrivateResponseEnvelope;
  evaluatorPrivateKey: CryptoKey;
  expectedEvaluatorKeyId: string;
  allowedInviteeIds: string[];
  hostMinimumParticipants: number;
}): Promise<OpenedPrivateResponse>;

export const privateResponseEnvelopeConstants: Readonly<{
  version: 1;
  cipherSuite: "P256_HKDF_SHA256_AES256_GCM";
  paddedPlaintextBytes: 4096;
  payloadFrameBytes: 4124;
  userWrapBytes: 60;
  evaluatorWrapBytes: 157;
}>;
