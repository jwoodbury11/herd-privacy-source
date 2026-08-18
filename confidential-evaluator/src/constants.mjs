export const PROTOCOL_VERSION = 1;
export const POLICY_DESCRIPTOR_CAPABILITY =
  "policy_descriptor_evaluator_measurement_v1";
export const CIPHER_SUITE = "P256_HKDF_SHA256_AES256_GCM";
export const DEFAULT_PORT = 8080;
export const DEFAULT_CONFIG_FILE = "/app/config/deployment.json";
export const DEFAULT_ATTESTATION_SOCKET =
  "/run/container_launcher/teeserver.sock";
export const GOOGLE_ATTESTATION_ISSUER =
  "https://confidentialcomputing.googleapis.com";
export const GOOGLE_STS_AUDIENCE = "https://sts.googleapis.com";
export const GOOGLE_STS_ENDPOINT = "https://sts.googleapis.com/v1/token";
export const GOOGLE_KMS_ENDPOINT = "https://cloudkms.googleapis.com/v1";
export const GOOGLE_FIRESTORE_ENDPOINT = "https://firestore.googleapis.com/v1";
export const MAXIMUM_EVALUATION_BYTES = 256 * 1024;
export const MAXIMUM_CANONICAL_PAYLOAD_BYTES = 64 * 1024;
export const MAXIMUM_ATTESTATION_BYTES = 1024;

export const KEY_BINDING_DOMAIN =
  "HERD-CONFIDENTIAL-EVALUATOR-KEY-BINDING-V1";
export const EVALUATION_RESULT_DOMAIN =
  "HERD-EVALUATION-RESULT-SIGNATURE-V1";
export const POLICY_SIGNATURE_DOMAIN =
  "HERD-POLICY-DESCRIPTOR-SIGNATURE-V1";
export const TRANSPARENCY_RECEIPT_DOMAIN =
  "HERD-TRANSPARENCY-RECEIPT-SIGNATURE-V1";
export const TRANSPARENCY_LOG_HEAD_DOMAIN =
  "HERD-TRANSPARENCY-LOG-HEAD-SIGNATURE-V1";
export const TRANSPARENCY_RECONCILIATION_DOMAIN =
  "HERD-TRANSPARENCY-RECONCILIATION-SIGNATURE-V1";
export const TRANSPARENCY_LOG_ENTRY_HASH_DOMAIN =
  "HERD-TRANSPARENCY-LOG-ENTRY-HASH-V1";
export const RESPONSE_AUTHORIZATION_DOMAIN =
  "HERD-RESPONSE-AUTHORIZATION-V1";
export const TRANSPARENCY_LOG_ID = "herd-response-log-v1";

export const IDENTIFIER_PATTERN = /^[A-Za-z0-9._-]{1,120}$/u;
export const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
export const IMAGE_DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
export const KMS_KEY_RESOURCE_PATTERN =
  /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[a-z0-9-]{1,63}\/keyRings\/[A-Za-z0-9_-]{1,63}\/cryptoKeys\/[A-Za-z0-9_-]{1,63}$/u;
export const WIP_PROVIDER_RESOURCE_PATTERN =
  /^projects\/[0-9]{6,20}\/locations\/global\/workloadIdentityPools\/[a-z][a-z0-9-]{3,31}\/providers\/[a-z][a-z0-9-]{3,31}$/u;
export const GOOGLE_PROJECT_ID_PATTERN =
  /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/u;
export const FIRESTORE_DATABASE_ID_PATTERN =
  /^(?:\(default\)|[a-z][a-z0-9-]{2,61}[a-z0-9])$/u;
export const FIRESTORE_COLLECTION_ID_PATTERN =
  /^[a-z][a-z0-9_-]{2,62}$/u;

export const PRIVATE_KEY_ENVIRONMENT_NAMES = Object.freeze([
  "HERD_EVALUATOR_PRIVATE_KEY_JWK",
  "HERD_EVALUATOR_PRIVATE_KEY_PEM",
  "HERD_RESULT_SIGNING_PRIVATE_KEY_JWK",
  "HERD_POLICY_SIGNING_PRIVATE_KEY_JWK",
  "HERD_TRANSPARENCY_SIGNING_PRIVATE_KEY_JWK",
  "HERD_EVALUATOR_TOKEN",
]);
