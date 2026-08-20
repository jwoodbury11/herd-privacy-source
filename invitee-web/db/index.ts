import { drizzle } from "drizzle-orm/d1";
import * as schema from "./schema";

export type HerdBindings = {
  DB?: D1Database;
  HERD_DEPLOYMENT_PROFILE?: string;
  HERD_AUTH_PEPPER?: string;
  HERD_BALLOT_PSEUDONYM_KEY?: string;
  HERD_TEST_ACCOUNT_ACCESS_ENABLED?: string;
  HERD_TEST_ACCOUNT_ACCESS_GENERATION?: string;
  HERD_CHALLENGE_TTL_SECONDS?: string;
  HERD_RESEND_SECONDS?: string;
  HERD_MAX_CODE_ATTEMPTS?: string;
  HERD_PHONE_REQUESTS_PER_HOUR?: string;
  HERD_IP_REQUESTS_PER_HOUR?: string;
  HERD_SESSION_TTL_SECONDS?: string;
  HERD_EVALUATOR_KEY_ID?: string;
  HERD_EVALUATOR_PUBLIC_KEY?: string;
  HERD_EVALUATOR_MEASUREMENT?: string;
  HERD_ARTIFACT_RELEASE_ID?: string;
  HERD_RELEASE_POINTER_JSON?: string;
  HERD_RELEASE_POINTER_URL?: string;
  HERD_RELEASE_ID?: string;
  HERD_EVALUATOR_KEY_EPOCH_SHA256?: string;
  HERD_EVALUATOR_EPOCH_DRAIN_MINIMUM_SECONDS?: string;
  HERD_EVALUATOR_URL?: string;
  HERD_EVALUATOR_TOKEN?: string;
  HERD_EVALUATOR_SITES_BYPASS_TOKEN?: string;
  HERD_EVALUATOR_TRANSPORT?: string;
  HERD_EVALUATOR_RESULT_SIGNING_KEY_ID?: string;
  HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY?: string;
  HERD_EVALUATOR_POLICY_SIGNING_KEY_ID?: string;
  HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY?: string;
  HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID?: string;
  HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY?: string;
  HERD_ATTESTATION_URL?: string;
  HERD_ATTESTATION_AUDIENCE?: string;
  HERD_ATTESTATION_MAX_AGE_SECONDS?: string;
  HERD_ATTESTATION_PROJECT_ID?: string;
  HERD_ATTESTATION_SERVICE_ACCOUNT?: string;
  HERD_ATTESTATION_IMAGE_DIGEST?: string;
  HERD_ATTESTATION_IMAGE_DIGESTS?: string;
  HERD_ATTESTATION_ROOT_FINGERPRINT?: string;
  HERD_ATTESTATION_ROOT_CERTIFICATE?: string;
  HERD_SCHEDULER_TOKEN?: string;
  HERD_OBSERVABILITY_TOKEN?: string;
  HERD_OPERATOR_TOKEN?: string;
  HERD_DATA_RESET_TOKEN?: string;
  HERD_MONITOR_ALERT_HMAC_SECRET?: string;
  HERD_PUBLIC_APP_URL?: string;
  HERD_IOS_APP_ID?: string;
  TWILIO_API_KEY_SID?: string;
  TWILIO_API_KEY_SECRET?: string;
  TWILIO_VERIFY_SERVICE_SID?: string;
  TWILIO_ACCOUNT_SID?: string;
  TWILIO_MESSAGING_SERVICE_SID?: string;
};

let cachedBindings: HerdBindings | null = null;
let cachedD1: D1Database | null = null;

export async function getBindings(): Promise<HerdBindings> {
  if (cachedBindings) return cachedBindings;
  const runtime = await import("cloudflare:workers");
  cachedBindings = runtime.env as unknown as HerdBindings;
  cachedD1 = cachedBindings.DB ?? null;
  return cachedBindings;
}

export async function getD1(): Promise<D1Database> {
  const binding = (await getBindings()).DB;
  if (!binding) {
    throw new Error(
      "Cloudflare D1 binding `DB` is unavailable. Configure the `DB` binding before using the Herd API.",
    );
  }
  cachedD1 = binding;
  return binding;
}

export function getDb() {
  if (!cachedD1) {
    throw new Error(
      "The D1 runtime has not been initialized. Call and await getD1() before getDb().",
    );
  }
  return drizzle(cachedD1, { schema });
}
