import type { Metadata } from "next";
import {
  SmsConsentDocument,
  smsConsentMetadata,
} from "../../../legal-content";
import { LegalPage, LegalSection } from "../legal-page";

export const metadata: Metadata = smsConsentMetadata;

export default function SMSInviteConsentPage() {
  return (
    <SmsConsentDocument
      Page={LegalPage}
      Section={LegalSection}
      classNames={{
        statusCard: "review-status",
        proofFrame: "consent-proof",
        proofTopbar: "proof-topbar",
        proofBody: "proof-body",
        proofIcon: "proof-icon",
        proofSummary: "proof-summary",
        proofAttestation: "proof-attestation",
        proofSend: "proof-send",
        proofDisclosure: "proof-disclosure",
        proofLinks: "proof-links",
        messageFormat: "message-format",
        programDetails: "program-details",
      }}
    />
  );
}
