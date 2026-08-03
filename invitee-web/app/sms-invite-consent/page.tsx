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
        statusCard: "legal-status-card",
        proofFrame: "consent-proof-frame",
        proofTopbar: "consent-proof-topbar",
        proofBody: "consent-proof-body",
        proofIcon: "consent-proof-icon",
        proofSummary: "consent-proof-summary",
        proofAttestation: "consent-proof-attestation",
        proofSend: "consent-proof-send",
        proofDisclosure: "consent-proof-disclosure",
        proofLinks: "consent-proof-links",
        messageFormat: "legal-message-format",
        programDetails: "legal-program-details",
      }}
    />
  );
}
