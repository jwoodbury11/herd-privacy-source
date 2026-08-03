import type { Metadata } from "next";
import { PrivacyDocument, privacyMetadata } from "../../../legal-content";
import { LegalPage, LegalSection } from "../legal-page";

export const metadata: Metadata = privacyMetadata;

export default function PrivacyPage() {
  return (
    <PrivacyDocument
      Page={LegalPage}
      Section={LegalSection}
      requiredClauseClassName="legal-required-clause"
    />
  );
}
