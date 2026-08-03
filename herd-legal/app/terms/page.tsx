import type { Metadata } from "next";
import { TermsDocument, termsMetadata } from "../../../legal-content";
import { LegalPage, LegalSection } from "../legal-page";

export const metadata: Metadata = termsMetadata;

export default function TermsPage() {
  return <TermsDocument Page={LegalPage} Section={LegalSection} />;
}
