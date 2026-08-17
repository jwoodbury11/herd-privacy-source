import Link from "next/link";
import type { ReactNode } from "react";
import { LEGAL_EFFECTIVE_DATE } from "../legal-content";

type LegalPageProps = {
  eyebrow: string;
  title: string;
  intro: string;
  children: ReactNode;
};

export function LegalPage({ eyebrow, title, intro, children }: LegalPageProps) {
  return (
    <main className="legal-site-stage">
      <div className="legal-page-shell">
        <header className="legal-header">
          <Link className="legal-brand" href="/" aria-label="Herd home">
            <span aria-hidden="true">H</span>
            <strong>Herd</strong>
          </Link>
          <Link className="legal-header-link" href="/sms-invite-consent">
            SMS invite policy
          </Link>
        </header>

        <article className="legal-document">
          <div className="legal-hero">
            <p className="legal-eyebrow">{eyebrow}</p>
            <h1>{title}</h1>
            <p>{intro}</p>
            <small>{LEGAL_EFFECTIVE_DATE}</small>
          </div>

          <div className="legal-sections">{children}</div>
        </article>

        <footer className="legal-footer">
          <span>Herd · Private replies. Real plans.</span>
          <nav aria-label="Legal links">
            <Link href="/terms">Terms</Link>
            <Link href="/privacy">Privacy</Link>
            <a href="mailto:jwoodbury11@gmail.com">Contact</a>
          </nav>
        </footer>
      </div>
    </main>
  );
}

export function LegalSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="legal-section">
      <h2>{title}</h2>
      {children}
    </section>
  );
}
