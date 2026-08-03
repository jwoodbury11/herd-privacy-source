import Link from "next/link";
import Image from "next/image";
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
    <main className="site-frame">
      <div className="page-width">
        <header className="site-header">
          <Link className="brand" href="/" aria-label="Herd legal home">
            <Image src="/herd-icon.png" width={38} height={38} alt="" priority />
            <strong>Herd</strong>
          </Link>
          <Link className="header-contact" href="/sms-invite-consent">SMS invite policy</Link>
        </header>

        <article className="document-shell">
          <div className="document-hero">
            <p className="eyebrow">{eyebrow}</p>
            <h1>{title}</h1>
            <p>{intro}</p>
            <small>{LEGAL_EFFECTIVE_DATE}</small>
          </div>
          <div className="document-body">{children}</div>
        </article>

        <footer className="site-footer">
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
  return <section className="document-section"><h2>{title}</h2>{children}</section>;
}
