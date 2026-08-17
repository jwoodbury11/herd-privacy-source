import Link from "next/link";
import Image from "next/image";

const documents = [
  {
    href: "/terms",
    eyebrow: "Using Herd",
    title: "Terms of Service",
    copy: "The simple rules for hosts, invitees, and one-time event invitation texts.",
  },
  {
    href: "/privacy",
    eyebrow: "Your information",
    title: "Privacy Policy",
    copy: "What Herd needs to deliver an invitation—and what it never does with that information.",
  },
  {
    href: "/sms-invite-consent",
    eyebrow: "Messaging transparency",
    title: "One-time SMS invite policy",
    copy: "The exact host confirmation and safeguards behind a Herd invitation text.",
  },
];

export default function Home() {
  return (
    <main className="site-frame">
      <div className="page-width">
        <header className="site-header">
          <Link className="brand" href="/" aria-label="Herd legal home">
            <Image src="/herd-icon.png" width={38} height={38} alt="" priority />
            <strong>Herd</strong>
          </Link>
          <a className="header-contact" href="mailto:jwoodbury11@gmail.com">Contact</a>
        </header>

        <section className="home-hero">
          <p className="eyebrow">Legal &amp; messaging</p>
          <h1>Clear rules for one-time Herd invitations.</h1>
          <p>
            Herd helps people make plans without public pressure. This site explains the small amount of information and
            messaging needed to deliver a private event invitation.
          </p>
        </section>

        <section className="document-grid" aria-label="Herd policies">
          {documents.map((document, index) => (
            <Link className="document-card" href={document.href} key={document.href}>
              <span className="document-number" aria-hidden="true">0{index + 1}</span>
              <div>
                <p>{document.eyebrow}</p>
                <h2>{document.title}</h2>
                <span>{document.copy}</span>
              </div>
              <span className="card-arrow" aria-hidden="true">↗</span>
            </Link>
          ))}
        </section>

        <section className="one-time-callout">
          <div className="status-dot" aria-hidden="true" />
          <div>
            <strong>One invitation. No automated reminders.</strong>
            <p>Every recipient is selected by a host they know, and every message supports STOP and HELP.</p>
          </div>
        </section>

        <SiteFooter />
      </div>
    </main>
  );
}

function SiteFooter() {
  return (
    <footer className="site-footer">
      <span>Herd · Private replies. Real plans.</span>
      <nav aria-label="Legal links">
        <Link href="/terms">Terms</Link>
        <Link href="/privacy">Privacy</Link>
        <Link href="/sms-invite-consent">SMS policy</Link>
      </nav>
    </footer>
  );
}
