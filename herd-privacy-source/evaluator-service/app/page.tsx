import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Herd confidential evaluator",
  description:
    "A sealed, machine-to-machine evaluation boundary for Herd event responses.",
};

export default function Home() {
  return (
    <main>
      <section aria-labelledby="service-title">
        <p className="eyebrow">Herd infrastructure</p>
        <h1 id="service-title">Confidential evaluator</h1>
        <p>
          This isolated service resolves encrypted event responses after their
          RSVP deadline. Its evaluation endpoint is authenticated and does not
          expose response details.
        </p>
        <dl>
          <div>
            <dt>Protocol</dt>
            <dd>Herd private responses v1</dd>
          </div>
          <div>
            <dt>Disclosure</dt>
            <dd>Confirmation result only</dd>
          </div>
        </dl>
      </section>
    </main>
  );
}
