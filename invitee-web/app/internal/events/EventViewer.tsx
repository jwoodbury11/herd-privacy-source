"use client";

import { FormEvent, useCallback, useState } from "react";

import styles from "./event-viewer.module.css";

type EventSummary = {
  id: string;
  title: string;
  eventDescription: string;
  eventDate: string | null;
  hostName: string;
  locationName: string;
  locationAddress: string;
  minimumParticipants: number;
  rsvpDeadline: string | null;
  invitationsSent: boolean;
  createdAt: string;
  resolutionStatus: "pending" | "evaluating" | "confirmed" | "not_confirmed" | null;
  resolvedAt: string | null;
  participantCount: number;
  ballotCount: number;
  legacyResponseCount: number;
  attendingCount: number | null;
  deliverySentCount: number;
  deliveryFailedCount: number;
  deliveryPendingCount: number;
};

type EventResponse = {
  releaseId: string;
  events: EventSummary[];
  nextCursor: string | null;
};

type BallotRevision = {
  ballotId: string;
  revision: number;
  response: "going" | "cant_commit";
  minimumParticipants: number | null;
  requiredGroups: Array<{ id: string; memberIDs: string[] }>;
  source: "user" | "support_correction";
  createdAt: string;
};

type BallotResponse = {
  eventId: string;
  ballots: BallotRevision[];
};

const formatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

function displayDate(value: string | null): string {
  if (!value) return "Not set";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Not set" : formatter.format(date);
}

function statusLabel(event: EventSummary): string {
  if (!event.invitationsSent) return "Draft";
  if (event.resolutionStatus === "confirmed") return "Confirmed";
  if (event.resolutionStatus === "not_confirmed") return "Not confirmed";
  if (event.resolutionStatus === "evaluating") return "Evaluating";
  return "Waiting for replies";
}

export default function EventViewer() {
  const [operatorKey, setOperatorKey] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [query, setQuery] = useState("");
  const [events, setEvents] = useState<EventSummary[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [releaseId, setReleaseId] = useState("");
  const [ballotsByEvent, setBallotsByEvent] = useState<Record<string, BallotRevision[]>>({});
  const [loadingBallotsFor, setLoadingBallotsFor] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const load = useCallback(async (cursor: string | null, append: boolean) => {
    if (operatorKey.trim().length < 32) {
      setError("Enter your admin key.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams();
      if (query.trim()) params.set("q", query.trim());
      if (cursor) params.set("cursor", cursor);
      const response = await fetch(`/api/internal/events?${params}`, {
        cache: "no-store",
        headers: { authorization: `Bearer ${operatorKey.trim()}` },
      });
      if (!response.ok) {
        throw new Error(response.status === 401 ? "That admin key was not accepted." : "Events could not be loaded.");
      }
      const body = await response.json() as EventResponse;
      setEvents((current) => append ? [...current, ...body.events] : body.events);
      setNextCursor(body.nextCursor);
      setReleaseId(body.releaseId);
      setAuthorized(true);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "Events could not be loaded.");
    } finally {
      setLoading(false);
    }
  }, [operatorKey, query]);

  function submit(event: FormEvent) {
    event.preventDefault();
    void load(null, false);
  }

  function signOut() {
    setAuthorized(false);
    setOperatorKey("");
    setQuery("");
    setEvents([]);
    setNextCursor(null);
    setReleaseId("");
    setBallotsByEvent({});
    setError("");
  }

  async function loadBallots(eventId: string) {
    setLoadingBallotsFor(eventId);
    setError("");
    try {
      const response = await fetch(`/api/internal/ballots?eventId=${encodeURIComponent(eventId)}`, {
        cache: "no-store",
        headers: { authorization: `Bearer ${operatorKey.trim()}` },
      });
      if (!response.ok) throw new Error("De-identified replies could not be loaded.");
      const body = await response.json() as BallotResponse;
      const latest = new Map<string, BallotRevision>();
      for (const ballot of body.ballots) latest.set(ballot.ballotId, ballot);
      setBallotsByEvent((current) => ({ ...current, [eventId]: [...latest.values()] }));
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : "De-identified replies could not be loaded.");
    } finally {
      setLoadingBallotsFor("");
    }
  }

  if (!authorized) {
    return (
      <main className={styles.root}>
        <form className={styles.signIn} onSubmit={submit}>
          <div className={styles.mark}>H</div>
          <h1>Herd event viewer</h1>
          <p>Private operations access. Your key stays in this tab.</p>
          <label htmlFor="operator-key">Admin key</label>
          <input
            id="operator-key"
            type="password"
            autoComplete="off"
            value={operatorKey}
            onChange={(event) => setOperatorKey(event.target.value)}
            autoFocus
          />
          {error ? <p className={styles.error} role="alert">{error}</p> : null}
          <button type="submit" disabled={loading}>{loading ? "Opening…" : "Open viewer"}</button>
        </form>
      </main>
    );
  }

  return (
    <main className={styles.root}>
      <div className={styles.viewer}>
        <header className={styles.header}>
          <div>
            <h1>Herd events</h1>
            <p>{events.length} loaded · Release {releaseId}</p>
          </div>
          <button className={styles.secondary} type="button" onClick={signOut}>Lock</button>
        </header>

        <form className={styles.search} onSubmit={submit}>
          <input
            aria-label="Search events"
            placeholder="Search title, host, location, or event ID"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          {query ? <button type="button" className={styles.clear} onClick={() => setQuery("")} aria-label="Clear search">×</button> : null}
          <button type="submit" disabled={loading}>{loading ? "Loading…" : "Search"}</button>
        </form>
        {error ? <p className={styles.error} role="alert">{error}</p> : null}

        <section className={styles.list} aria-live="polite">
          {events.map((event) => (
            <details className={styles.card} key={event.id}>
              <summary>
                <div className={styles.cardTitle}>
                  <span className={styles.status} data-status={event.resolutionStatus ?? (event.invitationsSent ? "pending" : "draft")}>
                    {statusLabel(event)}
                  </span>
                  <h2>{event.title || "Untitled event"}</h2>
                  <p>{displayDate(event.eventDate)} · Hosted by {event.hostName || "Unknown"}</p>
                </div>
                <span className={styles.chevron} aria-hidden="true">⌄</span>
              </summary>
              <div className={styles.metrics}>
                <div><strong>{event.participantCount}</strong><span>invited</span></div>
                <div><strong>{event.minimumParticipants}</strong><span>min attendees</span></div>
                <div><strong>{event.attendingCount ?? "—"}</strong><span>attending</span></div>
                <div><strong>{event.ballotCount}</strong><span>new replies</span></div>
              </div>
              <dl className={styles.details}>
                <div><dt>Location</dt><dd>{event.locationName || event.locationAddress || "Not set"}</dd></div>
                {event.locationName && event.locationAddress ? <div><dt>Address</dt><dd>{event.locationAddress}</dd></div> : null}
                <div><dt>Reply deadline</dt><dd>{displayDate(event.rsvpDeadline)}</dd></div>
                <div><dt>Created</dt><dd>{displayDate(event.createdAt)}</dd></div>
                <div><dt>Delivery</dt><dd>{event.deliverySentCount} sent · {event.deliveryPendingCount} pending · {event.deliveryFailedCount} failed</dd></div>
                {event.legacyResponseCount > 0 ? <div><dt>Compatibility</dt><dd>{event.legacyResponseCount} legacy replies preserved</dd></div> : null}
                <div><dt>Event ID</dt><dd className={styles.mono}>{event.id}</dd></div>
              </dl>
              {event.eventDescription ? <p className={styles.description}>{event.eventDescription}</p> : null}
              <div className={styles.ballots}>
                {ballotsByEvent[event.id] ? (
                  <>
                    <h3>De-identified replies</h3>
                    {ballotsByEvent[event.id].length === 0 ? <p>No replies yet.</p> : (
                      <div className={styles.ballotList}>
                        {ballotsByEvent[event.id].map((ballot, index) => (
                          <article key={ballot.ballotId}>
                            <strong>Ballot {index + 1}: {ballot.response === "going" ? "Going" : "Can’t commit"}</strong>
                            <span>Revision {ballot.revision}{ballot.source === "support_correction" ? " · corrected" : ""}</span>
                            {ballot.response === "going" ? (
                              <p>
                                At least {ballot.minimumParticipants} attendees
                                {ballot.requiredGroups.length === 0 ? " · No attendee conditions" : ""}
                              </p>
                            ) : null}
                            {ballot.requiredGroups.map((group, groupIndex) => (
                              <p key={group.id}>
                                Condition {groupIndex + 1}: any of {group.memberIDs.map((member) => member.slice(0, 8)).join(", ")}
                              </p>
                            ))}
                          </article>
                        ))}
                      </div>
                    )}
                  </>
                ) : (
                  <button
                    type="button"
                    className={styles.secondary}
                    disabled={loadingBallotsFor === event.id}
                    onClick={() => void loadBallots(event.id)}
                  >
                    {loadingBallotsFor === event.id ? "Loading…" : "View de-identified replies"}
                  </button>
                )}
              </div>
            </details>
          ))}
          {!loading && events.length === 0 ? <div className={styles.empty}>No events found.</div> : null}
        </section>

        {nextCursor ? (
          <button className={styles.more} type="button" disabled={loading} onClick={() => void load(nextCursor, true)}>
            {loading ? "Loading…" : "Load more"}
          </button>
        ) : null}
      </div>
    </main>
  );
}
