import { getBindings, getD1 } from "@/db";
import { jsonResponse, withApiErrors } from "@/lib/backend/http";
import { requireOperatorAuthorization } from "@/lib/backend/operator-auth";

export const dynamic = "force-dynamic";

const PAGE_SIZE = 40;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

type EventRow = {
  id: string;
  title: string;
  eventDescription: string;
  eventDate: string | null;
  endDate: string | null;
  hostName: string;
  locationName: string;
  locationAddress: string;
  minimumParticipants: number;
  allowsAttendeesToAddGuests: number;
  rsvpDeadline: string | null;
  invitationsSent: number;
  createdAt: string;
  updatedAt: string;
  resolutionStatus: string | null;
  attendingMemberIds: string | null;
  resolvedAt: string | null;
  participantCount: number;
  hostConditionGroupCount: number;
  hostConditionOptionCount: number;
  ballotCount: number;
  legacyResponseCount: number;
  deliverySentCount: number;
  deliveryFailedCount: number;
  deliveryPendingCount: number;
};

function encodeCursor(row: EventRow): string {
  return btoa(`${row.createdAt}\0${row.id}`)
    .replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

function decodeCursor(value: string | null): { createdAt: string; id: string } | null {
  if (!value || value.length > 200 || !/^[A-Za-z0-9_-]+$/u.test(value)) return null;
  try {
    const padded = value.replace(/-/gu, "+").replace(/_/gu, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=");
    const [createdAt, id, ...extra] = atob(padded).split("\0");
    if (extra.length > 0 || Number.isNaN(Date.parse(createdAt)) || !UUID_PATTERN.test(id)) return null;
    return { createdAt, id };
  } catch {
    return null;
  }
}

function escapeLike(value: string): string {
  return value.replace(/[\\%_]/gu, (match) => `\\${match}`);
}

function attendingCount(value: string | null): number | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.length : null;
  } catch {
    return null;
  }
}

export async function GET(request: Request) {
  return withApiErrors(async () => {
    const bindings = await getBindings();
    await requireOperatorAuthorization(request, bindings);

    const url = new URL(request.url);
    const query = (url.searchParams.get("q") ?? "").trim().slice(0, 100);
    const cursor = decodeCursor(url.searchParams.get("cursor"));
    const search = `%${escapeLike(query)}%`;
    const db = await getD1();
    const rows = await db.prepare(
      `SELECT e.id, e.title, e.event_description AS eventDescription,
              e.event_date AS eventDate, e.end_date AS endDate,
              e.host_name AS hostName, e.location_name AS locationName,
              e.location_address AS locationAddress,
              e.minimum_participants AS minimumParticipants,
              e.allows_attendees_to_add_guests AS allowsAttendeesToAddGuests,
              e.rsvp_deadline AS rsvpDeadline,
              e.invitations_sent AS invitationsSent,
              e.created_at AS createdAt, e.updated_at AS updatedAt,
              r.status AS resolutionStatus,
              r.attending_member_ids AS attendingMemberIds,
              r.resolved_at AS resolvedAt,
              (SELECT COUNT(*) + 1 FROM invitees i WHERE i.event_id = e.id) AS participantCount,
              (SELECT COUNT(*) FROM groups g WHERE g.event_id = e.id) AS hostConditionGroupCount,
              (SELECT COUNT(*)
                 FROM group_members gm
                 JOIN groups g ON g.id = gm.group_id
                WHERE g.event_id = e.id) AS hostConditionOptionCount,
              (SELECT COUNT(DISTINCT b.ballot_id) FROM ballot_revisions b WHERE b.event_id = e.id) AS ballotCount,
              (SELECT COUNT(*) FROM response_envelopes x WHERE x.event_id = e.id) AS legacyResponseCount,
              (SELECT COUNT(*) FROM invitation_deliveries d WHERE d.event_id = e.id AND d.status = 'sent') AS deliverySentCount,
              (SELECT COUNT(*) FROM invitation_deliveries d WHERE d.event_id = e.id AND d.status IN ('failed', 'unknown')) AS deliveryFailedCount,
              (SELECT COUNT(*) FROM invitation_deliveries d WHERE d.event_id = e.id AND d.status = 'dispatching') AS deliveryPendingCount
       FROM events e
       LEFT JOIN event_resolutions r ON r.event_id = e.id
       WHERE (? = '' OR e.title LIKE ? ESCAPE '\\' OR e.host_name LIKE ? ESCAPE '\\'
              OR e.location_name LIKE ? ESCAPE '\\' OR e.location_address LIKE ? ESCAPE '\\'
              OR e.id = ?)
         AND (? IS NULL OR e.created_at < ? OR (e.created_at = ? AND e.id < ?))
       ORDER BY e.created_at DESC, e.id DESC
       LIMIT ?`,
    ).bind(
      query, search, search, search, search, query.toLowerCase(),
      cursor?.createdAt ?? null,
      cursor?.createdAt ?? null,
      cursor?.createdAt ?? null,
      cursor?.id ?? null,
      PAGE_SIZE + 1,
    ).all<EventRow>();

    const hasMore = rows.results.length > PAGE_SIZE;
    const page = rows.results.slice(0, PAGE_SIZE);
    return jsonResponse({
      releaseId: bindings.HERD_ARTIFACT_RELEASE_ID ?? "unknown",
      events: page.map(({ attendingMemberIds, ...row }) => ({
        ...row,
        allowsAttendeesToAddGuests: Boolean(row.allowsAttendeesToAddGuests),
        invitationsSent: Boolean(row.invitationsSent),
        attendingCount: attendingCount(attendingMemberIds),
      })),
      nextCursor: hasMore && page.length > 0 ? encodeCursor(page.at(-1)!) : null,
    }, {
      headers: {
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Robots-Tag": "noindex, nofollow, noarchive",
      },
    });
  });
}
