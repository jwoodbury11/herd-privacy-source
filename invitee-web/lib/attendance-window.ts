/** Confirmed events keep accepting additions for 24 hours after their start. */
export const CONFIRMED_JOINING_WINDOW_MS = 24 * 60 * 60 * 1000;

type AttendanceWindowEvent = {
  eventDate?: string | null;
  rsvpDeadline: string | null;
  invitationsSent: boolean;
};

export function attendanceClosesAt(event: AttendanceWindowEvent, status?: string): number | null {
  const value = status === "confirmed" && event.eventDate
    ? Date.parse(event.eventDate) + CONFIRMED_JOINING_WINDOW_MS
    : event.rsvpDeadline ? Date.parse(event.rsvpDeadline) : NaN;
  return Number.isFinite(value) ? value : null;
}

export function acceptsAttendance(event: AttendanceWindowEvent, status?: string, now = Date.now()): boolean {
  const closesAt = attendanceClosesAt(event, status);
  return event.invitationsSent && closesAt !== null && now < closesAt;
}
