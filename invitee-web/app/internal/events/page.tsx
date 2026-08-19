import type { Metadata } from "next";

import EventViewer from "./EventViewer";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Herd event viewer",
  robots: { index: false, follow: false, noarchive: true },
  referrer: "no-referrer",
};

export default function InternalEventsPage() {
  return <EventViewer />;
}
