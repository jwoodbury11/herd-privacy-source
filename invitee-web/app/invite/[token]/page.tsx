import type { Metadata } from "next";
import { headers } from "next/headers";

import { getBindings, getD1 } from "@/db";
import { getInvitationLinkPreview } from "@/lib/backend/invites";

import { HerdApp } from "../../page";

type InvitationPageProps = {
  params: Promise<{ token: string }>;
};

const EVENT_IMAGE_IDS = new Set([
  "poker", "tennis", "board-games", "house-drinks", "restaurant",
  "cocktail-bar", "club-dancing", "movie-night", "park-picnic",
  "travel-airport", "camping", "fishing", "birthday-party", "jacuzzi",
  "skiing", "other",
]);

async function trustedOrigin(): Promise<string> {
  const configured = process.env.HERD_PUBLIC_APP_URL?.trim();
  if (configured) return new URL(configured).origin;
  const requestHeaders = await headers();
  const host = requestHeaders.get("host") ?? "127.0.0.1:3002";
  const local = host.startsWith("localhost") || host.startsWith("127.0.0.1");
  return `${local ? "http" : "https"}://${host}`;
}

export async function generateMetadata({ params }: InvitationPageProps): Promise<Metadata> {
  const { token } = await params;
  const origin = await trustedOrigin();
  const fallbackTitle = "A Herd invitation";
  let preview: Awaited<ReturnType<typeof getInvitationLinkPreview>> = null;
  try {
    preview = await getInvitationLinkPreview(
      await getD1(),
      await getBindings(),
      token,
    );
  } catch {
    // A crawler should still receive safe generic metadata if the link is
    // expired, malformed, or the database is temporarily unavailable.
  }
  const title = preview?.title.trim() || fallbackTitle;
  const imageID = preview && EVENT_IMAGE_IDS.has(preview.eventImageID)
    ? preview.eventImageID
    : "poker";
  const description = "Reply privately. Plan honestly.";
  const invitationURL = `${origin}/invite/${encodeURIComponent(token)}`;
  const imageURL = `${origin}/link-previews/${imageID}.png`;
  const appClipBundleID = process.env.HERD_IOS_APP_CLIP_BUNDLE_ID?.trim();

  return {
    title,
    description,
    alternates: { canonical: invitationURL },
    openGraph: {
      title,
      description,
      siteName: "Herd",
      type: "website",
      url: invitationURL,
      images: [{
        url: imageURL,
        width: 1200,
        height: 630,
        alt: `${title} invitation artwork`,
      }],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [imageURL],
    },
    other: appClipBundleID
      ? { "apple-itunes-app": `app-clip-bundle-id=${appClipBundleID}` }
      : undefined,
  };
}

export default function InvitationPage() {
  return <HerdApp />;
}
