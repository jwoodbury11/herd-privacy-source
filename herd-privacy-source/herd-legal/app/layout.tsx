import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import "./globals.css";

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#131315",
  colorScheme: "dark",
};

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host = requestHeaders.get("x-forwarded-host") ?? requestHeaders.get("host") ?? "localhost:3001";
  const local = host.startsWith("localhost") || host.startsWith("127.0.0.1");
  const protocol = requestHeaders.get("x-forwarded-proto") ?? (local ? "http" : "https");
  const origin = `${protocol}://${host}`;
  const imageUrl = `${origin}/og.png`;

  return {
    title: "Herd — Legal & Messaging",
    description: "Terms, privacy, and one-time event invitation messaging policies for Herd.",
    icons: {
      icon: [{ url: "/herd-icon.png", type: "image/png" }],
      shortcut: "/herd-icon.png",
      apple: [{ url: "/herd-icon.png", type: "image/png" }],
    },
    openGraph: {
      title: "Herd",
      description: "Private replies. Real plans.",
      type: "website",
      url: origin,
      images: [{ url: imageUrl, width: 1200, height: 630, alt: "Herd — Private replies. Real plans." }],
    },
    twitter: {
      card: "summary_large_image",
      title: "Herd",
      description: "Private replies. Real plans.",
      images: [imageUrl],
    },
  };
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
