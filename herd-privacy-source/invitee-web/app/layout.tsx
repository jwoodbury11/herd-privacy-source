import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import {
  PUBLIC_RUNTIME_CONFIG_KEYS,
  type PublicRuntimeConfig,
} from "@/lib/public-runtime-config";
import "./globals.css";

export const dynamic = "force-dynamic";

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
  themeColor: "#1c1c1f",
  colorScheme: "dark",
};

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const host =
    requestHeaders.get("x-forwarded-host") ??
    requestHeaders.get("host") ??
    "127.0.0.1:3002";
  const isLocal = host.startsWith("localhost") || host.startsWith("127.0.0.1");
  const protocol = requestHeaders.get("x-forwarded-proto") ?? (isLocal ? "http" : "https");
  const origin = `${protocol}://${host}`;
  const imageUrl = `${origin}/og.png`;

  return {
    title: "Herd — private event replies",
    description:
      "A private, low-pressure way to find out whether the group is really in.",
    manifest: "/site.webmanifest",
    icons: {
      icon: [
        { url: "/icons/herd-32.png", sizes: "32x32", type: "image/png" },
        { url: "/icons/herd-192.png", sizes: "192x192", type: "image/png" },
      ],
      shortcut: "/icons/herd-32.png",
      apple: [
        { url: "/icons/herd-180.png", sizes: "180x180", type: "image/png" },
      ],
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

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const publicRuntimeConfig = Object.fromEntries(
    PUBLIC_RUNTIME_CONFIG_KEYS.flatMap((key) => {
      const value = process.env[key];
      return typeof value === "string" && value.length > 0 ? [[key, value]] : [];
    }),
  ) as PublicRuntimeConfig;
  const serializedConfig = JSON.stringify(publicRuntimeConfig).replaceAll("<", "\\u003c");

  return (
    <html lang="en">
      <body>
        <script
          dangerouslySetInnerHTML={{
            __html: `window.__HERD_PUBLIC_RUNTIME_CONFIG__=${serializedConfig};`,
          }}
        />
        {children}
      </body>
    </html>
  );
}
