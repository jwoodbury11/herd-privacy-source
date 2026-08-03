import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Herd confidential evaluator",
  description:
    "An isolated machine-to-machine evaluation boundary for Herd private responses.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
