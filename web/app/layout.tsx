import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Threat Harvester - Japan Cyber Threat Intelligence",
  description: "Automated Cyber Threat Intelligence monitoring platform specialized for Japan-targeted threats.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen flex flex-col bg-[#070b14] text-slate-100 antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
        {children}
      </body>
    </html>
  );
}
