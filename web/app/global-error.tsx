"use client";

import "./globals.css";

// Replaces the built-in error page, whose inline styles are blocked by the Content Security Policy.
export default function GlobalError({ reset }: { error: Error; reset: () => void }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen flex flex-col items-center justify-center gap-4 bg-[#070b14] p-8 text-center text-slate-100">
        <h1 className="text-xl font-semibold text-cyan-300">Something went wrong</h1>
        <button type="button" onClick={reset} className="rounded border border-slate-700 px-4 py-2 text-sm hover:bg-slate-800">
          Try again
        </button>
      </body>
    </html>
  );
}
