// Replaces the built-in 404 page, whose inline styles are blocked by the Content Security Policy.
export default function NotFound() {
  return (
    <main className="flex flex-1 flex-col items-center justify-center gap-2 p-8 text-center">
      <h1 className="text-3xl font-semibold text-cyan-300">404</h1>
      <p className="text-sm text-slate-400">This page could not be found.</p>
    </main>
  );
}
