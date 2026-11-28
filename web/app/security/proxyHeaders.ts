// Headers the API proxy sends to the backend. Built from an allowlist, so that client-supplied
// credentials and forwarding headers never reach the internal service.

const FORWARDED_REQUEST_HEADERS = ["accept", "accept-language", "content-type", "last-event-id", "user-agent"];

/**
 * `privileged` must be true only for requests with a verified administrator session; only those
 * carry the internal service token.
 */
export function buildBackendHeaders(
  incoming: Headers,
  { privileged, token }: { privileged: boolean; token: string | undefined }
): Headers {
  const headers = new Headers();
  for (const name of FORWARDED_REQUEST_HEADERS) {
    const value = incoming.get(name);
    if (value !== null) headers.set(name, value);
  }
  // The backend uses the scheme to build absolute feed links.
  const proto = incoming.get("x-forwarded-proto");
  if (proto === "https" || proto === "http") headers.set("x-forwarded-proto", proto);

  const secret = token?.trim();
  if (privileged && secret) headers.set("authorization", `Bearer ${secret}`);
  return headers;
}
