/**
 * POST JSON and narrow the reply, or come back with a message worth showing.
 *
 * Both panels previously did `await res.json()` before checking `res.ok`. Any
 * non-JSON failure — a platform 502 page, or the 500 Next returns when
 * `resolveInferenceBase` rejects an unknown host — made the parse throw and
 * land in the network catch, so a reachable server that answered was reported
 * as "could not reach the scanner", with the status discarded.
 */
export type PostResult<T> =
  | { ok: true; data: T }
  | { ok: false; message: string };

export async function postJson<T>(
  path: string,
  body: unknown,
  isValid: (value: unknown) => value is T,
): Promise<PostResult<T>> {
  let res: Response;
  try {
    res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    return { ok: false, message: "Could not reach the scanner." };
  }

  // Parsed defensively: a failure response is not guaranteed to be JSON.
  let parsed: unknown = null;
  try {
    parsed = await res.json();
  } catch {
    parsed = null;
  }

  if (!res.ok) {
    const reported = (parsed as { error?: unknown } | null)?.error;
    return {
      ok: false,
      message:
        typeof reported === "string" && reported.trim()
          ? reported
          : `Request failed (${res.status}).`,
    };
  }

  if (!isValid(parsed)) {
    return {
      ok: false,
      message: "The scanner returned a response this page cannot read.",
    };
  }

  return { ok: true, data: parsed };
}
