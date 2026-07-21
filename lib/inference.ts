/**
 * Shared helpers for the Next.js API routes that front the Python inference
 * function.
 *
 * Routing note: the Python Function owns `/api/*` on this deployment, so these
 * gateway routes deliberately live at `/scan` and `/check` instead. Defining a
 * Next route under `app/api/` would collide with it.
 */

/** Hard cap mirrored from the Python side (api/index.py: MAX_URL_LENGTH). */
export const MAX_URL_LENGTH = 2048;

/**
 * Resolve the base URL of the Python function.
 *
 * In production both functions are served from the same deployment, so the
 * incoming request's own origin is the correct target - that keeps preview
 * deployments talking to their own backend rather than to production.
 */
export function resolveInferenceBase(request: Request): string {
  const override = process.env.INFERENCE_BASE_URL?.trim();
  if (override) return override.replace(/\/$/, '');

  const origin = new URL(request.url).origin;

  // Locally, `next dev` and the Python function run on different ports.
  if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
    return 'http://127.0.0.1:8000';
  }

  // `request.url` is derived from the Host header, which is client-supplied.
  // If a forged Host ever reached this function, the gateway would issue a
  // server-side request to an attacker-chosen origin - an SSRF primitive, and
  // precisely the class of bug this project's scope section says it avoids.
  //
  // Vercel validates Host against the deployment's aliases, so this is not
  // exploitable on the current host. That makes the platform the control,
  // though, not the code. Pinning to VERCEL_URL (set by the platform, not the
  // request) keeps the guarantee in the application where it belongs.
  const vercelUrl = process.env.VERCEL_URL?.trim();
  if (vercelUrl) {
    return `https://${vercelUrl.replace(/^https?:\/\//, '').replace(/\/$/, '')}`;
  }

  // No platform hint and no override: only same-origin https is acceptable.
  const parsed = new URL(origin);
  if (parsed.protocol !== 'https:') {
    throw new Error('refusing to call a non-https inference backend');
  }
  return origin;
}

export type ValidationError = { error: string; status: number };

/**
 * True if the string contains any C0 control byte or DEL.
 *
 * Written as an explicit char-code scan rather than a regex character class:
 * such a class must be spelled with literal control bytes or escapes, and
 * both corrupt silently when the file is round-tripped through tooling. This
 * version is plain ASCII and cannot be mangled without it being obvious.
 */
function hasControlChars(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

/**
 * Validate a submitted URL before it reaches the model.
 *
 * This duplicates the Python validator on purpose. The gateway is the public
 * contract and must reject hostile input on its own terms rather than assuming
 * the backend will - and the backend must not assume the gateway did either.
 */
export function validateUrl(value: unknown): string | ValidationError {
  if (typeof value !== 'string') {
    return { error: 'url must be a string', status: 422 };
  }
  const url = value.trim();
  if (!url) {
    return { error: 'url must not be empty', status: 422 };
  }
  if (url.length > MAX_URL_LENGTH) {
    return {
      error: `url must be at most ${MAX_URL_LENGTH} characters`,
      status: 422,
    };
  }
  // CR/LF would enable header injection if this value were ever placed into an
  // upstream request line; NUL and friends have no business in a URL.
  if (hasControlChars(url)) {
    return { error: 'url must not contain control characters', status: 422 };
  }

  // Only http/https are scored. `javascript:` and `data:` are rejected rather
  // than classified: the model has no useful opinion about them, and a client
  // rendering one back into the page would be an XSS sink.
  const schemeMatch = url.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      return {
        error: `unsupported scheme '${scheme}' - only http and https are accepted`,
        status: 422,
      };
    }
  }

  return url;
}

/** Forward a request to the Python function, normalising failures. */
export async function callInference(
  base: string,
  path: string,
  payload: unknown,
  timeoutMs = 15000,
): Promise<{ status: number; body: unknown }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`${base}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
      cache: 'no-store',
    });

    const text = await res.text();
    let body: unknown;
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      // Never surface a raw upstream body to the caller: it may contain a
      // stack trace or other internal detail.
      return {
        status: 502,
        body: { error: 'inference backend returned a malformed response' },
      };
    }
    return { status: res.status, body };
  } catch (err) {
    const aborted = err instanceof Error && err.name === 'AbortError';
    return {
      status: aborted ? 504 : 502,
      body: {
        error: aborted
          ? 'inference backend timed out'
          : 'inference backend unreachable',
      },
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Parse a JSON body, tolerating malformed input without throwing. */
export async function readJson(
  request: Request,
): Promise<Record<string, unknown>> {
  try {
    const data = await request.json();
    return data && typeof data === 'object'
      ? (data as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}
