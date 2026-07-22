import { useRef, useState } from "react";
import { FileDropZone } from "./FileDropZone";
import { FileVerdictCard } from "./FileVerdictCard";
import { DigestError, digestFile, type FileDigest } from "../file-digest";
import { postJson } from "../post-json";
import { isCheckResult, type CheckResult } from "../types";

/**
 * Owns the file-signature path. The file is hashed here, in the browser, and
 * only the digest and a 64-byte header sample are posted — `/check` refuses
 * uploads by design, so there is no version of this that sends the file.
 */
export function FileScanPanel() {
  const [digest, setDigest] = useState<FileDigest | null>(null);
  /*
   * The digest is stored *with* the result rather than read from state at
   * render time. Hashing and checking are both async and both can be
   * superseded, and reading them independently let the card pair one file's
   * name and hash with another file's verdict — the worst failure this screen
   * could have. Held together, they cannot disagree.
   */
  const [checked, setChecked] = useState<{
    digest: FileDigest;
    result: CheckResult;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hashing, setHashing] = useState(false);
  const [loading, setLoading] = useState(false);

  // Monotonic tokens; a later call retires whatever earlier ones are in flight.
  const hashSeq = useRef(0);
  const checkSeq = useRef(0);

  async function hash(file: File) {
    const id = ++hashSeq.current;
    checkSeq.current += 1; // any in-flight check is now for a stale file

    setHashing(true);
    setError(null);
    setChecked(null);
    setDigest(null);

    try {
      const next = await digestFile(file);
      if (id !== hashSeq.current) return;
      setDigest(next);
    } catch (e) {
      if (id !== hashSeq.current) return;
      setError(
        e instanceof DigestError ? e.message : "That file could not be read.",
      );
    } finally {
      if (id === hashSeq.current) setHashing(false);
    }
  }

  async function check() {
    if (!digest) return;
    const target = digest;
    const id = ++checkSeq.current;

    setLoading(true);
    setError(null);
    setChecked(null);

    const outcome = await postJson(
      "/check",
      {
        hash: target.sha256,
        filename: target.name,
        mime_type: target.mimeType || undefined,
        header_b64: target.headerB64 ?? undefined,
      },
      isCheckResult,
    );

    if (id !== checkSeq.current) return;

    if (outcome.ok) setChecked({ digest: target, result: outcome.data });
    else setError(outcome.message);
    setLoading(false);
  }

  const busy = hashing || loading;

  return (
    <>
      <FileDropZone
        digest={digest}
        hashing={hashing}
        disabled={busy}
        onFile={hash}
        onClear={() => {
          hashSeq.current += 1;
          checkSeq.current += 1;
          setDigest(null);
          setChecked(null);
          setError(null);
        }}
      />

      <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2">
        <button
          type="button"
          onClick={check}
          disabled={!digest || busy}
          className="inline-flex shrink-0 cursor-pointer items-center justify-center gap-2 rounded-lg bg-fg-strong px-5 py-2.5 text-sm font-medium text-surface-0 transition duration-200 hover:bg-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-300 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-0 active:translate-y-px disabled:cursor-not-allowed disabled:opacity-40 disabled:active:translate-y-0"
        >
          {loading ? (
            <>
              <svg
                className="motion-only h-3.5 w-3.5 animate-spin"
                viewBox="0 0 16 16"
                fill="none"
                aria-hidden="true"
              >
                <circle
                  cx="8"
                  cy="8"
                  r="6.5"
                  stroke="currentColor"
                  strokeOpacity="0.25"
                  strokeWidth="2"
                />
                <path
                  d="M14.5 8A6.5 6.5 0 0 0 8 1.5"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                />
              </svg>
              Checking
            </>
          ) : (
            "Check signature"
          )}
        </button>

        <p className="text-xs text-fg-faint">
          Sends the digest, filename, declared type and 64 header bytes.
        </p>
      </div>

      {error && (
        <div
          role="alert"
          className="mt-8 animate-rise-in rounded-xl border border-amber-900/60 bg-amber-950/25 px-5 py-4 text-sm text-amber-200 shadow-card"
        >
          {error}
        </div>
      )}

      <div aria-live="polite">
        {checked && (
          <section
            className="mt-8 animate-rise-in"
            aria-label="File signature result"
          >
            <FileVerdictCard digest={checked.digest} result={checked.result} />
          </section>
        )}
      </div>
    </>
  );
}
