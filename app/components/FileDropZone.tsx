import { useEffect, useRef, useState, type DragEvent } from "react";
import { formatBytes, type FileDigest } from "../file-digest";

type FileDropZoneProps = {
  digest: FileDigest | null;
  hashing: boolean;
  disabled: boolean;
  onFile: (file: File) => void;
  onClear: () => void;
};

const INPUT_ID = "file-scan-input";
const HINT_ID = "file-scan-hint";

function FileIcon() {
  return (
    <svg
      className="h-5 w-5"
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.4"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M11.5 2.5H6a1.5 1.5 0 0 0-1.5 1.5v12A1.5 1.5 0 0 0 6 17.5h8a1.5 1.5 0 0 0 1.5-1.5V6.5z" />
      <path d="M11.5 2.5v4h4" />
    </svg>
  );
}

/**
 * A real `<input type="file">`, visually hidden rather than `display: none` so
 * it keeps its place in the tab order, driven by `<label for>` rather than by
 * wrapping. Wrapping put the computed digest inside the label, so trying to
 * select the hash to copy it re-opened the file picker instead — and the
 * digest is the one thing on this panel worth copying.
 *
 * The zone holds a fixed minimum height across its three states, so selecting
 * a file does not reflow the panel beneath it.
 */
export function FileDropZone({
  digest,
  hashing,
  disabled,
  onFile,
  onClear,
}: FileDropZoneProps) {
  const [dragging, setDragging] = useState(false);
  /*
   * dragenter/dragleave fire for every descendant the pointer crosses, so a
   * single boolean flickers off as soon as the cursor moves over the inner
   * text. Counting entries against exits tracks the zone as a whole.
   */
  const depth = useRef(0);

  /*
   * A file dropped anywhere outside the zone is otherwise handled by the
   * browser, which navigates the tab to `file:///…` and throws away every
   * piece of state on the page — the typed URL, any result, the digest. A
   * near-miss on a 9.5rem target should not cost the user their session.
   */
  useEffect(() => {
    const swallow = (e: Event) => e.preventDefault();
    document.addEventListener("dragover", swallow);
    document.addEventListener("drop", swallow);
    return () => {
      document.removeEventListener("dragover", swallow);
      document.removeEventListener("drop", swallow);
    };
  }, []);

  const reset = () => {
    depth.current = 0;
    setDragging(false);
  };

  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    reset();
    if (disabled) return;
    const file = e.dataTransfer.files?.[0];
    if (file) onFile(file);
  };

  const state = hashing ? "hashing" : digest ? "ready" : "idle";

  return (
    <div>
      <div
        onDragEnter={(e) => {
          e.preventDefault();
          depth.current += 1;
          if (!disabled) setDragging(true);
        }}
        onDragOver={(e) => e.preventDefault()}
        onDragLeave={(e) => {
          e.preventDefault();
          depth.current -= 1;
          if (depth.current <= 0) reset();
        }}
        onDrop={onDrop}
        className={`flex min-h-[9.5rem] w-full flex-col justify-center rounded-xl border border-dashed px-5 py-5 transition-colors duration-200 focus-within:border-slate-500 focus-within:ring-2 focus-within:ring-slate-300 ${
          dragging
            ? "border-slate-400 bg-surface-2"
            : "border-line-strong bg-surface-1/60"
        } ${disabled ? "opacity-50" : ""}`}
      >
        <input
          id={INPUT_ID}
          type="file"
          className="sr-only"
          disabled={disabled}
          aria-label="Choose a file to hash"
          aria-describedby={HINT_ID}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) onFile(file);
            // Allow re-selecting the same file after a clear.
            e.target.value = "";
          }}
        />

        {state === "idle" && (
          <label
            htmlFor={INPUT_ID}
            className={`flex flex-col items-center gap-2 text-center text-fg-muted ${
              disabled ? "cursor-not-allowed" : "cursor-pointer"
            }`}
          >
            <FileIcon />
            <span className="text-sm">
              Drop a file here, or{" "}
              <span className="font-medium text-fg-strong underline underline-offset-4">
                browse
              </span>
            </span>
          </label>
        )}

        {state === "hashing" && (
          <div className="flex flex-col items-center gap-2 text-center text-fg-muted">
            <svg
              className="motion-only h-5 w-5 animate-spin"
              viewBox="0 0 20 20"
              fill="none"
              aria-hidden="true"
            >
              <circle
                cx="10"
                cy="10"
                r="8"
                stroke="currentColor"
                strokeOpacity="0.25"
                strokeWidth="2"
              />
              <path
                d="M18 10a8 8 0 0 0-8-8"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
              />
            </svg>
            <span className="text-sm">Computing SHA-256…</span>
          </div>
        )}

        {state === "ready" && digest && (
          <div className="flex flex-col gap-3">
            <div className="flex items-baseline justify-between gap-3">
              <span className="min-w-0 truncate text-sm font-medium text-fg-strong">
                {digest.name}
              </span>
              <span className="tnum shrink-0 font-mono text-xs text-fg-muted">
                {formatBytes(digest.size)}
              </span>
            </div>

            {/*
             * Outside any label, so it can be selected and copied. The digest
             * is shown before anything is sent: it is the payload, and seeing
             * it is how the claim that the file stays local becomes checkable
             * rather than something the page merely asserts.
             */}
            <div className="flex flex-col gap-1">
              <span className="text-[0.625rem] font-medium uppercase tracking-[0.14em] text-fg-faint">
                SHA-256
              </span>
              <code className="select-all break-all font-mono text-[0.6875rem] leading-relaxed text-fg">
                {digest.sha256}
              </code>
            </div>

            <span className="text-[0.6875rem] text-fg-faint">
              Declared type{" "}
              <span className="font-mono">{digest.mimeType || "unknown"}</span>
            </span>
          </div>
        )}
      </div>

      {/*
       * Always mounted: as a conditionally rendered node this was a dangling
       * aria-describedby target in two of the three states, and a live region
       * that only exists once it has something to say is one most screen
       * readers never announce.
       */}
      <p
        id={HINT_ID}
        aria-live="polite"
        className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-fg-faint"
      >
        <span>
          {state === "hashing"
            ? "Computing SHA-256 in this tab."
            : "Hashed in this tab. The file itself is never uploaded."}
        </span>

        {state === "ready" && (
          <>
            <label
              htmlFor={INPUT_ID}
              className={`rounded underline underline-offset-4 transition-colors duration-200 hover:text-fg-strong ${
                disabled ? "cursor-not-allowed" : "cursor-pointer"
              }`}
            >
              Choose a different file
            </label>
            <button
              type="button"
              onClick={onClear}
              disabled={disabled}
              className="cursor-pointer rounded underline underline-offset-4 transition-colors duration-200 hover:text-fg-strong focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-300 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Remove file
            </button>
          </>
        )}
      </p>
    </div>
  );
}
