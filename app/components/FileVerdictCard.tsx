import type {
  CheckResult,
  FileMetadata,
  HashLookup,
  Severity,
  Suspicion,
} from "../types";
import type { FileDigest } from "../file-digest";

type FileVerdictCardProps = {
  digest: FileDigest;
  result: CheckResult;
};

const SEVERITY_TONE: Record<Severity, string> = {
  high: "border-red-900/60 bg-red-950/30 text-red-300",
  medium: "border-amber-900/60 bg-amber-950/25 text-amber-300",
  low: "border-line-strong bg-surface-2 text-fg-muted",
};

/*
 * `none` is deliberately neutral rather than green. These are static checks
 * over a filename and 64 header bytes; finding nothing means the checks did
 * not fire, which is a much smaller claim than "this file is fine".
 */
const SUSPICION_TONE: Record<Suspicion, { card: string; text: string; label: string }> =
  {
    high: {
      card: "border-red-900/60 bg-red-950/25",
      text: "text-red-300",
      label: "High suspicion",
    },
    medium: {
      card: "border-amber-900/60 bg-amber-950/20",
      text: "text-amber-300",
      label: "Medium suspicion",
    },
    low: {
      card: "border-amber-900/50 bg-amber-950/15",
      text: "text-amber-300/90",
      label: "Low suspicion",
    },
    none: {
      card: "border-line bg-surface-1/50",
      text: "text-fg-strong",
      label: "No static findings",
    },
  };

function HashSection({ lookup }: { lookup: HashLookup }) {
  const hit = lookup.known_malicious;

  const meta = [
    lookup.hash_type ? { term: "Hash type", value: lookup.hash_type } : null,
    { term: "Looked up in", value: lookup.lookup_backend },
    lookup.source ? { term: "Source", value: lookup.source } : null,
    lookup.file_type ? { term: "File type", value: lookup.file_type } : null,
    lookup.signature ? { term: "Signature", value: lookup.signature } : null,
  ].filter((m): m is { term: string; value: string } => m !== null);

  return (
    <article
      className={`rounded-xl border px-5 py-5 shadow-card sm:px-6 ${
        hit ? "border-red-900/60 bg-red-950/25" : "border-line bg-surface-1/50"
      }`}
    >
      <header className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2
          className={`text-sm font-semibold ${hit ? "text-red-300" : "text-fg-strong"}`}
        >
          {hit ? "Known malicious" : "No signature match"}
        </h2>
        <p className="text-xs text-fg-muted">
          {hit
            ? "This digest is in the malicious-hash table."
            : "This digest is not in the table."}
        </p>
      </header>

      {lookup.error && (
        <p className="mt-3 text-xs leading-relaxed text-amber-200">
          {lookup.error}
        </p>
      )}

      {/*
       * The caveat for a miss, rendered as prominently as the result itself. A
       * lookup returning "not found" is weak evidence, and a card showing only
       * the headline would read as a clearance.
       *
       * The fallback is load-bearing, not defensive padding. `note` is only
       * attached on the local-snapshot path: `check_file_signature` in
       * ml/signatures.py returns the Supabase verdict before reaching the
       * block that sets it, and HashVerdict has no such field. So on the
       * production path a miss arrives with no caveat at all, and keying the
       * warning off `note` alone would silently drop it exactly where the
       * service is most used.
       */}
      {!hit && (
        <p className="mt-3 border-l-2 border-line-strong pl-3 text-xs leading-relaxed text-fg-muted">
          {lookup.note ??
            "Absence of a match is not evidence the file is safe. The table covers known-bad samples only."}
        </p>
      )}

      {meta.length > 0 && (
        <dl className="mt-5 grid grid-cols-1 gap-px overflow-hidden rounded-lg border border-line bg-line sm:grid-cols-2">
          {meta.map((item) => (
            <div key={item.term} className="bg-surface-1 px-4 py-3">
              <dt className="text-[0.625rem] font-medium uppercase tracking-[0.14em] text-fg-faint">
                {item.term}
              </dt>
              <dd
                className="mt-1 truncate font-mono text-xs text-fg"
                title={item.value}
              >
                {item.value}
              </dd>
            </div>
          ))}
        </dl>
      )}
    </article>
  );
}

function MetadataSection({ metadata }: { metadata: FileMetadata }) {
  const tone = SUSPICION_TONE[metadata.suspicion];

  return (
    <article className={`rounded-xl border px-5 py-5 shadow-card sm:px-6 ${tone.card}`}>
      <header className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 className={`text-sm font-semibold ${tone.text}`}>{tone.label}</h2>
        <p className="text-xs text-fg-muted">Filename, declared type, magic bytes</p>
      </header>

      <dl className="mt-5 grid grid-cols-1 gap-px overflow-hidden rounded-lg border border-line bg-line sm:grid-cols-2">
        <div className="bg-surface-1 px-4 py-3">
          <dt className="text-[0.625rem] font-medium uppercase tracking-[0.14em] text-fg-faint">
            Magic bytes
          </dt>
          {/*
           * Not `truncate`. Magic labels run to ~37 characters, which fills
           * the cell on a 375px screen on its own — appending the executable
           * flag to the same line box clipped it away entirely, losing the
           * single most important word in the section.
           */}
          <dd className="mt-1 flex flex-wrap items-baseline gap-x-2 font-mono text-xs text-fg">
            <span className="break-words">{metadata.magic ?? "unrecognised"}</span>
            {metadata.magic_is_executable && (
              <span className="shrink-0 rounded border border-red-900/60 bg-red-950/40 px-1.5 py-0.5 text-[0.625rem] text-red-300">
                executable
              </span>
            )}
          </dd>
        </div>
        <div className="bg-surface-1 px-4 py-3">
          <dt className="text-[0.625rem] font-medium uppercase tracking-[0.14em] text-fg-faint">
            Extensions
          </dt>
          <dd className="mt-1 truncate font-mono text-xs text-fg">
            {metadata.extensions.length > 0
              ? metadata.extensions.map((e) => `.${e}`).join(" ")
              : "none"}
          </dd>
        </div>
      </dl>

      {metadata.findings.length > 0 && (
        <ul className="mt-4 space-y-2">
          {metadata.findings.map((f) => (
            <li
              key={f.check}
              className={`rounded-lg border px-4 py-3 ${SEVERITY_TONE[f.severity]}`}
            >
              <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                <span className="break-all font-mono text-xs">{f.check}</span>
                <span className="text-[0.625rem] font-medium uppercase tracking-[0.14em]">
                  {f.severity}
                </span>
              </div>
              {/*
               * `break-words`: mime_extension_mismatch interpolates the full
               * expected MIME list, and the .docx entry alone is a 70-character
               * unbroken token that would otherwise widen the page.
               */}
              <p className="mt-1.5 break-words text-xs leading-relaxed text-fg">
                {f.detail}
              </p>
            </li>
          ))}
        </ul>
      )}

      <p className="mt-4 text-xs leading-relaxed text-fg-faint">{metadata.note}</p>
    </article>
  );
}

export function FileVerdictCard({ digest, result }: FileVerdictCardProps) {
  return (
    <div className="space-y-5">
      <p className="break-all font-mono text-xs leading-relaxed text-fg-muted">
        {digest.name}
      </p>

      {result.hash_lookup && <HashSection lookup={result.hash_lookup} />}
      {result.metadata && <MetadataSection metadata={result.metadata} />}

      <p className="max-w-[68ch] text-xs leading-relaxed text-fg-faint">
        {result.disclaimer}
      </p>
    </div>
  );
}
