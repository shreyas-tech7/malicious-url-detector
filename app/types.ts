/**
 * Shape of the /scan response.
 *
 * This mirrors what the Python inference function returns. `lib/inference.ts`
 * is a validating passthrough and does not model the response body, so this
 * is the only declaration of it — keep it in step with
 * `api/` when the feature set or verdict bands change.
 */

export type Verdict = "malicious" | "uncertain" | "benign";

export type Contribution = {
  /** Feature name as emitted by the model, e.g. `url_entropy`. */
  feature: string;
  /** The feature's value for this URL. */
  value: number;
  /**
   * Change in log-odds when this feature is replaced by its training median.
   * Positive pushes toward malicious.
   */
  contribution: number;
};

export type ScanResult = {
  url: string;
  verdict: Verdict;
  binary_verdict: Exclude<Verdict, "uncertain">;
  /** Probability in [0, 1]. */
  score: number;
  /** Decision boundary for `binary_verdict`, in [0, 1]. */
  threshold: number;
  /** Inclusive [low, high] score range reported as `uncertain`. */
  uncertain_band: [number, number];
  model_version: string;
  registrable_domain: string;
  top_features: Contribution[];
  disclaimer: string;
};

/**
 * Per-verdict presentation. `uncertain` is amber rather than red or green on
 * purpose: the point is that the model declined to call it, and either
 * confident colour would overstate what it knows.
 */
export type VerdictStyle = {
  label: string;
  /** Short gloss shown beside the label. */
  gloss: string;
  border: string;
  surface: string;
  text: string;
  fill: string;
};

const VERDICTS: readonly Verdict[] = ["malicious", "uncertain", "benign"];

const isContribution = (v: unknown): v is Contribution => {
  const c = v as Contribution;
  return (
    !!c &&
    typeof c.feature === "string" &&
    Number.isFinite(c.value) &&
    Number.isFinite(c.contribution)
  );
};

/**
 * Narrows a parsed `/scan` body before it reaches the render tree.
 *
 * The response was previously cast straight to `ScanResult`, which made every
 * field a promise the compiler could not keep: a 200 that omitted
 * `uncertain_band` threw inside the verdict card, past the point where the
 * fetch's own catch could help, and the page went blank. Failing here turns
 * that into the ordinary error state instead.
 */
export function isScanResult(value: unknown): value is ScanResult {
  const r = value as ScanResult;
  return (
    !!r &&
    typeof r === "object" &&
    typeof r.url === "string" &&
    VERDICTS.includes(r.verdict) &&
    Number.isFinite(r.score) &&
    Number.isFinite(r.threshold) &&
    Array.isArray(r.uncertain_band) &&
    r.uncertain_band.length === 2 &&
    r.uncertain_band.every(Number.isFinite) &&
    typeof r.model_version === "string" &&
    typeof r.registrable_domain === "string" &&
    typeof r.disclaimer === "string" &&
    Array.isArray(r.top_features) &&
    r.top_features.every(isContribution)
  );
}

export const VERDICT_STYLES: Record<Verdict, VerdictStyle> = {
  malicious: {
    label: "Likely malicious",
    gloss: "Scored above the decision threshold.",
    border: "border-red-900/60",
    surface: "bg-red-950/25",
    text: "text-red-300",
    fill: "bg-red-500/80",
  },
  uncertain: {
    label: "Uncertain",
    gloss: "Inside the band where the model declines to call it.",
    border: "border-amber-900/60",
    surface: "bg-amber-950/20",
    text: "text-amber-300",
    fill: "bg-amber-500/80",
  },
  benign: {
    label: "Likely benign",
    gloss: "Scored below the decision threshold.",
    border: "border-emerald-900/60",
    surface: "bg-emerald-950/20",
    text: "text-emerald-300",
    fill: "bg-emerald-500/80",
  },
};

/**
 * Sample URLs, each chosen to exercise a different part of the feature space.
 * The labels matter: an unlabelled row of truncated URLs gives no signal about
 * what clicking one is meant to demonstrate.
 */
export type Example = {
  label: string;
  note: string;
  url: string;
};

export const EXAMPLES: Example[] = [
  {
    label: "Reputable host",
    note: "Common domain, ordinary path",
    url: "https://en.wikipedia.org/wiki/Shannon_entropy",
  },
  {
    label: "Brand lookalike",
    note: "Trusted name as a subdomain of another registrar",
    url: "http://paypal.com.security-check.ru/login/verify/account.php",
  },
  {
    label: "Raw IP host",
    note: "No domain, non-standard port, binary payload path",
    url: "http://192.168.14.99:8080/bins/mirai.arm7",
  },
  {
    label: "Deep benign path",
    note: "Tests that path depth alone does not carry the score",
    url: "https://github.com/python/cpython/blob/main/Lib/json/decoder.py",
  },
];

/* ------------------------------------------------------------------ */
/* File-signature check — POST /check                                  */
/* ------------------------------------------------------------------ */

/**
 * Result of looking a digest up against the malicious-hash table.
 *
 * `known_malicious: false` is a miss, not a clearance. The local snapshot is a
 * truncated subset of the URLhaus payload feed, and the API says so in `note`
 * — the UI must not upgrade that into a clean bill of health.
 */
export type HashLookup = {
  known_malicious: boolean;
  hash_type: string | null;
  source?: string | null;
  file_type?: string | null;
  signature?: string | null;
  lookup_backend: string;
  note?: string;
  error?: string;
};

export type Severity = "high" | "medium" | "low";

export type MetadataFinding = {
  check: string;
  severity: Severity;
  detail: string;
};

export type Suspicion = "none" | Severity;

/** Static checks over filename, declared MIME and the header sample. */
export type FileMetadata = {
  suspicion: Suspicion;
  extensions: string[];
  magic: string | null;
  magic_is_executable: boolean;
  findings: MetadataFinding[];
  note: string;
};

/**
 * Both members are conditional: the API returns `hash_lookup` only when given
 * a hash, and `metadata` only when given a filename, MIME type or header.
 */
export type CheckResult = {
  hash_lookup?: HashLookup;
  metadata?: FileMetadata;
  disclaimer: string;
};

const SUSPICIONS: readonly Suspicion[] = ["none", "low", "medium", "high"];
const SEVERITIES: readonly Severity[] = ["low", "medium", "high"];

/** Optional in the response, but must be a string when present. */
const optionalString = (v: unknown): boolean =>
  v === undefined || v === null || typeof v === "string";

/*
 * Every field these guards skip is a field the card will render unchecked.
 * `metadata.note` carries the "neither executed nor unpacked" scope
 * disclaimer, and `findings[].check` is used as a React key — so the rule is
 * that anything reaching the DOM gets validated, not just the fields that
 * would throw if absent.
 */
const isHashLookup = (v: unknown): v is HashLookup => {
  const h = v as HashLookup;
  return (
    !!h &&
    typeof h === "object" &&
    typeof h.known_malicious === "boolean" &&
    typeof h.lookup_backend === "string" &&
    optionalString(h.hash_type) &&
    optionalString(h.source) &&
    optionalString(h.file_type) &&
    optionalString(h.signature) &&
    optionalString(h.note) &&
    optionalString(h.error)
  );
};

const isFileMetadata = (v: unknown): v is FileMetadata => {
  const m = v as FileMetadata;
  return (
    !!m &&
    typeof m === "object" &&
    SUSPICIONS.includes(m.suspicion) &&
    typeof m.magic_is_executable === "boolean" &&
    typeof m.note === "string" &&
    optionalString(m.magic) &&
    Array.isArray(m.extensions) &&
    m.extensions.every((e) => typeof e === "string") &&
    Array.isArray(m.findings) &&
    m.findings.every(
      (f) =>
        !!f &&
        typeof f === "object" &&
        typeof f.check === "string" &&
        typeof f.detail === "string" &&
        SEVERITIES.includes(f.severity),
    )
  );
};

/** Narrows a parsed `/check` body before it reaches the render tree. */
export function isCheckResult(value: unknown): value is CheckResult {
  const r = value as CheckResult;
  if (!r || typeof r !== "object" || typeof r.disclaimer !== "string") {
    return false;
  }
  if (r.hash_lookup !== undefined && !isHashLookup(r.hash_lookup)) return false;
  if (r.metadata !== undefined && !isFileMetadata(r.metadata)) return false;
  // A body carrying neither section has nothing to render.
  return r.hash_lookup !== undefined || r.metadata !== undefined;
}
