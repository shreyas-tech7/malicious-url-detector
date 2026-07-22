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
