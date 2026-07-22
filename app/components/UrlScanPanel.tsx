import { useRef, useState } from "react";
import { ExampleChips } from "./ExampleChips";
import { FeatureContributions } from "./FeatureContributions";
import { ScanForm } from "./ScanForm";
import { VerdictCard } from "./VerdictCard";
import { postJson } from "../post-json";
import { EXAMPLES, isScanResult, type ScanResult } from "../types";

/**
 * Owns everything about scoring a URL. Lifting this out of the page means the
 * two scan modes share no state and cannot leave each other's results on
 * screen, and the page itself is left as composition.
 */
export function UrlScanPanel() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const seq = useRef(0);

  async function scan(target: string) {
    const value = target.trim();
    if (!value) return;

    const id = ++seq.current;
    setLoading(true);
    setError(null);
    setResult(null);

    const outcome = await postJson("/scan", { url: value }, isScanResult);

    // The submit button and the example chips are both disabled while a scan
    // is in flight, so this is unreachable today. It is here so that loosening
    // either guard cannot resurrect a last-resolver-wins bug.
    if (id !== seq.current) return;

    if (outcome.ok) setResult(outcome.data);
    else setError(outcome.message);
    setLoading(false);
  }

  return (
    <>
      <ScanForm
        value={url}
        onChange={setUrl}
        onSubmit={() => scan(url)}
        loading={loading}
      />

      <ExampleChips
        examples={EXAMPLES}
        disabled={loading}
        onPick={(next) => {
          setUrl(next);
          scan(next);
        }}
      />

      {error && (
        <div
          role="alert"
          className="mt-8 animate-rise-in rounded-xl border border-amber-900/60 bg-amber-950/25 px-5 py-4 text-sm text-amber-200 shadow-card"
        >
          {error}
        </div>
      )}

      <div aria-live="polite">
        {result && (
          <section
            className="mt-8 animate-rise-in space-y-5"
            aria-label="URL scan result"
          >
            <VerdictCard result={result} />

            {result.top_features.length > 0 && (
              <FeatureContributions features={result.top_features} />
            )}

            <p className="max-w-[68ch] text-xs leading-relaxed text-fg-faint">
              {result.disclaimer}
            </p>
          </section>
        )}
      </div>
    </>
  );
}
