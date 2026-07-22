import type { ScanResult } from "../types";
import { VERDICT_STYLES } from "../types";
import { ScoreScale } from "./ScoreScale";

type VerdictCardProps = {
  result: ScanResult;
};

type MetaItem = {
  term: string;
  value: string;
};

/**
 * The score leads and the verdict word supports it, not the other way round.
 * This tool reports a probability against a threshold; a headline verdict with
 * the number tucked underneath would imply more certainty than it has.
 */
export function VerdictCard({ result }: VerdictCardProps) {
  const style = VERDICT_STYLES[result.verdict];

  const meta: MetaItem[] = [
    { term: "Registrable domain", value: result.registrable_domain || "—" },
    { term: "Threshold", value: String(result.threshold) },
    { term: "Model", value: result.model_version },
  ];

  return (
    <article
      className={`rounded-xl border ${style.border} ${style.surface} px-5 py-5 shadow-card sm:px-6 sm:py-6`}
    >
      <header className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 className={`text-sm font-semibold ${style.text}`}>{style.label}</h2>
        <p className="text-xs text-fg-muted">{style.gloss}</p>
      </header>

      {/*
       * The scanned URL belongs on the card. The input stays editable after a
       * scan, so without it the field can read one URL while the verdict
       * describes another, with nothing on screen to catch the mismatch.
       * `break-all` because these strings have no spaces to wrap at and can
       * run to 2048 characters.
       */}
      <p className="mt-3 line-clamp-2 break-all font-mono text-xs leading-relaxed text-fg-muted">
        {result.url}
      </p>

      <p className="mt-4 flex items-baseline gap-1.5">
        <span className="tnum font-mono text-5xl font-semibold tracking-display text-fg-strong sm:text-6xl">
          {(result.score * 100).toFixed(1)}
        </span>
        <span className="font-mono text-xl text-fg-muted">%</span>
        <span className="sr-only">probability of being malicious</span>
      </p>

      <div className="mt-5">
        <ScoreScale
          score={result.score}
          threshold={result.threshold}
          band={result.uncertain_band}
          fillClass={style.fill}
        />
      </div>

      {/*
       * No inline note for the uncertain case. The API's own disclaimer
       * already carries the band bounds and the two-thirds error statistic
       * (api/index.py), the scale below plots the band, and the header gloss
       * states the abstention — a fourth restatement on the same screen was
       * the same sentence in four voices.
       *
       * Hairline separators come from a 1px grid gap over a line-coloured
       * background. Three items in a three-column grid — the previous
       * two-column layout left the third orphaned on its own row.
       */}
      <dl className="mt-6 grid grid-cols-1 gap-px overflow-hidden rounded-lg border border-line bg-line sm:grid-cols-3">
        {meta.map((item) => (
          <div key={item.term} className="bg-surface-1 px-4 py-3">
            <dt className="text-[0.625rem] font-medium uppercase tracking-[0.14em] text-fg-faint">
              {item.term}
            </dt>
            <dd className="mt-1 truncate font-mono text-xs text-fg" title={item.value}>
              {item.value}
            </dd>
          </div>
        ))}
      </dl>
    </article>
  );
}
