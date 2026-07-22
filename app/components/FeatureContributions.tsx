import type { Contribution } from "../types";

type FeatureContributionsProps = {
  features: Contribution[];
};

const formatValue = (n: number) =>
  Number.isInteger(n) ? String(n) : n.toFixed(2);

/**
 * Contributions are signed, so they get a diverging axis rather than a column
 * of numbers: length is magnitude, side is direction. Bars are scaled against
 * the largest absolute contribution in the set, which makes the ranking
 * legible without implying an absolute unit the log-odds delta does not have.
 */
export function FeatureContributions({ features }: FeatureContributionsProps) {
  const maxAbs =
    features.reduce((max, f) => Math.max(max, Math.abs(f.contribution)), 0) || 1;

  return (
    <section className="rounded-xl border border-line bg-surface-1/50 px-5 py-5 shadow-card sm:px-6">
      <h2 className="text-sm font-medium text-fg-strong">
        What drove this score
      </h2>
      <p className="mt-1 max-w-[62ch] text-xs leading-relaxed text-fg-muted">
        Change in log-odds when each feature is replaced by its training median.
      </p>

      <div className="mt-4 flex items-center gap-3">
        <div className="flex flex-1 items-center justify-between font-medium text-[0.625rem] uppercase tracking-[0.12em] text-fg-faint">
          <span>&larr; toward benign</span>
          <span>toward malicious &rarr;</span>
        </div>
        <span className="w-14 shrink-0" aria-hidden="true" />
      </div>

      <ul className="mt-2.5 space-y-3">
        {features.map((f, i) => {
          /*
           * Three states, not two. A contribution of exactly 0 moved the score
           * nowhere; sorting it into the negative branch would paint it green
           * and file it under "toward benign", which is a claim the number
           * does not make.
           */
          const direction = Math.sign(f.contribution) as -1 | 0 | 1;
          const width = (Math.abs(f.contribution) / maxAbs) * 50;
          const delay = `${i * 45}ms`;

          const barSide =
            direction === 1
              ? "left-1/2 origin-left bg-red-500/70"
              : "right-1/2 origin-right bg-emerald-500/70";
          const valueTone =
            direction === 1
              ? "text-red-300"
              : direction === -1
                ? "text-emerald-300"
                : "text-fg-muted";

          return (
            <li key={f.feature}>
              <div className="flex items-baseline justify-between gap-3">
                <span className="truncate font-mono text-xs text-fg">
                  {f.feature}
                </span>
                <span className="tnum shrink-0 font-mono text-[0.625rem] text-fg-faint">
                  = {formatValue(f.value)}
                </span>
              </div>

              <div className="mt-1.5 flex items-center gap-3">
                <div className="relative h-1.5 flex-1 rounded-sm bg-surface-2 ring-1 ring-inset ring-line">
                  <div
                    aria-hidden="true"
                    className="absolute inset-y-0 left-1/2 w-px -translate-x-1/2 bg-line-strong"
                  />
                  {direction !== 0 && (
                    <div
                      className={`absolute inset-y-0 animate-sweep-x rounded-sm ${barSide}`}
                      style={{ width: `${width}%`, animationDelay: delay }}
                    />
                  )}
                </div>

                <span
                  className={`tnum w-14 shrink-0 text-right font-mono text-[0.6875rem] ${valueTone}`}
                >
                  {direction === 1 ? "+" : ""}
                  {f.contribution.toFixed(3)}
                </span>
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
