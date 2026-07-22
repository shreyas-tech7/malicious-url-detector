type ScoreScaleProps = {
  /** Probability in [0, 1]. */
  score: number;
  /** Decision boundary, in [0, 1]. */
  threshold: number;
  /** Inclusive [low, high] range reported as uncertain. */
  band: [number, number];
  /** Tailwind background class for the filled portion. */
  fillClass: string;
};

const pct = (n: number) => `${(n * 100).toFixed(1)}%`;

/**
 * A fixed 0–1 scale rather than a bare progress bar. A probability only means
 * something against the boundary it will be compared to, so the threshold and
 * the uncertain band are drawn on the same track as the score.
 */
export function ScoreScale({
  score,
  threshold,
  band,
  fillClass,
}: ScoreScaleProps) {
  const [low, high] = band;

  return (
    <div>
      <div
        role="meter"
        aria-label="Maliciousness score"
        aria-valuenow={Number(score.toFixed(3))}
        aria-valuemin={0}
        aria-valuemax={1}
        aria-valuetext={`Score ${score.toFixed(3)} of 1. Decision threshold ${threshold}. Uncertain band ${low} to ${high}.`}
        className="relative h-2 w-full overflow-hidden rounded-full bg-surface-2 ring-1 ring-inset ring-line"
      >
        {/* Band first, so the fill and the threshold tick read on top of it. */}
        <div
          className="absolute inset-y-0 bg-slate-600/35"
          style={{ left: pct(low), width: pct(high - low) }}
        />
        <div
          className={`absolute inset-y-0 left-0 origin-left animate-sweep-x rounded-full ${fillClass}`}
          style={{ width: pct(score) }}
        />
        {/*
         * The track clips its overflow, so a tick sitting at exactly 100%
         * would be scrolled out of existence. Pulling it back by its own
         * width at the right edge keeps a threshold of 1 visible.
         */}
        <div
          className="absolute inset-y-0 w-px bg-slate-200/70"
          style={{
            left: pct(threshold),
            transform: threshold >= 1 ? "translateX(-100%)" : undefined,
          }}
        />
      </div>

      <div className="mt-2 flex items-baseline justify-between font-mono text-[0.625rem] text-fg-faint">
        <span>0.0</span>
        <span>1.0</span>
      </div>

      <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-[0.6875rem] text-fg-faint">
        <span className="inline-flex items-center gap-1.5">
          <span
            aria-hidden="true"
            className="h-2 w-3 rounded-sm bg-slate-600/35 ring-1 ring-inset ring-line"
          />
          Uncertain{" "}
          <span className="font-mono tnum">
            {low}–{high}
          </span>
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span aria-hidden="true" className="h-2.5 w-px bg-slate-200/70" />
          Threshold <span className="font-mono tnum">{threshold}</span>
        </span>
      </div>
    </div>
  );
}
