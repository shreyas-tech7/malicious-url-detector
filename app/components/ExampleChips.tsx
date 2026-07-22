import type { Example } from "../types";

type ExampleChipsProps = {
  examples: Example[];
  onPick: (url: string) => void;
  disabled: boolean;
};

/**
 * Each sample is labelled with what it exercises. Previously these rendered as
 * bare truncated URLs, which told you nothing about why you would click one —
 * and truncated twice, via both a `slice(0, 52)` and a `truncate` class.
 */
export function ExampleChips({
  examples,
  onPick,
  disabled,
}: ExampleChipsProps) {
  return (
    <section className="mt-6" aria-labelledby="examples-heading">
      <h2
        id="examples-heading"
        className="text-[0.6875rem] font-medium uppercase tracking-[0.14em] text-fg-faint"
      >
        Try a sample
      </h2>

      {/*
       * `min-w-0` on the grid item and the flex container below: without it
       * they keep their automatic minimum size, the nowrap mono URL cannot
       * shrink, `truncate` never engages, and the card overflows the viewport
       * at 375px.
       */}
      <ul className="mt-3 grid gap-2 sm:grid-cols-2">
        {examples.map((ex) => (
          <li key={ex.url} className="min-w-0">
            <button
              type="button"
              onClick={() => onPick(ex.url)}
              disabled={disabled}
              className="group flex w-full min-w-0 cursor-pointer flex-col items-stretch gap-1 rounded-lg border border-line bg-surface-1/60 px-3.5 py-3 text-left transition duration-200 hover:border-line-strong hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-300 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <span className="flex min-w-0 items-baseline justify-between gap-3">
                <span className="text-xs font-medium text-fg-muted transition-colors duration-200 group-hover:text-fg-strong">
                  {ex.label}
                </span>
                <span
                  aria-hidden="true"
                  className="shrink-0 text-fg-faint opacity-0 transition-opacity duration-200 group-hover:opacity-100"
                >
                  <svg
                    className="h-3 w-3"
                    viewBox="0 0 12 12"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <path d="M2.5 9.5 9.5 2.5M4 2.5h5.5V8" />
                  </svg>
                </span>
              </span>

              <span className="min-w-0 truncate font-mono text-[0.6875rem] text-fg-faint">
                {ex.url}
              </span>

              <span className="text-[0.6875rem] leading-relaxed text-fg-faint">
                {ex.note}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
