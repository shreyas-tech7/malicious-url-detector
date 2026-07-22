type ScanFormProps = {
  value: string;
  onChange: (next: string) => void;
  onSubmit: () => void;
  loading: boolean;
};

function Spinner() {
  return (
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
  );
}

/**
 * The input and its submit share one bordered shell so focus lights the whole
 * control rather than a single edge. The previous version set `outline-none`
 * and signalled focus only by shifting the border one step of grey, which is
 * not a visible focus indicator.
 */
export function ScanForm({ value, onChange, onSubmit, loading }: ScanFormProps) {
  const empty = !value.trim();

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit();
      }}
      aria-busy={loading}
    >
      <label htmlFor="url-input" className="sr-only">
        URL to scan
      </label>

      <div className="flex flex-col gap-2 rounded-xl border border-line-strong bg-surface-1 p-2 shadow-card transition-shadow duration-200 focus-within:border-slate-500 focus-within:shadow-raised focus-within:ring-2 focus-within:ring-slate-400/25 sm:flex-row sm:items-center">
        <input
          id="url-input"
          type="text"
          inputMode="url"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="https://example.com/some/path"
          spellCheck={false}
          autoComplete="off"
          autoCapitalize="off"
          className="min-w-0 flex-1 bg-transparent px-3 py-2 font-mono text-sm text-fg-strong outline-none placeholder:font-sans placeholder:text-fg-faint"
        />
        <button
          type="submit"
          disabled={loading || empty}
          className="inline-flex shrink-0 cursor-pointer items-center justify-center gap-2 rounded-lg bg-fg-strong px-5 py-2.5 text-sm font-medium text-surface-0 transition duration-200 hover:bg-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-300 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-1 active:translate-y-px disabled:cursor-not-allowed disabled:opacity-40 disabled:active:translate-y-0 sm:min-w-[8.5rem]"
        >
          {loading ? (
            <>
              <Spinner />
              Scanning
            </>
          ) : (
            "Scan URL"
          )}
        </button>
      </div>
    </form>
  );
}
