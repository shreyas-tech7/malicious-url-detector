'use client';

import { useState } from 'react';
import { ExampleChips } from './components/ExampleChips';
import { FeatureContributions } from './components/FeatureContributions';
import { ScanForm } from './components/ScanForm';
import { VerdictCard } from './components/VerdictCard';
import { EXAMPLES, isScanResult, type ScanResult } from './types';

export default function Home() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function scan(target: string) {
    const value = target.trim();
    if (!value) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: value }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data?.error ?? `Request failed (${res.status})`);
      } else if (isScanResult(data)) {
        setResult(data);
      } else {
        // A 200 carrying a body we cannot render is a scanner fault, not a
        // verdict. Better to say so than to throw somewhere down the tree.
        setError('The scanner returned a response this page cannot read.');
      }
    } catch {
      setError('Could not reach the scanner.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="mx-auto min-h-screen max-w-3xl px-6 py-14 sm:py-20">
      <header>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-3">
          <h1 className="text-3xl font-semibold tracking-display text-fg-strong sm:text-4xl">
            Malicious URL Detector
          </h1>
          {/*
           * The strongest thing this page can tell a first-time visitor is what
           * it does *not* do with their input, so that claim gets its own
           * element instead of being buried mid-sentence.
           */}
          <span className="inline-flex items-center gap-1.5 rounded-full border border-line-strong bg-surface-1 px-2.5 py-1 text-[0.6875rem] font-medium text-fg-muted shadow-card">
            <span
              aria-hidden="true"
              className="h-1.5 w-1.5 rounded-full bg-emerald-400"
            />
            Never fetches the link
          </span>
        </div>

        <p className="mt-4 max-w-[62ch] text-sm leading-relaxed text-fg-muted">
          A gradient-boosted classifier over URL-derived features. It scores the
          URL <strong className="font-medium text-fg-strong">string only</strong>
          {' '}&mdash; the submitted link is never fetched, opened, or rendered.
        </p>
      </header>

      <div className="mt-8">
        <ScanForm
          value={url}
          onChange={setUrl}
          onSubmit={() => scan(url)}
          loading={loading}
        />
      </div>

      <ExampleChips
        examples={EXAMPLES}
        disabled={loading}
        onPick={(next) => {
          setUrl(next);
          scan(next);
        }}
      />

      {/*
       * `role="alert"` is an assertive live region in its own right, so it sits
       * outside the polite one below — nesting them makes several screen
       * readers announce the same error twice.
       */}
      {error && (
        <div
          role="alert"
          className="mt-8 animate-rise-in rounded-xl border border-amber-900/60 bg-amber-950/25 px-5 py-4 text-sm text-amber-200 shadow-card"
        >
          {error}
        </div>
      )}

      {/*
       * Results replaced the previous content with no announcement, so a screen
       * reader user got silence when a scan finished. The container is always
       * mounted; only its contents change.
       */}
      <div aria-live="polite">
        {result && (
          <section
            className="mt-8 animate-rise-in space-y-5"
            aria-label="Scan result"
          >
            <VerdictCard result={result} />

            {result.top_features?.length > 0 && (
              <FeatureContributions features={result.top_features} />
            )}

            <p className="max-w-[68ch] text-xs leading-relaxed text-fg-faint">
              {result.disclaimer}
            </p>
          </section>
        )}
      </div>

      <footer className="mt-20 border-t border-line pt-6">
        <p className="max-w-[68ch] text-xs leading-relaxed text-fg-faint">
          Portfolio demonstration of a full ML pipeline: data acquisition,
          leakage-aware evaluation, and serverless deployment. Not a substitute
          for a real security product. See{' '}
          <code className="font-mono text-fg-muted">
            ml/reports/EVALUATION.md
          </code>{' '}
          for measured performance and an honest limitations section.
        </p>
      </footer>
    </main>
  );
}
