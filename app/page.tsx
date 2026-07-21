'use client';

import { useState } from 'react';

type Contribution = {
  feature: string;
  value: number;
  contribution: number;
};

type ScanResult = {
  url: string;
  verdict: 'malicious' | 'benign';
  score: number;
  threshold: number;
  model_version: string;
  registrable_domain: string;
  top_features: Contribution[];
  disclaimer: string;
};

const EXAMPLES = [
  'https://en.wikipedia.org/wiki/Shannon_entropy',
  'http://paypal.com.security-check.ru/login/verify/account.php',
  'http://192.168.14.99:8080/bins/mirai.arm7',
  'https://github.com/python/cpython/blob/main/Lib/json/decoder.py',
];

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
      } else {
        setResult(data as ScanResult);
      }
    } catch {
      setError('Could not reach the scanner.');
    } finally {
      setLoading(false);
    }
  }

  const malicious = result?.verdict === 'malicious';

  return (
    <main className="mx-auto min-h-screen max-w-3xl px-6 py-12">
      <header className="mb-10">
        <h1 className="text-3xl font-semibold tracking-tight text-slate-100">
          Malicious URL Detector
        </h1>
        <p className="mt-3 text-sm leading-relaxed text-slate-400">
          A gradient-boosted classifier over URL-derived features. It scores the
          URL <strong className="text-slate-200">string only</strong> and never
          fetches, opens, or renders the link you submit.
        </p>
      </header>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          scan(url);
        }}
        className="flex flex-col gap-3 sm:flex-row"
      >
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com/some/path"
          spellCheck={false}
          autoComplete="off"
          className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-4 py-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-slate-500"
        />
        <button
          type="submit"
          disabled={loading || !url.trim()}
          className="rounded-lg bg-slate-100 px-6 py-3 text-sm font-medium text-slate-900 transition hover:bg-white disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? 'Scanning...' : 'Scan URL'}
        </button>
      </form>

      <div className="mt-4 flex flex-wrap gap-2">
        {EXAMPLES.map((ex) => (
          <button
            key={ex}
            type="button"
            onClick={() => {
              setUrl(ex);
              scan(ex);
            }}
            className="max-w-full truncate rounded-md border border-slate-800 bg-slate-900/60 px-3 py-1.5 text-xs text-slate-400 transition hover:border-slate-600 hover:text-slate-200"
          >
            {ex.length > 52 ? `${ex.slice(0, 52)}...` : ex}
          </button>
        ))}
      </div>

      {error && (
        <div className="mt-8 rounded-lg border border-amber-900/60 bg-amber-950/30 px-4 py-3 text-sm text-amber-200">
          {error}
        </div>
      )}

      {result && (
        <section className="mt-8 space-y-5">
          <div
            className={`rounded-xl border px-5 py-5 ${
              malicious
                ? 'border-red-900/70 bg-red-950/30'
                : 'border-emerald-900/70 bg-emerald-950/25'
            }`}
          >
            <div className="flex items-baseline justify-between gap-4">
              <span
                className={`text-xl font-semibold ${
                  malicious ? 'text-red-300' : 'text-emerald-300'
                }`}
              >
                {malicious ? 'Likely malicious' : 'Likely benign'}
              </span>
              <span className="font-mono text-sm text-slate-400">
                {(result.score * 100).toFixed(1)}%
              </span>
            </div>

            <div className="mt-4 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
              <div
                className={
                  malicious ? 'h-full bg-red-500' : 'h-full bg-emerald-500'
                }
                style={{ width: `${Math.round(result.score * 100)}%` }}
              />
            </div>

            <dl className="mt-4 grid gap-1 text-xs text-slate-400 sm:grid-cols-2 sm:gap-x-6">
              <div className="flex justify-between gap-4">
                <dt>Domain</dt>
                <dd className="truncate font-mono text-slate-300">
                  {result.registrable_domain || '-'}
                </dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt>Threshold</dt>
                <dd className="font-mono text-slate-300">{result.threshold}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt>Model</dt>
                <dd className="truncate font-mono text-slate-300">
                  {result.model_version}
                </dd>
              </div>
            </dl>
          </div>

          {result.top_features?.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/40 px-5 py-4">
              <h2 className="text-sm font-medium text-slate-300">
                What drove this score
              </h2>
              <p className="mt-1 text-xs leading-relaxed text-slate-500">
                Change in log-odds when each feature is replaced by its training
                median. Positive pushes toward malicious.
              </p>
              <ul className="mt-3 space-y-1.5">
                {result.top_features.map((f) => (
                  <li
                    key={f.feature}
                    className="flex items-center justify-between gap-4 text-xs"
                  >
                    <span className="truncate font-mono text-slate-300">
                      {f.feature}
                    </span>
                    <span className="flex shrink-0 items-center gap-3">
                      <span className="text-slate-500">
                        ={' '}
                        {Number.isInteger(f.value)
                          ? f.value
                          : f.value.toFixed(2)}
                      </span>
                      <span
                        className={`w-16 text-right font-mono ${
                          f.contribution > 0
                            ? 'text-red-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {f.contribution > 0 ? '+' : ''}
                        {f.contribution.toFixed(3)}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <p className="text-xs leading-relaxed text-slate-500">
            {result.disclaimer}
          </p>
        </section>
      )}

      <footer className="mt-16 border-t border-slate-900 pt-6 text-xs leading-relaxed text-slate-600">
        <p>
          Portfolio demonstration of a full ML pipeline: data acquisition,
          leakage-aware evaluation, and serverless deployment. Not a substitute
          for a real security product. See{' '}
          <code className="text-slate-500">ml/reports/EVALUATION.md</code> for
          measured performance and an honest limitations section.
        </p>
      </footer>
    </main>
  );
}
