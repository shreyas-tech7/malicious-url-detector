'use client';

import { useState } from 'react';
import { FileScanPanel } from './components/FileScanPanel';
import { ScanTabs, panelId, tabId, type ScanMode } from './components/ScanTabs';
import { UrlScanPanel } from './components/UrlScanPanel';

export default function Home() {
  const [mode, setMode] = useState<ScanMode>('url');

  return (
    <main className="mx-auto min-h-screen max-w-3xl px-6 py-14 sm:py-20">
      <header>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-3">
          <h1 className="text-3xl font-semibold tracking-display text-fg-strong sm:text-4xl">
            Malicious URL &amp; File-Signature Detector
          </h1>
          {/*
           * The strongest thing this page can tell a first-time visitor is what
           * it does *not* do with their input, so that claim gets its own
           * element instead of being buried mid-sentence. It holds for both
           * modes: the link is never dereferenced, the file never leaves the
           * browser.
           */}
          <span className="inline-flex items-center gap-1.5 rounded-full border border-line-strong bg-surface-1 px-2.5 py-1 text-[0.6875rem] font-medium text-fg-muted shadow-card">
            <span
              aria-hidden="true"
              className="h-1.5 w-1.5 rounded-full bg-emerald-400"
            />
            Nothing is fetched or uploaded
          </span>
        </div>

        <p className="mt-4 max-w-[62ch] text-sm leading-relaxed text-fg-muted">
          A gradient-boosted classifier over URL-derived features, plus a hash
          lookup against a malicious-signature table. Links are scored as{' '}
          <strong className="font-medium text-fg-strong">strings</strong> and
          never fetched; files are hashed{' '}
          <strong className="font-medium text-fg-strong">in your browser</strong>{' '}
          and never uploaded.
        </p>
      </header>

      <div className="mt-8">
        <ScanTabs value={mode} onChange={setMode} />
      </div>

      {/*
       * Both panels stay mounted and the inactive one is hidden, which is what
       * the tabs pattern calls for: switching keeps each mode's result intact
       * instead of discarding it, and neither panel refetches on return.
       */}
      <div className="mt-6">
        <div
          role="tabpanel"
          id={panelId('url')}
          aria-labelledby={tabId('url')}
          hidden={mode !== 'url'}
        >
          <UrlScanPanel />
        </div>

        <div
          role="tabpanel"
          id={panelId('file')}
          aria-labelledby={tabId('file')}
          hidden={mode !== 'file'}
        >
          <FileScanPanel />
        </div>
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
