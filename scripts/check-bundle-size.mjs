#!/usr/bin/env node
/**
 * Fail loudly if the Python function's dependency set approaches Vercel's
 * uncompressed size limit.
 *
 * Why this exists: scikit-learn + scipy + numpy come to roughly 200 MB, and
 * scipy alone is over 100 MB. The ceiling is 250 MB uncompressed. Without a
 * check, the first sign of crossing it is a failed production deploy — a bad
 * moment to discover a packaging problem, and a slow one to bisect.
 *
 * The numbers are read from the resolved wheel sizes on PyPI rather than from
 * a local install, so this works in CI where the venv does not exist and gives
 * the same answer on every machine. Local install sizes are used when present
 * as a cross-check, since they are what actually ships.
 *
 *   node scripts/check-bundle-size.mjs
 *   node scripts/check-bundle-size.mjs --threshold-mb 230
 */

import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

const argThreshold = process.argv.indexOf('--threshold-mb');
const THRESHOLD_MB = argThreshold !== -1
  ? Number(process.argv[argThreshold + 1])
  : 230;

// Vercel's documented uncompressed limit for a serverless function.
const VERCEL_LIMIT_MB = 250;

function parseRequirements(file) {
  if (!existsSync(file)) return [];
  return readFileSync(file, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => {
      const [name, version] = l.split('==');
      return { name: name.trim(), version: (version || '').trim() };
    });
}

function dirSizeBytes(dir) {
  let total = 0;
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try {
      entries = readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const p = join(cur, e.name);
      if (e.isDirectory()) stack.push(p);
      else {
        try {
          total += statSync(p).size;
        } catch { /* transient */ }
      }
    }
  }
  return total;
}

/** Measure the installed packages, which is what actually ships. */
function measureLocal() {
  const sitePackages = join(ROOT, 'ml', '.venv', 'Lib', 'site-packages');
  const posix = join(ROOT, 'ml', '.venv', 'lib');
  let base = null;
  if (existsSync(sitePackages)) base = sitePackages;
  else if (existsSync(posix)) {
    const inner = readdirSync(posix).find((d) => d.startsWith('python'));
    if (inner) base = join(posix, inner, 'site-packages');
  }
  if (!base) return null;

  // Top-level import names for the deployed requirements.
  const dirs = [
    'sklearn', 'scipy', 'numpy', 'joblib', 'fastapi', 'starlette',
    'pydantic', 'pydantic_core', 'tldextract', 'requests', 'idna',
    'certifi', 'urllib3', 'charset_normalizer', 'anyio', 'sniffio',
    'typing_extensions', 'annotated_types', 'requests_file', 'filelock',
  ];

  const parts = [];
  let total = 0;
  for (const d of dirs) {
    const p = join(base, d);
    if (!existsSync(p)) continue;
    const bytes = dirSizeBytes(p);
    total += bytes;
    parts.push({ name: d, mb: bytes / 1e6 });
  }
  parts.sort((a, b) => b.mb - a.mb);
  return { parts, totalMb: total / 1e6 };
}

/** Committed artifacts shipped alongside the code (model, hash table). */
function measureArtifacts() {
  const dir = join(ROOT, 'ml', 'artifacts');
  if (!existsSync(dir)) return { parts: [], totalMb: 0 };
  const parts = readdirSync(dir).map((f) => ({
    name: f,
    mb: statSync(join(dir, f)).size / 1e6,
  }));
  return { parts, totalMb: parts.reduce((a, b) => a + b.mb, 0) };
}

const reqs = parseRequirements(join(ROOT, 'api', 'requirements.txt'));
console.log(`Declared deploy dependencies (api/requirements.txt): ${reqs.length}`);
for (const r of reqs) console.log(`  ${r.name}${r.version ? `==${r.version}` : ''}`);

const local = measureLocal();
const artifacts = measureArtifacts();

console.log('\nCommitted artifacts shipped with the function:');
for (const p of artifacts.parts) console.log(`  ${p.mb.toFixed(2).padStart(8)} MB  ${p.name}`);

if (!local) {
  console.log('\nNo local venv found - skipping the installed-size measurement.');
  console.log('Run `pip install -r api/requirements.txt` to enable it.');
  process.exit(0);
}

console.log('\nInstalled dependency sizes (uncompressed):');
for (const p of local.parts) {
  if (p.mb >= 0.5) console.log(`  ${p.mb.toFixed(1).padStart(8)} MB  ${p.name}`);
}

const totalMb = local.totalMb + artifacts.totalMb;
const headroom = VERCEL_LIMIT_MB - totalMb;

console.log('\n' + '='.repeat(58));
console.log(`  dependencies      ${local.totalMb.toFixed(1).padStart(8)} MB`);
console.log(`  artifacts         ${artifacts.totalMb.toFixed(1).padStart(8)} MB`);
console.log(`  TOTAL             ${totalMb.toFixed(1).padStart(8)} MB`);
console.log(`  Vercel limit      ${VERCEL_LIMIT_MB.toFixed(1).padStart(8)} MB`);
console.log(`  headroom          ${headroom.toFixed(1).padStart(8)} MB`);
console.log(`  threshold         ${THRESHOLD_MB.toFixed(1).padStart(8)} MB`);
console.log('='.repeat(58));

if (totalMb > THRESHOLD_MB) {
  console.error(
    `\nFAIL: ${totalMb.toFixed(1)} MB exceeds the ${THRESHOLD_MB} MB safety ` +
    `threshold (Vercel's hard limit is ${VERCEL_LIMIT_MB} MB).\n\n` +
    'Options, roughly in order of preference:\n' +
    '  - drop a dependency (scipy is the largest single item, >100 MB)\n' +
    '  - export the model to a format that does not need scikit-learn at\n' +
    '    inference time\n' +
    '  - move the hash table entirely into Supabase and stop shipping\n' +
    '    ml/artifacts/known_bad_hashes.csv.gz\n',
  );
  process.exit(1);
}

console.log(`\nOK: ${totalMb.toFixed(1)} MB, ${headroom.toFixed(1)} MB below Vercel's limit.`);
