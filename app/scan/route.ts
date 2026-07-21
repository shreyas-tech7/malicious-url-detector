import { NextResponse } from 'next/server';

import {
  callInference,
  readJson,
  resolveInferenceBase,
  validateUrl,
} from '@/lib/inference';

/**
 * POST /scan - public contract for URL classification.
 *
 * Fronts the Python function rather than exposing it directly, so request
 * shaping and validation live in one place. This route lives at `/scan`
 * instead of `/api/scan` because the Python Function owns `/api/*` on this
 * deployment.
 *
 * This endpoint classifies the URL *string*. It never fetches, resolves or
 * renders the submitted URL.
 */

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(request: Request) {
  const body = await readJson(request);
  const url = validateUrl(body.url);

  if (typeof url !== 'string') {
    return NextResponse.json({ error: url.error }, { status: url.status });
  }

  const base = resolveInferenceBase(request);
  const { status, body: result } = await callInference(base, '/api/predict', {
    url,
  });

  return NextResponse.json(result, {
    status,
    headers: {
      // A verdict is specific to the submitted URL and must not be cached by
      // a shared cache and served to a different request.
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export async function GET() {
  return NextResponse.json(
    { error: 'method not allowed - POST a JSON body of {"url": "..."}' },
    { status: 405, headers: { Allow: 'POST' } },
  );
}
