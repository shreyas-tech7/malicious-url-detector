import { NextResponse } from 'next/server';

import {
  callInference,
  readJson,
  resolveInferenceBase,
} from '@/lib/inference';

/**
 * POST /check - public contract for file-signature checking.
 *
 * Accepts a hash and/or lightweight file metadata. It deliberately does NOT
 * accept file uploads: the client computes the hash locally and may send at
 * most a few dozen header bytes for magic-number checks. The service never
 * ingests, unpacks or executes a file.
 */

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** Mirrors MAX_HEADER_SAMPLE_BYTES in api/index.py, as base64 characters. */
const MAX_HEADER_B64 = 512;

export async function POST(request: Request) {
  const body = await readJson(request);

  const hash = typeof body.hash === 'string' ? body.hash.trim() : undefined;
  const filename =
    typeof body.filename === 'string' ? body.filename.slice(0, 512) : undefined;
  const mimeType =
    typeof body.mime_type === 'string' ? body.mime_type.slice(0, 255) : undefined;
  const headerB64 =
    typeof body.header_b64 === 'string' ? body.header_b64 : undefined;

  if (!hash && !filename && !headerB64) {
    return NextResponse.json(
      { error: 'provide at least one of: hash, filename, header_b64' },
      { status: 422 },
    );
  }

  if (hash && !/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(hash)) {
    return NextResponse.json(
      { error: 'hash must be a hex md5, sha1 or sha256' },
      { status: 422 },
    );
  }

  if (headerB64 && headerB64.length > MAX_HEADER_B64) {
    return NextResponse.json(
      {
        error:
          'header_b64 too large - send only the first few dozen bytes, not the file',
      },
      { status: 413 },
    );
  }

  const base = resolveInferenceBase(request);
  const { status, body: result } = await callInference(base, '/api/check-file', {
    hash,
    filename,
    mime_type: mimeType,
    header_b64: headerB64,
  });

  return NextResponse.json(result, {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export async function GET() {
  return NextResponse.json(
    { error: 'method not allowed - POST a JSON body' },
    { status: 405, headers: { Allow: 'POST' } },
  );
}
