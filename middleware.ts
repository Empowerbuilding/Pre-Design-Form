import { NextRequest, NextResponse } from 'next/server';

// ─── Rate limiting store ────────────────────────────────────────────────────
// Module-level state persists across requests in the same runtime instance.
// Resets on cold starts. For production at scale, replace with Redis/Upstash.

const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;   // purge stale entries every 5 min

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();
let lastCleanup = Date.now();

function cleanupStaleEntries() {
  const now = Date.now();
  if (now - lastCleanup < CLEANUP_INTERVAL_MS) return;
  lastCleanup = now;

  for (const [ip, entry] of rateLimitStore) {
    if (now > entry.resetAt) {
      rateLimitStore.delete(ip);
    }
  }
}

function getClientIp(request: NextRequest): string {
  return (
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    request.headers.get('cf-connecting-ip') ||
    'unknown'
  );
}

function checkRateLimit(ip: string): { allowed: boolean; remaining: number; resetAt: number } {
  const now = Date.now();
  const entry = rateLimitStore.get(ip);

  if (!entry || now > entry.resetAt) {
    const resetAt = now + RATE_LIMIT_WINDOW_MS;
    rateLimitStore.set(ip, { count: 1, resetAt });
    return { allowed: true, remaining: RATE_LIMIT_MAX - 1, resetAt };
  }

  if (entry.count >= RATE_LIMIT_MAX) {
    return { allowed: false, remaining: 0, resetAt: entry.resetAt };
  }

  entry.count++;
  return { allowed: true, remaining: RATE_LIMIT_MAX - entry.count, resetAt: entry.resetAt };
}

// ─── Security headers applied to every matched response ─────────────────────

function applySecurityHeaders(response: NextResponse) {
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  return response;
}

// ─── Middleware ──────────────────────────────────────────────────────────────

export function middleware(request: NextRequest) {
  cleanupStaleEntries();

  const { pathname } = request.nextUrl;

  // Rate limit only POST to /api/submit-form
  if (pathname === '/api/submit-form' && request.method === 'POST') {
    const ip = getClientIp(request);
    const { allowed, remaining, resetAt } = checkRateLimit(ip);

    if (!allowed) {
      const retryAfterSeconds = Math.ceil((resetAt - Date.now()) / 1000);
      const response = NextResponse.json(
        { success: false, message: 'Too many submissions. Please try again later.' },
        { status: 429 }
      );
      response.headers.set('Retry-After', String(retryAfterSeconds));
      response.headers.set('X-RateLimit-Limit', String(RATE_LIMIT_MAX));
      response.headers.set('X-RateLimit-Remaining', '0');
      response.headers.set('X-RateLimit-Reset', String(Math.ceil(resetAt / 1000)));
      return applySecurityHeaders(response);
    }

    // Let the request through with rate limit info headers
    const response = NextResponse.next();
    response.headers.set('X-RateLimit-Limit', String(RATE_LIMIT_MAX));
    response.headers.set('X-RateLimit-Remaining', String(remaining));
    response.headers.set('X-RateLimit-Reset', String(Math.ceil(resetAt / 1000)));
    return applySecurityHeaders(response);
  }

  // All other matched routes just get security headers
  const response = NextResponse.next();
  return applySecurityHeaders(response);
}

export const config = {
  matcher: [
    '/api/submit-form',
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
