// ============================================================
// src/middleware.ts
//
// Next.js middleware — runs on every matching request BEFORE
// the page/route handler renders.
//
// Responsibilities:
//   1. Refresh the Supabase session (required by @supabase/ssr)
//   2. Detect authentication state
//   3. Protect marketplace routes — redirect unauthenticated users
//   4. Prevent authenticated users from re-visiting auth pages
//
// NOT responsible for:
//   - KGPian verification (happens during login/signup)
//   - Authorization (role checks, etc.)
//   - Business logic
// ============================================================

import { type NextRequest, NextResponse } from "next/server";
import { updateSession } from "@/lib/supabase/middleware";

// ── Route classification ─────────────────────────────────────

/** Routes that require an authenticated session */
const PROTECTED_ROUTE_PREFIXES = [
  "/marketplace",
  "/profile",
  "/settings",
  "/api/marketplace",
  "/api/profile",
];

/** Auth routes — authenticated users should be redirected away from these */
const AUTH_ROUTE_PREFIXES = [
  "/auth/kgpian",
  "/auth/general",
  "/auth-choice",
  "/login",
  "/signup",
];

/** Routes that should ALWAYS pass through (never redirect) */
const PUBLIC_ROUTE_PREFIXES = [
  "/auth/callback", // OAuth callback must always be reachable
  "/auth/error",    // Error page must always be reachable
  "/api/auth",      // Auth API must always be reachable
  "/_next",         // Next.js internals
  "/favicon",
  "/public",
];

function isProtectedRoute(pathname: string): boolean {
  return PROTECTED_ROUTE_PREFIXES.some((prefix) =>
    pathname.startsWith(prefix)
  );
}

function isAuthRoute(pathname: string): boolean {
  return AUTH_ROUTE_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTE_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

// ── Middleware ───────────────────────────────────────────────

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Always let public/system routes pass through
  if (isPublicRoute(pathname)) {
    return NextResponse.next({ request });
  }

  // Refresh the session — MUST be called before any auth check.
  // Returns the updated response (with refreshed cookies) and user.
  const { response, user } = await updateSession(request);

  const isAuthenticated = user !== null;

  // ── Protect marketplace routes ───────────────────────────
  if (isProtectedRoute(pathname) && !isAuthenticated) {
    const loginUrl = new URL("/", request.url);
    loginUrl.searchParams.set("next", pathname);
    return NextResponse.redirect(loginUrl);
  }

  // ── Redirect authenticated users away from auth pages ────
  if (isAuthRoute(pathname) && isAuthenticated) {
    const marketplaceUrl = new URL("/marketplace", request.url);
    return NextResponse.redirect(marketplaceUrl);
  }

  // Return the (possibly cookie-updated) response
  return response;
}

// ── Matcher ──────────────────────────────────────────────────
// Run middleware on all routes EXCEPT Next.js static files and images.

export const config = {
  matcher: [
    /*
     * Match all request paths EXCEPT:
     * - _next/static (static files)
     * - _next/image (image optimization)
     * - favicon.ico, sitemap.xml, robots.txt
     */
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
};
