// ============================================================
// src/proxy.ts
//
// Next.js 16+ renames "middleware" to "proxy".
// This file is the new convention for what was middleware.ts
// in Next.js 14/15.
//
// Responsibilities:
//   1. Refresh the Supabase session on every request
//   2. Protect marketplace routes
//   3. Redirect unauthenticated users
//   4. Redirect authenticated users away from auth pages
// ============================================================

import { type NextRequest, NextResponse } from "next/server";
import { updateSession } from "@/lib/supabase/middleware";

// ── Route classification ─────────────────────────────────────

const PROTECTED_ROUTE_PREFIXES = [
  "/marketplace",
  "/profile",
  "/settings",
  "/api/marketplace",
  "/api/profile",
];

const AUTH_ROUTE_PREFIXES = [
  "/auth/kgpian",
  "/auth/general",
  "/auth-choice",
  "/login",
  "/signup",
];

const PUBLIC_ROUTE_PREFIXES = [
  "/auth/callback",
  "/auth/error",
  "/api/auth",
  "/_next",
  "/favicon",
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

// ── Proxy handler ─────────────────────────────────────────────

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (isPublicRoute(pathname)) {
    return NextResponse.next({ request });
  }

  const { response, user } = await updateSession(request);
  const isAuthenticated = user !== null;

  if (isProtectedRoute(pathname) && !isAuthenticated) {
    const loginUrl = new URL("/", request.url);
    loginUrl.searchParams.set("next", pathname);
    return NextResponse.redirect(loginUrl);
  }

  if (isAuthRoute(pathname) && isAuthenticated) {
    const marketplaceUrl = new URL("/marketplace", request.url);
    return NextResponse.redirect(marketplaceUrl);
  }

  return response;
}

// ── Matcher ──────────────────────────────────────────────────

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|sitemap.xml|robots.txt).*)",
  ],
};
