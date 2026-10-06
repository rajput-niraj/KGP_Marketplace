// ============================================================
// src/app/auth/callback/route.ts
//
// GET /auth/callback
//
// OAuth callback handler — processes the authorization code
// returned by Google (via Supabase) after the user consents.
//
// Flow:
//   Google → Supabase → /auth/callback?code=...
//                          ↓
//                    Exchange code for session
//                          ↓
//                    Retrieve authenticated user
//                          ↓
//                    Classify: KGP or non-KGP
//                          ↓
//                    Create/fetch profile
//                          ↓
//                    Redirect to app
//
// SECURITY:
// - Does NOT allow arbitrary redirects (open redirect prevention)
// - is_kgp_user determined by email domain, NOT frontend flag
// - Profile created server-side with correct is_kgp_user value
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { createSupabaseServerClient } from "@/lib/supabase/server";
import { ensureProfile } from "@/lib/auth/profile";

/** Allowed redirect destinations after OAuth (open redirect prevention) */
const ALLOWED_REDIRECTS = ["/", "/marketplace", "/profile"];
const DEFAULT_POST_AUTH_REDIRECT = "/marketplace";
const DEFAULT_ERROR_REDIRECT = "/auth/error";

/** IIT KGP institutional email domain */
const KGP_EMAIL_DOMAIN =
  process.env.ALLOWED_IIT_KGP_EMAIL_DOMAIN ?? "kgpian.iitkgp.ac.in";

/**
 * Determines whether a Google-authenticated user is a KGP user
 * based on their verified email domain.
 *
 * The frontend's "I am KGPian / not KGPian" choice is IGNORED here.
 * The authenticated identity (email from Google) is the source of truth.
 */
function classifyGoogleUser(email: string | undefined): boolean {
  if (!email) return false;
  const domain = email.split("@")[1]?.toLowerCase();
  return domain === KGP_EMAIL_DOMAIN.toLowerCase();
}

/**
 * Validates a next-path to prevent open redirect attacks.
 * Only relative paths in the allowlist are accepted.
 */
function getSafeRedirect(next: string | null): string {
  if (!next) return DEFAULT_POST_AUTH_REDIRECT;

  // Must be a relative path (no protocol, no external domain)
  if (!next.startsWith("/")) return DEFAULT_POST_AUTH_REDIRECT;

  // Must be in the explicit allowlist
  if (ALLOWED_REDIRECTS.includes(next)) return next;

  return DEFAULT_POST_AUTH_REDIRECT;
}

export async function GET(request: NextRequest) {
  const { searchParams, origin } = new URL(request.url);

  const code = searchParams.get("code");
  const next = searchParams.get("next") ?? null;
  const errorParam = searchParams.get("error");
  const errorDescription = searchParams.get("error_description");

  // Handle OAuth provider errors
  if (errorParam) {
    console.error(
      `[Auth Callback] OAuth error: ${errorParam} — ${errorDescription}`
    );
    const errorUrl = new URL(DEFAULT_ERROR_REDIRECT, origin);
    errorUrl.searchParams.set("error", "oauth_failed");
    return NextResponse.redirect(errorUrl);
  }

  if (!code) {
    console.error("[Auth Callback] No authorization code in callback URL");
    const errorUrl = new URL(DEFAULT_ERROR_REDIRECT, origin);
    errorUrl.searchParams.set("error", "missing_code");
    return NextResponse.redirect(errorUrl);
  }

  // ── Exchange code for session ───────────────────────────
  const supabase = await createSupabaseServerClient();

  const { data: sessionData, error: sessionError } =
    await supabase.auth.exchangeCodeForSession(code);

  if (sessionError || !sessionData?.user) {
    console.error("[Auth Callback] Code exchange failed:", sessionError);
    const errorUrl = new URL(DEFAULT_ERROR_REDIRECT, origin);
    errorUrl.searchParams.set("error", "session_failed");
    return NextResponse.redirect(errorUrl);
  }

  const authUser = sessionData.user;

  // ── Classify user type (KGP or non-KGP) ────────────────
  // NOTE: We use the verified email from Google (via Supabase),
  // NOT the frontend's "I am KGPian" flag.
  const isKgpUser = classifyGoogleUser(authUser.email);

  // ── Create/fetch profile ────────────────────────────────
  try {
    await ensureProfile({
      userId: authUser.id,
      email: authUser.email ?? null,
      isKgpUser,
      kgpianId: null, // Google OAuth users don't have a KGPian ID
      name:
        authUser.user_metadata?.full_name ??
        authUser.user_metadata?.name ??
        null,
      avatarUrl: authUser.user_metadata?.avatar_url ?? null,
    });
  } catch (error) {
    console.error("[Auth Callback] Profile creation failed:", error);
    // Don't block the user — they have a valid session.
    // Profile will be created on next access.
  }

  // ── Redirect to app ────────────────────────────────────
  const redirectPath = getSafeRedirect(next);
  const redirectUrl = new URL(redirectPath, origin);

  return NextResponse.redirect(redirectUrl);
}
