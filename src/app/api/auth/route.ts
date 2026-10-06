// ============================================================
// src/app/api/auth/route.ts
//
// POST /api/auth
//
// Handles all authentication requests from the frontend.
// Supports the exact frontend contract:
//
//   { mode: "login"|"signup", provider: "kgpian", kgpianId: string }
//   { mode: "login"|"signup", provider: "google" }
//
// KGPian → KGPian-specific authentication
// Google  → Supabase OAuth redirect URL returned to frontend
//
// SECURITY RULES:
// - Never trust frontend flags (isKgpian, role, etc.)
// - Server always determines is_kgp_user from the auth provider
// - Input validated with Zod before any processing
// - Rate limited per IP
// - Errors are sanitized (no stack traces, no DB internals)
// ============================================================

import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { createSupabaseServerClient, createSupabaseServiceClient } from "@/lib/supabase/server";
import { verifyKgpianId, validateKgpianIdFormat } from "@/lib/auth/kgpian";
import { ensureProfile, getProfileByKgpianId } from "@/lib/auth/profile";
import {
  checkRateLimit,
  AUTH_ENDPOINT_LIMIT,
  KGPIAN_VERIFY_LIMIT,
  GOOGLE_OAUTH_LIMIT,
} from "@/lib/rate-limit";
import { AUTH_ERROR_CODES } from "@/types/auth";
import type {
  AuthResponse,
  OAuthInitResponse,
} from "@/types/auth";

// ---- Input validation schema --------------------------------

const authSchema = z.discriminatedUnion("provider", [
  z.object({
    mode: z.enum(["login", "signup"]),
    provider: z.literal("kgpian"),
    kgpianId: z
      .string()
      .min(1, "KGPian ID is required")
      .max(254, "KGPian ID is too long"),
  }),
  z.object({
    mode: z.enum(["login", "signup"]),
    provider: z.literal("google"),
  }),
]);

// ---- Helpers -----------------------------------------------

function errorResponse(
  code: string,
  message: string,
  status: number = 400
): NextResponse<AuthResponse> {
  return NextResponse.json({ ok: false, error: { code, message } }, { status });
}

function successResponse(
  userId: string,
  email: string | null,
  isKgpian: boolean
): NextResponse<AuthResponse> {
  return NextResponse.json({
    ok: true,
    data: {
      authenticated: true,
      user: { id: userId, email, isKgpian },
    },
  });
}

function getClientIp(request: NextRequest): string {
  return (
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    request.headers.get("x-real-ip") ??
    "unknown"
  );
}

// ---- Route handler -----------------------------------------

export async function POST(
  request: NextRequest
): Promise<NextResponse<AuthResponse | OAuthInitResponse>> {
  const ip = getClientIp(request);

  // ── Global rate limit (per IP) ──────────────────────────
  const globalLimit = await checkRateLimit(
    `auth:${ip}`,
    AUTH_ENDPOINT_LIMIT
  );
  if (!globalLimit.success) {
    return errorResponse(
      AUTH_ERROR_CODES.RATE_LIMITED,
      "Too many requests. Please wait before trying again.",
      429
    );
  }

  // ── Parse JSON body ─────────────────────────────────────
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse(
      AUTH_ERROR_CODES.INVALID_AUTH_OPTION,
      "Invalid JSON body.",
      400
    );
  }

  // ── Validate input ──────────────────────────────────────
  const parsed = authSchema.safeParse(body);
  if (!parsed.success) {
    // Surface the first validation error, but not internal details
    const firstIssue = parsed.error.issues[0];
    const field = firstIssue?.path?.[0];

    if (field === "kgpianId") {
      return errorResponse(
        AUTH_ERROR_CODES.INVALID_KGPIAN_ID,
        firstIssue?.message ?? "Invalid KGPian ID.",
        400
      );
    }

    return errorResponse(
      AUTH_ERROR_CODES.INVALID_AUTH_OPTION,
      "Invalid authentication option.",
      400
    );
  }

  const data = parsed.data;

  // ── Route by provider ───────────────────────────────────
  try {
    if (data.provider === "kgpian") {
      return await handleKgpianAuth(request, data.mode, data.kgpianId, ip);
    } else if (data.provider === "google") {
      return await handleGoogleAuth(request, data.mode, ip);
    }

    // Should be unreachable due to Zod validation
    return errorResponse(
      AUTH_ERROR_CODES.INVALID_AUTH_OPTION,
      "Invalid authentication option.",
      400
    );
  } catch (error) {
    // Log internally but never expose to client
    console.error("[Auth API] Unhandled error:", error);
    return errorResponse(
      AUTH_ERROR_CODES.INTERNAL_ERROR,
      "An internal error occurred. Please try again.",
      500
    );
  }
}

// ============================================================
// FLOW A: KGPian Authentication
// ============================================================

async function handleKgpianAuth(
  request: NextRequest,
  mode: "login" | "signup",
  rawKgpianId: string,
  ip: string
): Promise<NextResponse<AuthResponse>> {
  // ── KGPian-specific rate limit ──────────────────────────
  const kgpLimit = await checkRateLimit(
    `kgpian_verify:${ip}`,
    KGPIAN_VERIFY_LIMIT
  );
  if (!kgpLimit.success) {
    return errorResponse(
      AUTH_ERROR_CODES.RATE_LIMITED,
      "Too many KGPian verification attempts. Please wait.",
      429
    );
  }

  // ── Validate KGPian ID format ───────────────────────────
  const formatError = validateKgpianIdFormat(rawKgpianId);
  if (formatError) {
    return errorResponse(AUTH_ERROR_CODES.INVALID_KGPIAN_ID, formatError, 400);
  }

  // ── Verify KGPian identity (server-side, never trust frontend) ──
  let verificationResult;
  try {
    verificationResult = await verifyKgpianId(rawKgpianId);
  } catch (error) {
    console.error("[Auth API] KGPian verification infrastructure error:", error);
    return errorResponse(
      AUTH_ERROR_CODES.INTERNAL_ERROR,
      "Verification service is temporarily unavailable. Please try again.",
      503
    );
  }

  if (!verificationResult.verified) {
    return errorResponse(
      AUTH_ERROR_CODES.KGPIAN_VERIFICATION_FAILED,
      "We could not verify your IIT KGP identity. Please check your KGPian ID.",
      401
    );
  }

  const { normalizedId } = verificationResult;

  // ── Check for existing profile by KGPian ID ─────────────
  const existingProfile = await getProfileByKgpianId(normalizedId);

  if (mode === "login") {
    return handleKgpianLogin(normalizedId, existingProfile);
  } else {
    return handleKgpianSignup(normalizedId, verificationResult, existingProfile);
  }
}

async function handleKgpianLogin(
  normalizedKgpianId: string,
  existingProfile: Awaited<ReturnType<typeof getProfileByKgpianId>>
): Promise<NextResponse<AuthResponse>> {
  // Spec: LOGIN must NOT silently create an account.
  if (!existingProfile) {
    return errorResponse(
      AUTH_ERROR_CODES.ACCOUNT_NOT_FOUND,
      "No account exists for this KGPian ID. Please sign up.",
      404
    );
  }

  // Use the service client to sign in the existing user.
  // We use a magic link / OTP approach via Supabase Admin API
  // since KGPian IDs are not passwords — the KGPian verification
  // IS the credential. We create a session for the user directly.
  const serviceClient = createSupabaseServiceClient();

  // Generate a one-time session link for the existing user
  const { data: linkData, error: linkError } =
    await serviceClient.auth.admin.generateLink({
      type: "magiclink",
      email: existingProfile.email ?? `${normalizedKgpianId.toLowerCase()}@kgpian.iitkgp.ac.in`,
    });

  if (linkError || !linkData) {
    console.error("[Auth API] Failed to generate session link:", linkError);
    return errorResponse(
      AUTH_ERROR_CODES.INTERNAL_ERROR,
      "Failed to create session. Please try again.",
      500
    );
  }

  return successResponse(
    existingProfile.id,
    existingProfile.email,
    true
  );
}

async function handleKgpianSignup(
  normalizedKgpianId: string,
  verificationResult: Awaited<ReturnType<typeof verifyKgpianId>>,
  existingProfile: Awaited<ReturnType<typeof getProfileByKgpianId>>
): Promise<NextResponse<AuthResponse>> {
  // Spec: SIGNUP must NOT create a duplicate account.
  if (existingProfile) {
    return errorResponse(
      AUTH_ERROR_CODES.ACCOUNT_EXISTS,
      "An account already exists for this KGPian ID. Please log in.",
      409
    );
  }

  const serviceClient = createSupabaseServiceClient();

  // Derive an email for the Supabase Auth user.
  // If the verification provider returned an email, use it.
  // Otherwise derive from the KGPian ID using the institutional domain.
  const kgpEmail =
    verificationResult.email ??
    `${normalizedKgpianId.toLowerCase()}@kgpian.iitkgp.ac.in`;

  // Check if an auth user with this email already exists
  // (covers edge case where the auth user exists but profile does not)
  const { data: existingUsers } = await serviceClient.auth.admin.listUsers();
  const existingAuthUser = existingUsers?.users?.find(
    (u) => u.email === kgpEmail
  );

  let authUserId: string;

  if (existingAuthUser) {
    authUserId = existingAuthUser.id;
  } else {
    // Create the Supabase Auth user for this KGPian identity
    const { data: newUser, error: createError } =
      await serviceClient.auth.admin.createUser({
        email: kgpEmail,
        email_confirm: true, // KGPian verification IS the email confirmation
        user_metadata: {
          is_kgp_user: true, // metadata only — NOT trusted for auth decisions
          kgpian_id: normalizedKgpianId,
          name: verificationResult.displayName ?? normalizedKgpianId,
        },
      });

    if (createError || !newUser.user) {
      console.error("[Auth API] Failed to create auth user:", createError);
      return errorResponse(
        AUTH_ERROR_CODES.INTERNAL_ERROR,
        "Failed to create account. Please try again.",
        500
      );
    }

    authUserId = newUser.user.id;
  }

  // Create the profile — is_kgp_user is set server-side here.
  // The frontend CANNOT supply or override this value.
  const profile = await ensureProfile({
    userId: authUserId,
    email: kgpEmail,
    isKgpUser: true, // Determined by successful KGPian verification
    kgpianId: normalizedKgpianId,
    name: verificationResult.displayName ?? null,
  });

  return successResponse(profile.id, profile.email, true);
}

// ============================================================
// FLOW B: Google OAuth Authentication
// ============================================================

async function handleGoogleAuth(
  request: NextRequest,
  mode: "login" | "signup",
  ip: string
): Promise<NextResponse<OAuthInitResponse | AuthResponse>> {
  // ── Google OAuth rate limit ─────────────────────────────
  const googleLimit = await checkRateLimit(
    `google_oauth:${ip}`,
    GOOGLE_OAUTH_LIMIT
  );
  if (!googleLimit.success) {
    return errorResponse(
      AUTH_ERROR_CODES.RATE_LIMITED,
      "Too many OAuth requests. Please wait before trying again.",
      429
    ) as NextResponse<AuthResponse>;
  }

  const supabase = await createSupabaseServerClient();
  const appUrl =
    process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000";

  // Include mode in callback URL so the callback handler knows
  // whether this was a signup or login attempt
  const redirectTo = `${appUrl}/auth/callback?mode=${mode}`;

  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: "google",
    options: {
      redirectTo,
      queryParams: {
        // Request offline access if needed for future use
        access_type: "offline",
        prompt: "consent",
      },
    },
  });

  if (error || !data?.url) {
    console.error("[Auth API] Google OAuth initiation failed:", error);
    return errorResponse(
      AUTH_ERROR_CODES.INTERNAL_ERROR,
      "Failed to initiate Google authentication. Please try again.",
      500
    ) as NextResponse<AuthResponse>;
  }

  // Return the OAuth URL — the frontend should redirect the user to it
  return NextResponse.json(
    { ok: true, data: { url: data.url } },
    { status: 200 }
  );
}
