// ============================================================
// src/types/auth.ts
// Central type definitions for authentication.
// ============================================================

export type AuthMode = "login" | "signup";
export type AuthProvider = "kgpian" | "google";

// ---- Request shapes ----------------------------------------

export interface KgpianAuthRequest {
  mode: AuthMode;
  provider: "kgpian";
  kgpianId: string;
}

export interface GoogleAuthRequest {
  mode: AuthMode;
  provider: "google";
}

export type AuthRequest = KgpianAuthRequest | GoogleAuthRequest;

// ---- Response shapes ----------------------------------------

export interface AuthUser {
  id: string;
  email: string | null;
  isKgpian: boolean;
}

export interface AuthSuccessData {
  authenticated: true;
  user: AuthUser;
}

export interface AuthSuccessResponse {
  ok: true;
  data: AuthSuccessData;
}

export interface AuthErrorResponse {
  ok: false;
  error: {
    code: string;
    message: string;
  };
}

export type AuthResponse = AuthSuccessResponse | AuthErrorResponse;

// ---- Google OAuth redirect ----------------------------------

export interface OAuthInitData {
  url: string;
}

export interface OAuthInitResponse {
  ok: true;
  data: OAuthInitData;
}

// ---- Known error codes ---------------------------------------

export const AUTH_ERROR_CODES = {
  INVALID_AUTH_OPTION: "INVALID_AUTH_OPTION",
  INVALID_KGPIAN_ID: "INVALID_KGPIAN_ID",
  KGPIAN_VERIFICATION_FAILED: "KGPIAN_VERIFICATION_FAILED",
  ACCOUNT_NOT_FOUND: "ACCOUNT_NOT_FOUND",
  ACCOUNT_EXISTS: "ACCOUNT_EXISTS",
  INTERNAL_ERROR: "INTERNAL_ERROR",
  RATE_LIMITED: "RATE_LIMITED",
} as const;

export type AuthErrorCode =
  (typeof AUTH_ERROR_CODES)[keyof typeof AUTH_ERROR_CODES];
