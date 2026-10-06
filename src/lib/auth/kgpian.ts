// ============================================================
// src/lib/auth/kgpian.ts
//
// KGPian identity verification abstraction.
//
// ARCHITECTURE:
//   This file defines a clean interface (KgpianVerificationProvider)
//   so the actual IIT KGP verification mechanism can be plugged in
//   without changing the rest of the auth code.
//
//   Current implementations:
//   - MockKgpianVerificationProvider  — development/test only
//   - ProductionKgpianVerificationProvider — placeholder, real API TBD
//
// SECURITY:
//   - NEVER allow mock verification in production.
//   - NEVER trust a frontend-supplied "verified" flag.
//   - The server always re-verifies the KGPian ID before acting.
// ============================================================

// ---- Types -------------------------------------------------

export interface KgpianVerificationResult {
  /** Whether the ID was successfully verified */
  verified: boolean;
  /** Normalized form of the KGPian ID (uppercase, trimmed) */
  normalizedId: string;
  /** Optional display name returned by the verification provider */
  displayName?: string;
  /** Optional email returned by the verification provider */
  email?: string;
}

export interface KgpianVerificationProvider {
  /**
   * Verifies a KGPian ID against the authoritative source.
   *
   * @param kgpianId - Raw KGPian ID as entered by the user
   * @returns Verification result. `verified: false` for invalid IDs
   *          (do not throw for expected invalid input).
   * @throws Only for unexpected infrastructure failures.
   */
  verifyKgpianId(kgpianId: string): Promise<KgpianVerificationResult>;
}

// ---- ID validation -----------------------------------------

const KGPIAN_ID_REGEX = /^[A-Za-z0-9]{2,20}$/;

/**
 * Validates the format of a KGPian ID before sending to the
 * verification provider.
 *
 * @returns null if valid, or an error message string if invalid
 */
export function validateKgpianIdFormat(kgpianId: string): string | null {
  if (!kgpianId || typeof kgpianId !== "string") {
    return "KGPian ID is required.";
  }
  const trimmed = kgpianId.trim();
  if (trimmed.length === 0) {
    return "KGPian ID cannot be empty.";
  }
  if (trimmed.length > 254) {
    return "KGPian ID is too long.";
  }
  if (!KGPIAN_ID_REGEX.test(trimmed)) {
    return "KGPian ID contains invalid characters.";
  }
  return null;
}

/**
 * Normalizes a KGPian ID to its canonical form (uppercase, trimmed).
 */
export function normalizeKgpianId(kgpianId: string): string {
  return kgpianId.trim().toUpperCase();
}

// ---- Mock provider (development only) ---------------------

/**
 * Development-only mock verification provider.
 *
 * ⚠️  NEVER use this in production.
 *
 * In development mode (KGPIAN_VERIFICATION_MODE=mock), any
 * syntactically valid KGPian ID is accepted as verified.
 * This allows local development without a real KGP API.
 *
 * Mock behavior:
 *   - IDs starting with "INVALID" → not verified
 *   - All other valid-format IDs → verified
 */
class MockKgpianVerificationProvider implements KgpianVerificationProvider {
  async verifyKgpianId(kgpianId: string): Promise<KgpianVerificationResult> {
    if (process.env.NODE_ENV === "production") {
      // This should never be reached in production due to the
      // factory function guard, but belt-and-suspenders protection.
      throw new Error(
        "[KGPian Auth] MockKgpianVerificationProvider must not be used in production."
      );
    }

    console.warn(
      "[KGPian Auth] Using MOCK verification provider. " +
        "Set KGPIAN_VERIFICATION_MODE=production for real verification."
    );

    const normalizedId = normalizeKgpianId(kgpianId);

    // Simulate a brief network call
    await new Promise((resolve) => setTimeout(resolve, 100));

    // IDs starting with "INVALID" are rejected in mock mode
    if (normalizedId.startsWith("INVALID")) {
      return { verified: false, normalizedId };
    }

    return {
      verified: true,
      normalizedId,
      displayName: `Mock User (${normalizedId})`,
      email: `${normalizedId.toLowerCase()}@kgpian.iitkgp.ac.in`,
    };
  }
}

// ---- Production provider (placeholder) --------------------

/**
 * Production KGPian verification provider.
 *
 * TODO: Implement once the actual IIT KGP verification API
 * is specified. Connect to the official identity service, ERP,
 * or institutional verification API here.
 *
 * Required environment variables (set in .env.local, server only):
 *   KGPIAN_VERIFICATION_API_URL
 *   KGPIAN_VERIFICATION_API_KEY
 */
class ProductionKgpianVerificationProvider
  implements KgpianVerificationProvider
{
  private apiUrl: string;
  private apiKey: string;

  constructor() {
    const apiUrl = process.env.KGPIAN_VERIFICATION_API_URL;
    const apiKey = process.env.KGPIAN_VERIFICATION_API_KEY;

    if (!apiUrl || !apiKey) {
      throw new Error(
        "[KGPian Auth] KGPIAN_VERIFICATION_API_URL and " +
          "KGPIAN_VERIFICATION_API_KEY must be set when " +
          "KGPIAN_VERIFICATION_MODE=production."
      );
    }

    this.apiUrl = apiUrl;
    this.apiKey = apiKey;
  }

  async verifyKgpianId(kgpianId: string): Promise<KgpianVerificationResult> {
    // ── Implement real API call here ──────────────────────────
    // Example shape (replace with actual API contract):
    //
    // const normalizedId = normalizeKgpianId(kgpianId);
    // const response = await fetch(`${this.apiUrl}/verify`, {
    //   method: "POST",
    //   headers: {
    //     "Content-Type": "application/json",
    //     "Authorization": `Bearer ${this.apiKey}`,
    //   },
    //   body: JSON.stringify({ kgpianId: normalizedId }),
    // });
    //
    // if (!response.ok) {
    //   throw new Error(`KGPian verification API returned ${response.status}`);
    // }
    //
    // const data = await response.json();
    // return {
    //   verified: data.verified,
    //   normalizedId,
    //   displayName: data.name,
    //   email: data.email,
    // };
    // ──────────────────────────────────────────────────────────

    // Until the real API is specified, throw to prevent silently
    // passing all verifications in production.
    void kgpianId; // will be used once the API is implemented
    throw new Error(
      "[KGPian Auth] ProductionKgpianVerificationProvider is not yet implemented. " +
        "Connect the real IIT KGP verification API here."
    );
  }
}


// ---- Factory (singleton) ----------------------------------

let _provider: KgpianVerificationProvider | null = null;

/**
 * Returns the appropriate KGPian verification provider based on
 * the KGPIAN_VERIFICATION_MODE environment variable.
 *
 * Guards:
 * - In production, KGPIAN_VERIFICATION_MODE must be "production"
 *   (mock is explicitly disallowed).
 * - In development/test, defaults to mock if not set.
 */
export function getKgpianVerificationProvider(): KgpianVerificationProvider {
  if (_provider) return _provider;

  const mode = process.env.KGPIAN_VERIFICATION_MODE;
  const isProduction = process.env.NODE_ENV === "production";

  if (isProduction && mode !== "production") {
    throw new Error(
      "[KGPian Auth] KGPIAN_VERIFICATION_MODE must be set to " +
        '"production" in a production environment. ' +
        'Setting it to "mock" in production is not allowed.'
    );
  }

  if (mode === "production") {
    _provider = new ProductionKgpianVerificationProvider();
  } else {
    _provider = new MockKgpianVerificationProvider();
  }

  return _provider;
}

/**
 * Main entry point: validates format and verifies a KGPian ID.
 *
 * @throws Never — returns `verified: false` for invalid IDs,
 *         and propagates infrastructure errors as thrown errors.
 */
export async function verifyKgpianId(
  rawKgpianId: string
): Promise<KgpianVerificationResult> {
  const formatError = validateKgpianIdFormat(rawKgpianId);
  if (formatError) {
    return {
      verified: false,
      normalizedId: rawKgpianId.trim().toUpperCase(),
    };
  }

  const provider = getKgpianVerificationProvider();
  return provider.verifyKgpianId(rawKgpianId);
}
