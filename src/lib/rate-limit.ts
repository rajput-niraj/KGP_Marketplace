// ============================================================
// src/lib/rate-limit.ts
// Request rate limiting using Upstash Redis.
//
// If UPSTASH_REDIS_REST_URL / TOKEN are not configured, rate
// limiting is disabled and a warning is logged. This allows the
// app to run in development without Redis.
//
// Production deployments SHOULD configure Upstash Redis.
// ============================================================

interface RateLimitResult {
  success: boolean;
  /** Remaining requests in the current window */
  remaining: number;
  /** Reset time in seconds (Unix timestamp) */
  reset: number;
}

interface RateLimitConfig {
  /** Max requests per window */
  limit: number;
  /** Window duration in seconds */
  windowSeconds: number;
}

const DEFAULTS: RateLimitConfig = {
  limit: 10,
  windowSeconds: 60,
};

/**
 * Checks a rate limit for the given identifier (e.g., IP address).
 *
 * Uses a sliding window counter in Upstash Redis.
 * Falls back to allowing all requests if Redis is not configured.
 *
 * @param identifier - Unique key for this rate limit (e.g., "auth:1.2.3.4")
 * @param config     - Limit and window configuration
 */
export async function checkRateLimit(
  identifier: string,
  config: RateLimitConfig = DEFAULTS
): Promise<RateLimitResult> {
  const restUrl = process.env.UPSTASH_REDIS_REST_URL;
  const restToken = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (!restUrl || !restToken) {
    // Rate limiting disabled — warn once per process in development
    if (process.env.NODE_ENV !== "production") {
      console.warn(
        "[RateLimit] Upstash Redis is not configured. " +
          "Rate limiting is DISABLED. Set UPSTASH_REDIS_REST_URL " +
          "and UPSTASH_REDIS_REST_TOKEN to enable it."
      );
    } else {
      console.error(
        "[RateLimit] UPSTASH_REDIS_REST_URL or UPSTASH_REDIS_REST_TOKEN " +
          "is not set in production. Rate limiting is DISABLED — " +
          "configure Upstash Redis immediately."
      );
    }

    return { success: true, remaining: config.limit, reset: 0 };
  }

  const key = `rate_limit:${identifier}`;
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - config.windowSeconds;

  try {
    // Use Upstash Redis REST API directly (no SDK dependency)
    // Pipeline: ZREMRANGEBYSCORE + ZADD + ZCARD + EXPIRE
    const pipeline = [
      ["ZREMRANGEBYSCORE", key, "0", windowStart.toString()],
      ["ZADD", key, now.toString(), `${now}-${Math.random()}`],
      ["ZCARD", key],
      ["EXPIRE", key, config.windowSeconds.toString()],
    ];

    const response = await fetch(`${restUrl}/pipeline`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${restToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(pipeline),
    });

    if (!response.ok) {
      console.error(
        `[RateLimit] Upstash Redis pipeline failed: ${response.status}`
      );
      // Fail open — allow the request
      return { success: true, remaining: config.limit, reset: 0 };
    }

    const results = await response.json();
    // results[2] is the ZCARD result (current count in window)
    const currentCount = results[2]?.result ?? 0;
    const remaining = Math.max(0, config.limit - currentCount);
    const reset = now + config.windowSeconds;

    return {
      success: currentCount <= config.limit,
      remaining,
      reset,
    };
  } catch (error) {
    console.error("[RateLimit] Unexpected error:", error);
    // Fail open — don't block users due to Redis failures
    return { success: true, remaining: config.limit, reset: 0 };
  }
}

// ---- Preset limits for specific operations -----------------

/** Rate limit for KGPian verification attempts */
export const KGPIAN_VERIFY_LIMIT: RateLimitConfig = {
  limit: 5,
  windowSeconds: 60,
};

/** Rate limit for the general auth endpoint */
export const AUTH_ENDPOINT_LIMIT: RateLimitConfig = {
  limit: 20,
  windowSeconds: 60,
};

/** Rate limit for Google OAuth initiations */
export const GOOGLE_OAUTH_LIMIT: RateLimitConfig = {
  limit: 10,
  windowSeconds: 60,
};
