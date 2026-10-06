// ============================================================
// src/lib/supabase/middleware.ts
// Session-refresh helper used exclusively in middleware.ts.
// Does NOT use next/headers (not available in Edge Runtime).
// ============================================================

import { createServerClient } from "@supabase/ssr";
import { type NextRequest, NextResponse } from "next/server";
import type { Database } from "@/types/database";
import type { User } from "@supabase/supabase-js";

export interface UpdateSessionResult {
  response: NextResponse;
  user: User | null;
}

/**
 * Refreshes the Supabase auth session within Next.js middleware.
 *
 * Must be called on every request that hits middleware so that:
 * - Expired tokens are refreshed before Server Components render
 * - Updated session cookies are forwarded to the browser
 *
 * Returns the (possibly modified) NextResponse and the current user.
 */
export async function updateSession(
  request: NextRequest
): Promise<UpdateSessionResult> {
  // Start with a pass-through response
  let supabaseResponse = NextResponse.next({ request });

  const supabase = createServerClient<Database>(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          // Write to both request (for downstream Server Components)
          // and to the response (for the browser to persist).
          cookiesToSet.forEach(({ name, value }) =>
            request.cookies.set(name, value)
          );
          supabaseResponse = NextResponse.next({ request });
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options)
          );
        },
      },
    }
  );

  // IMPORTANT: This call is what triggers the token refresh.
  // Do NOT remove it or replace it with getSession() — getUser()
  // validates the token against Supabase Auth servers.
  const {
    data: { user },
  } = await supabase.auth.getUser();

  return { response: supabaseResponse, user };
}
