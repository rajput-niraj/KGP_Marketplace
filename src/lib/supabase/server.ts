// ============================================================
// src/lib/supabase/server.ts
// Supabase client for Server Components, Route Handlers,
// and Server Actions. Uses next/headers cookies() for the
// session stored in secure HTTP-only cookies.
// ============================================================

import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";
import { createClient } from "@supabase/supabase-js";
import type { Database } from "@/types/database";

/**
 * Creates a Supabase client for server-side Next.js contexts.
 * Uses the anon key — RLS policies enforce access control.
 *
 * Must be called inside a Server Component / Route Handler /
 * Server Action (requires access to cookies()).
 */
export async function createSupabaseServerClient() {
  const cookieStore = await cookies();

  return createServerClient<Database>(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll();
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) => {
              cookieStore.set(name, value, options);
            });
          } catch {
            // Called from a Server Component — next refresh in middleware
            // will handle the updated session. This is intentional.
          }
        },
      },
    }
  );
}

/**
 * Creates a Supabase client with the service-role key.
 *
 * ⚠️  SECURITY: Bypasses RLS. Use ONLY in trusted server code for
 * operations that need privileged access (e.g., profile creation
 * triggered by auth, admin tasks). NEVER use in user-facing routes
 * that receive and act on untrusted user input without additional
 * server-side validation.
 *
 * Returns an untyped client — callers cast results as needed.
 * (Typed clients require Supabase CLI generated types.)
 */
export function createSupabaseServiceClient() {
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!serviceRoleKey) {
    throw new Error(
      "[Supabase] SUPABASE_SERVICE_ROLE_KEY is not configured. " +
        "Set it in .env.local (server-only)."
    );
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return createClient<any>(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    serviceRoleKey,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    }
  );
}
