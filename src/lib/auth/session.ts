// ============================================================
// src/lib/auth/session.ts
// Server-side session helpers.
// ============================================================

import { createSupabaseServerClient } from "@/lib/supabase/server";
import type { User } from "@supabase/supabase-js";

/**
 * Returns the currently authenticated Supabase user, or null
 * if there is no active session.
 *
 * Uses getUser() (not getSession()) to validate the token against
 * Supabase Auth servers — never trusts a client-supplied JWT.
 */
export async function getCurrentUser(): Promise<User | null> {
  try {
    const supabase = await createSupabaseServerClient();
    const {
      data: { user },
      error,
    } = await supabase.auth.getUser();

    if (error || !user) return null;
    return user;
  } catch {
    return null;
  }
}

/**
 * Returns true if there is a valid authenticated session.
 */
export async function isAuthenticated(): Promise<boolean> {
  const user = await getCurrentUser();
  return user !== null;
}
