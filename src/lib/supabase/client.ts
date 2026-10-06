// ============================================================
// src/lib/supabase/client.ts
// Supabase browser client — for Client Components only.
// Auth itself happens server-side; this is for reading data.
// ============================================================

import { createBrowserClient } from "@supabase/ssr";
import type { Database } from "@/types/database";

let _client: ReturnType<typeof createBrowserClient<Database>> | null = null;

/**
 * Returns a singleton Supabase browser client.
 * Safe to call multiple times — returns the same instance.
 */
export function createSupabaseBrowserClient() {
  if (_client) return _client;

  _client = createBrowserClient<Database>(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  );

  return _client;
}
