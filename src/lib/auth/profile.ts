// ============================================================
// src/lib/auth/profile.ts
// Server-side profile helpers.
// Uses the service-role client to bypass RLS for profile writes
// that happen as a direct result of verified authentication.
// ============================================================

import { createSupabaseServiceClient } from "@/lib/supabase/server";
import type { Profile, ProfileInsert } from "@/types/database";

export interface EnsureProfileOptions {
  userId: string;
  email: string | null;
  isKgpUser: boolean;
  kgpianId?: string | null;
  name?: string | null;
  avatarUrl?: string | null;
}

/**
 * Creates a profile for a newly authenticated user, or fetches
 * the existing profile if one already exists.
 *
 * Uses the service-role client because:
 * 1. RLS prevents the anon client from inserting profiles
 *    (only the trigger or service-role can write server fields)
 * 2. This function is ONLY called from trusted server code after
 *    the authentication provider has verified the identity
 *
 * ⚠️  Never call this from a route that accepts arbitrary user data
 *    without first verifying the authenticated user matches userId.
 */
export async function ensureProfile(
  options: EnsureProfileOptions
): Promise<Profile> {
  const { userId, email, isKgpUser, kgpianId, name, avatarUrl } = options;
  const serviceClient = createSupabaseServiceClient();

  // Check if profile already exists
  const { data: existing, error: fetchError } = await serviceClient
    .from("profiles")
    .select("*")
    .eq("id", userId)
    .single();

  if (fetchError && fetchError.code !== "PGRST116") {
    // PGRST116 = "Row not found" — that is expected for new users
    throw new Error(
      `[Profile] Failed to fetch profile for user ${userId}: ${fetchError.message}`
    );
  }

  if (existing) {
    return existing;
  }

  // Create a new profile
  const insertPayload: ProfileInsert = {
    id: userId,
    email,
    is_kgp_user: isKgpUser,
    kgpian_id: kgpianId ?? null,
    name: name ?? null,
    avatar_url: avatarUrl ?? null,
  };

  const { data: created, error: insertError } = await serviceClient
    .from("profiles")
    .insert(insertPayload)
    .select("*")
    .single();

  if (insertError || !created) {
    throw new Error(
      `[Profile] Failed to create profile for user ${userId}: ${insertError?.message}`
    );
  }

  return created;
}

/**
 * Fetches a profile by user ID using the service-role client.
 * Returns null if not found.
 */
export async function getProfileById(userId: string): Promise<Profile | null> {
  const serviceClient = createSupabaseServiceClient();

  const { data, error } = await serviceClient
    .from("profiles")
    .select("*")
    .eq("id", userId)
    .single();

  if (error) {
    if (error.code === "PGRST116") return null;
    throw new Error(`[Profile] Failed to fetch profile: ${error.message}`);
  }

  return data;
}

/**
 * Checks whether a profile with the given KGPian ID already exists.
 * Returns the profile if found, null otherwise.
 */
export async function getProfileByKgpianId(
  normalizedKgpianId: string
): Promise<Profile | null> {
  const serviceClient = createSupabaseServiceClient();

  const { data, error } = await serviceClient
    .from("profiles")
    .select("*")
    .eq("kgpian_id", normalizedKgpianId)
    .single();

  if (error) {
    if (error.code === "PGRST116") return null;
    throw new Error(
      `[Profile] Failed to query by KGPian ID: ${error.message}`
    );
  }

  return data;
}
