// ============================================================
// src/types/database.ts
// Supabase database row types — mirrors the SQL schema exactly.
// ============================================================

export interface Profile {
  id: string; // UUID — equals auth.users.id
  email: string | null;
  name: string | null;
  phone: string | null;
  avatar_url: string | null;
  city: string | null;
  location: string | null;
  rating_avg: number;
  rating_count: number;
  /** Server-controlled: "user" | "moderator" | "admin" */
  role: "user" | "moderator" | "admin";
  /** True only for verified IIT KGP users. Set by the server. */
  is_kgp_user: boolean;
  /** True after identity verification. Set by the server. */
  is_verified: boolean;
  /** Normalized KGPian ID — null for non-KGP users. */
  kgpian_id: string | null;
  created_at: string;
  updated_at: string;
}

// Fields for inserting a new profile (server-controlled fields
// excluded so they cannot be injected by clients)
export interface ProfileInsert {
  id: string;
  email: string | null;
  is_kgp_user: boolean;
  kgpian_id?: string | null;
  name?: string | null;
  avatar_url?: string | null;
}

// Fields a user is allowed to update through the normal update path
export interface ProfileUpdate {
  name?: string | null;
  phone?: string | null;
  avatar_url?: string | null;
  city?: string | null;
  location?: string | null;
}

// Supabase client generic typing
export interface Database {
  public: {
    Tables: {
      profiles: {
        Row: Profile;
        Insert: ProfileInsert;
        Update: ProfileUpdate;
      };
    };
  };
}
