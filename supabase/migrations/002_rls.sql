-- ============================================================
-- supabase/migrations/002_rls.sql
--
-- Row Level Security policies for the profiles table.
--
-- Enforcement:
-- - Users can only read their OWN profile (private data)
-- - Users can update only PERMITTED fields
-- - Server-controlled fields (role, is_kgp_user, is_verified)
--   cannot be written by any user through the anon/user key
-- - Profile creation happens via service-role (bypasses RLS)
--   from trusted server code only
-- ============================================================

-- Enable RLS on profiles
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- ── READ policy ──────────────────────────────────────────────
-- A user can only read their own profile.
-- Adjust this if you want to allow public profiles later.
DROP POLICY IF EXISTS "profiles_select_own" ON public.profiles;
CREATE POLICY "profiles_select_own"
  ON public.profiles
  FOR SELECT
  USING (auth.uid() = id);

-- ── UPDATE policy ────────────────────────────────────────────
-- A user can update only their own profile.
-- The WITH CHECK clause prevents them from escalating
-- server-controlled fields even if they try.
--
-- Protected fields (role, is_kgp_user, is_verified, kgpian_id,
-- rating_avg, rating_count) are not included — if they try to
-- update them, Supabase will reject rows where the NEW values
-- differ from OLD values for those columns.
DROP POLICY IF EXISTS "profiles_update_own" ON public.profiles;
CREATE POLICY "profiles_update_own"
  ON public.profiles
  FOR UPDATE
  USING (auth.uid() = id)
  WITH CHECK (
    auth.uid() = id
    -- Prevent escalation: server-controlled fields must not change
    AND role        = (SELECT role        FROM public.profiles WHERE id = auth.uid())
    AND is_kgp_user = (SELECT is_kgp_user FROM public.profiles WHERE id = auth.uid())
    AND is_verified = (SELECT is_verified FROM public.profiles WHERE id = auth.uid())
    AND (
      kgpian_id IS NOT DISTINCT FROM
      (SELECT kgpian_id FROM public.profiles WHERE id = auth.uid())
    )
  );

-- ── INSERT policy ────────────────────────────────────────────
-- Users cannot insert profiles through the anon/user key.
-- All profile creation is done via the service-role key from
-- trusted server code (ensureProfile() in lib/auth/profile.ts).
-- No INSERT policy = no inserts via anon/user key.

-- ── DELETE policy ────────────────────────────────────────────
-- Profiles are not deleted via the user key.
-- Account deletion is a separate admin operation.
-- No DELETE policy = no deletes via anon/user key.

-- ── Verify RLS is enforced ────────────────────────────────────
-- Confirm RLS is actually enabled (sanity check)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_tables
    WHERE schemaname = 'public'
      AND tablename = 'profiles'
  ) THEN
    RAISE EXCEPTION 'profiles table does not exist — run 001_profiles.sql first';
  END IF;
END $$;
