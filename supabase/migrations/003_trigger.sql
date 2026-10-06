-- ============================================================
-- supabase/migrations/003_trigger.sql
--
-- Optional: Auto-create a minimal profile row when a new
-- auth.users row is created (e.g., via Google OAuth or
-- email magic link).
--
-- This acts as a safety net — the main profile creation logic
-- is in lib/auth/profile.ts (ensureProfile), which sets all
-- fields correctly. This trigger only creates the skeleton.
--
-- Server-controlled fields (role, is_kgp_user, is_verified) use
-- their safe defaults (user / false / false).
-- They are later updated by server code if needed.
-- ============================================================

CREATE OR REPLACE FUNCTION public.handle_new_auth_user()
RETURNS TRIGGER
SECURITY DEFINER SET search_path = public
LANGUAGE plpgsql AS $$
BEGIN
  -- Only insert if a profile doesn't already exist
  -- (ensureProfile() may have already created it)
  INSERT INTO public.profiles (id, email, name, avatar_url)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(
      NEW.raw_user_meta_data->>'full_name',
      NEW.raw_user_meta_data->>'name'
    ),
    NEW.raw_user_meta_data->>'avatar_url'
  )
  ON CONFLICT (id) DO NOTHING;

  RETURN NEW;
END;
$$;

-- Attach trigger to auth.users
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_auth_user();

-- ── Security note ─────────────────────────────────────────────
-- The trigger runs as SECURITY DEFINER (elevated privileges) to
-- be able to insert into public.profiles from the auth schema.
-- It does NOT allow the user to set role, is_kgp_user, or
-- is_verified — those remain at their safe defaults until
-- trusted server code explicitly updates them.
