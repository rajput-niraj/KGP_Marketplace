-- ============================================================
-- supabase/migrations/001_profiles.sql
--
-- Creates the profiles table.
-- Run this in the Supabase SQL Editor or via Supabase CLI.
--
-- IMPORTANT: profiles.id = auth.users.id (UUID foreign key)
-- Server-controlled fields (role, is_kgp_user, is_verified)
-- are NOT writable by users — enforced by RLS (002_rls.sql)
-- and the fact that insert happens via service-role only.
-- ============================================================

CREATE TABLE IF NOT EXISTS public.profiles (
  -- Identity
  id           UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email        TEXT,
  name         TEXT,
  phone        TEXT,
  avatar_url   TEXT,

  -- Location
  city         TEXT,
  location     TEXT,

  -- Ratings (updated by server, never directly by users)
  rating_avg   NUMERIC(3, 2) NOT NULL DEFAULT 0,
  rating_count INTEGER       NOT NULL DEFAULT 0,

  -- Server-controlled fields (NOT writable by users)
  role         TEXT NOT NULL DEFAULT 'user'
                 CHECK (role IN ('user', 'moderator', 'admin')),
  is_kgp_user  BOOLEAN NOT NULL DEFAULT false,
  is_verified  BOOLEAN NOT NULL DEFAULT false,

  -- KGPian identity (null for non-KGP users)
  -- Normalized (uppercase) when set.
  kgpian_id    TEXT UNIQUE,

  -- Timestamps
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast KGPian ID lookups
CREATE INDEX IF NOT EXISTS idx_profiles_kgpian_id
  ON public.profiles (kgpian_id)
  WHERE kgpian_id IS NOT NULL;

-- Index for email lookups
CREATE INDEX IF NOT EXISTS idx_profiles_email
  ON public.profiles (email)
  WHERE email IS NOT NULL;

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS profiles_set_updated_at ON public.profiles;
CREATE TRIGGER profiles_set_updated_at
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW
  EXECUTE FUNCTION public.set_updated_at();
