-- D1 Migration Phase 3: Advanced Security (2FA, Encryption, Backups)
-- Run with: wrangler d1 execute <DB_NAME> --file=migration_phase3.sql

-- Add 2FA columns to users table
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0;

-- Backups table for automated backups
CREATE TABLE IF NOT EXISTS backups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL,
  data TEXT NOT NULL,
  ts INTEGER NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_backups_ts ON backups(ts);
CREATE INDEX IF NOT EXISTS idx_backups_key ON backups(key);
