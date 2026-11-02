-- D1 Migration Phase 4: Enterprise Security (Encryption, Monitoring, Backups)
-- Run with: wrangler d1 execute <DB_NAME> --file=migration_phase4.sql

-- Add session_version to users (for session invalidation)
ALTER TABLE users ADD COLUMN session_version INTEGER DEFAULT 0;

-- Backups table
CREATE TABLE IF NOT EXISTS backups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL,
  data TEXT NOT NULL,
  ts INTEGER NOT NULL
);

-- Security alerts table
CREATE TABLE IF NOT EXISTS security_alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_type TEXT NOT NULL,
  user TEXT,
  ip TEXT,
  details TEXT,
  ts INTEGER NOT NULL,
  acknowledged INTEGER DEFAULT 0
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_backups_ts ON backups(ts);
CREATE INDEX IF NOT EXISTS idx_backups_key ON backups(key);
CREATE INDEX IF NOT EXISTS idx_security_alerts_ts ON security_alerts(ts);
CREATE INDEX IF NOT EXISTS idx_security_alerts_type ON security_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_security_alerts_ack ON security_alerts(acknowledged);
