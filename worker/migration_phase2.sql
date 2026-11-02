-- D1 Migration Phase 2: Enhanced Security (RBAC, Rate Limiting, Audit Logging)
-- Run with: wrangler d1 execute <DB_NAME> --file=migration_phase2.sql

-- Users table (Phase 1)
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'viewer',
  failed_attempts INTEGER DEFAULT 0,
  locked_until INTEGER,
  last_login INTEGER,
  created_at INTEGER NOT NULL
);

-- Audit log table (Phase 1)
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  details TEXT,
  ip TEXT,
  ts INTEGER NOT NULL
);

-- Rate limit tracking table (Phase 2)
CREATE TABLE IF NOT EXISTS rate_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  endpoint TEXT,
  count INTEGER DEFAULT 1,
  window_start INTEGER NOT NULL,
  UNIQUE(ip, endpoint)
);

-- Permissions table (Phase 2 - RBAC)
CREATE TABLE IF NOT EXISTS permissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role TEXT NOT NULL,
  permission TEXT NOT NULL,
  UNIQUE(role, permission)
);

-- Insert default permissions
INSERT OR IGNORE INTO permissions (role, permission) VALUES
  ('admin', 'read'),
  ('admin', 'write'),
  ('admin', 'delete'),
  ('admin', 'manage_users'),
  ('admin', 'view_audit'),
  ('admin', 'manage_passwords'),
  ('admin', 'export_data'),
  ('staff', 'read'),
  ('staff', 'write'),
  ('staff', 'export_data'),
  ('viewer', 'read');

-- Indexes
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip);
CREATE INDEX IF NOT EXISTS idx_permissions_role ON permissions(role);
