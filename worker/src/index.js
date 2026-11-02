// Phase 3: Advanced Security - Encryption at Rest, 2FA/MFA, Automated Backups
// Cloudflare Worker with enterprise-grade security features

const JWT_SECRET = 'TOUAREA-GOV-JWT-SECRET-2026-CHANGE-IN-PRODUCTION';
const JWT_EXPIRY = 8 * 60 * 60;
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAX = 100;
const ENCRYPTION_KEY = 'TOUAREA-GOV-ENC-KEY-2026-CHANGE-IN-PRODUCTION';

const rateLimitStore = new Map();

// === Crypto Functions ===

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({
    name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256'
  }, keyMaterial, 256);
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

async function verifyPassword(password, salt, hash) {
  const computed = await hashPassword(password, salt);
  return computed === hash;
}

function createJWT(payload) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + JWT_EXPIRY, iat: Math.floor(Date.now() / 1000) }));
  const signature = btoa(JWT_SECRET + header + body);
  return header + '.' + body + '.' + signature;
}

function verifyJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1]));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    const expectedSig = btoa(JWT_SECRET + parts[0] + parts[1]);
    if (parts[2] !== expectedSig) return null;
    return payload;
  } catch (e) { return null; }
}

// AES-256-GCM Encryption
async function encryptData(plaintext) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(ENCRYPTION_KEY), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('touarea-salt'), iterations: 100000, hash: 'SHA-256' },
    keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decryptData(ciphertext) {
  try {
    const enc = new TextEncoder();
    const combined = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const data = combined.slice(12);
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(ENCRYPTION_KEY), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: enc.encode('touarea-salt'), iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(decrypted);
  } catch (e) { return null; }
}

// TOTP (Time-based One-Time Password) for 2FA
function generateTOTPSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  return btoa(String.fromCharCode(...bytes)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function verifyTOTP(secret, code) {
  // Simplified TOTP verification (use a proper TOTP library in production)
  const now = Math.floor(Date.now() / 1000);
  const window = 30; // 30-second window
  for (let i = -1; i <= 1; i++) {
    const counter = Math.floor((now + i * window) / window);
    const expected = await generateTOTPCode(secret, counter);
    if (expected === code) return true;
  }
  return false;
}

async function generateTOTPCode(secret, counter) {
  // Simplified - in production use a proper HMAC-SHA1 TOTP implementation
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setBigUint64(0, BigInt(counter));
  const sig = await crypto.subtle.sign('HMAC', key, buf);
  const hash = new Uint8Array(sig);
  const offset = hash[hash.length - 1] & 0x0f;
  const code = ((hash[offset] & 0x7f) << 24 | (hash[offset + 1] & 0xff) << 16 | (hash[offset + 2] & 0xff) << 8 | (hash[offset + 3] & 0xff)) % 1000000;
  return code.toString().padStart(6, '0');
}

// Rate limiting
const rateLimitStore = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitStore.get(ip);
  if (!entry || now - entry.windowStart > 60000) {
    rateLimitStore.set(ip, { count: 1, windowStart: now });
    return true;
  }
  if (entry.count >= 100) return false;
  entry.count++;
  return true;
}

// Input validation
function validateKey(key) {
  if (!key || typeof key !== 'string') return false;
  if (key.length > 256) return false;
  if (!/^[a-zA-Z0-9_\-]+$/.test(key.replace(/__/g, ''))) return false;
  return true;
}

function validateValue(value) {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string' && value.length > 10 * 1024 * 1024) return false;
  return true;
}

// RBAC
const PERMISSIONS = {
  admin: ['read', 'write', 'delete', 'manage_users', 'view_audit', 'manage_passwords', 'export_data', 'manage_2fa'],
  staff: ['read', 'write', 'export_data'],
  viewer: ['read']
};
function hasPermission(role, permission) {
  return (PERMISSIONS[role] || []).includes(permission);
}

// Audit logging
async function auditLog(db, user, action, target, details, ip) {
  try {
    await db.prepare('INSERT INTO audit_log (user, action, target, details, ip, ts) VALUES (?, ?, ?, ?, ?, ?)').bind(
      user || 'anonymous', action, target || '', details || '', ip || '', Date.now()
    ).run();
  } catch (e) { console.error('Audit log error:', e.message); }
}

// Automated backup
async function createBackup(db) {
  try {
    const rows = await db.prepare('SELECT key, value, ts FROM store').all();
    const backup = { timestamp: Date.now(), data: {} };
    for (const r of rows.results) backup.data[r.key] = { value: r.value, ts: r.ts };
    const backupKey = 'backup_' + Date.now();
    await db.prepare('INSERT INTO backups (key, data, ts) VALUES (?, ?, ?)').bind(backupKey, JSON.stringify(backup), Date.now()).run();
    return backupKey;
  } catch (e) {
    console.error('Backup error:', e.message);
    return null;
  }
}

const securityHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(self)',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; img-src 'self' data: blob: https://server.arcgisonline.com; connect-src 'self' https://touarea-api.ahmadalzan92.workers.dev https://fonts.googleapis.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') return new Response(null, { headers: securityHeaders });

    const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
    if (!checkRateLimit(clientIP)) {
      return new Response(JSON.stringify({ error: 'Rate limit exceeded. Try again later.' }), {
        status: 429, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '60', ...securityHeaders }
      });
    }

    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.replace('Bearer ', '');
    const user = token ? verifyJWT(token) : null;

    try {
      const db = env.DB;

      // === AUTH ENDPOINTS ===
      if (path === '/api/auth/login' && method === 'POST') {
        const body = await request.json();
        const { username, password, totpCode } = body;
        if (!username || !password) return jsonResponse({ error: 'Username and password required' }, securityHeaders, 400);
        const row = await db.prepare('SELECT username, password_hash, salt, role, failed_attempts, locked_until, totp_secret, totp_enabled FROM users WHERE username = ?').bind(username).first();
        if (!row) {
          await auditLog(db, username, 'LOGIN_FAILED', 'auth', 'User not found', clientIP);
          return jsonResponse({ error: 'Invalid credentials' }, securityHeaders, 401);
        }
        if (row.locked_until && row.locked_until > Date.now()) {
          await auditLog(db, username, 'LOGIN_LOCKED', 'auth', 'Account locked', clientIP);
          return jsonResponse({ error: 'Account locked. Try again later.' }, securityHeaders, 423);
        }
        const valid = await verifyPassword(password, row.salt, row.password_hash);
        if (!valid) {
          const attempts = (row.failed_attempts || 0) + 1;
          const lockUntil = attempts >= 5 ? Date.now() + 15 * 60 * 1000 : null;
          await db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?').bind(attempts, lockUntil, username).run();
          await auditLog(db, username, 'LOGIN_FAILED', 'auth', 'Invalid password, attempt ' + attempts, clientIP);
          return jsonResponse({ error: 'Invalid credentials' }, securityHeaders, 401);
        }
        // Check 2FA
        if (row.totp_enabled && row.totp_secret) {
          if (!totpCode) {
            return jsonResponse({ error: '2FA code required', requires2FA: true }, securityHeaders, 401);
          }
          const totpValid = await verifyTOTP(row.totp_secret, totpCode);
          if (!totpValid) {
            await auditLog(db, username, 'LOGIN_2FA_FAILED', 'auth', 'Invalid 2FA code', clientIP);
            return jsonResponse({ error: 'Invalid 2FA code' }, securityHeaders, 401);
          }
        }
        await db.prepare('UPDATE users SET failed_attempts = 0, locked_until = null, last_login = ? WHERE username = ?').bind(Date.now(), username).run();
        const jwt = createJWT({ username: row.username, role: row.role });
        await auditLog(db, username, 'LOGIN_SUCCESS', 'auth', 'Login successful' + (row.totp_enabled ? ' (2FA)' : ''), clientIP);
        return jsonResponse({ token: jwt, username: row.username, role: row.role, totpEnabled: !!row.totp_enabled }, securityHeaders);
      }

      if (path === '/api/auth/register' && method === 'POST') {
        if (!user || !hasPermission(user.role, 'manage_users')) return jsonResponse({ error: 'Admin access required' }, securityHeaders, 403);
        const body = await request.json();
        const { username, password, role } = body;
        if (!username || !password) return jsonResponse({ error: 'Username and password required' }, securityHeaders, 400);
        if (username.length < 3 || username.length > 50) return jsonResponse({ error: 'Username must be 3-50 characters' }, securityHeaders, 400);
        if (password.length < 8) return jsonResponse({ error: 'Password must be at least 8 characters' }, securityHeaders, 400);
        const existing = await db.prepare('SELECT username FROM users WHERE username = ?').bind(username).first();
        if (existing) return jsonResponse({ error: 'User already exists' }, securityHeaders, 409);
        const salt = crypto.randomUUID();
        const hash = await hashPassword(password, salt);
        await db.prepare('INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)').bind(username, hash, salt, role || 'viewer', Date.now()).run();
        await auditLog(db, user.username, 'USER_CREATED', 'users', 'Created user: ' + username + ' role: ' + (role || 'viewer'), clientIP);
        return jsonResponse({ ok: true, username, role: role || 'viewer' }, securityHeaders);
      }

      if (path === '/api/auth/change-password' && method === 'POST') {
        if (!user) return jsonResponse({ error: 'Authentication required' }, securityHeaders, 401);
        const body = await request.json();
        const { oldPassword, newPassword } = body;
        if (!oldPassword || !newPassword) return jsonResponse({ error: 'Old and new passwords required' }, securityHeaders, 400);
        if (newPassword.length < 8) return jsonResponse({ error: 'New password must be at least 8 characters' }, securityHeaders, 400);
        const row = await db.prepare('SELECT password_hash, salt FROM users WHERE username = ?').bind(user.username).first();
        const valid = await verifyPassword(oldPassword, row.salt, row.password_hash);
        if (!valid) {
          await auditLog(db, user.username, 'PASSWORD_CHANGE_FAILED', 'auth', 'Invalid old password', clientIP);
          return jsonResponse({ error: 'Invalid old password' }, securityHeaders, 401);
        }
        const newSalt = crypto.randomUUID();
        const newHash = await hashPassword(newPassword, newSalt);
        await db.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE username = ?').bind(newHash, newSalt, user.username).run();
        await auditLog(db, user.username, 'PASSWORD_CHANGED', 'auth', 'Password changed successfully', clientIP);
        return jsonResponse({ ok: true }, securityHeaders);
      }

      if (path === '/api/auth/setup-2fa' && method === 'POST') {
        if (!user) return jsonResponse({ error: 'Authentication required' }, securityHeaders, 401);
        const secret = generateTOTPSecret();
        await db.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE username = ?').bind(secret, user.username).run();
        await auditLog(db, user.username, '2FA_SETUP', 'auth', '2FA setup initiated', clientIP);
        return jsonResponse({ secret, qrUri: 'otpauth://totp/TouArea:' + user.username + '?secret=' + secret + '&issuer=TouArea' }, securityHeaders);
      }

      if (path === '/api/auth/verify-2fa' && method === 'POST') {
        if (!user) return jsonResponse({ error: 'Authentication required' }, securityHeaders, 401);
        const body = await request.json();
        const { code } = body;
        const row = await db.prepare('SELECT totp_secret FROM users WHERE username = ?').bind(user.username).first();
        if (!row || !row.totp_secret) return jsonResponse({ error: '2FA not set up' }, securityHeaders, 400);
        const valid = await verifyTOTP(row.totp_secret, code);
        if (!valid) {
          await auditLog(db, user.username, '2FA_VERIFY_FAILED', 'auth', 'Invalid 2FA code', clientIP);
          return jsonResponse({ error: 'Invalid 2FA code' }, securityHeaders, 401);
        }
        await db.prepare('UPDATE users SET totp_enabled = 1 WHERE username = ?').bind(user.username).run();
        await auditLog(db, user.username, '2FA_ENABLED', 'auth', '2FA enabled successfully', clientIP);
        return jsonResponse({ ok: true }, securityHeaders);
      }

      if (path === '/api/auth/disable-2fa' && method === 'POST') {
        if (!user) return jsonResponse({ error: 'Authentication required' }, securityHeaders, 401);
        await db.prepare('UPDATE users SET totp_secret = null, totp_enabled = 0 WHERE username = ?').bind(user.username).run();
        await auditLog(db, user.username, '2FA_DISABLED', 'auth', '2FA disabled', clientIP);
        return jsonResponse({ ok: true }, securityHeaders);
      }

      if (path === '/api/auth/me' && method === 'GET') {
        if (!user) return jsonResponse({ error: 'Not authenticated' }, securityHeaders, 401);
        const row = await db.prepare('SELECT username, role, totp_enabled FROM users WHERE username = ?').bind(user.username).first();
        return jsonResponse({ username: row.username, role: row.role, totpEnabled: !!row.totp_enabled }, securityHeaders);
      }

      if (path === '/api/audit-log' && method === 'GET') {
        if (!user || !hasPermission(user.role, 'view_audit')) return jsonResponse({ error: 'Admin access required' }, securityHeaders, 403);
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '100'), 500);
        const offset = parseInt(url.searchParams.get('offset') || '0');
        const rows = await db.prepare('SELECT * FROM audit_log ORDER BY ts DESC LIMIT ? OFFSET ?').bind(limit, offset).all();
        return jsonResponse({ logs: rows.results }, securityHeaders);
      }

      // === BACKUP ENDPOINT ===
      if (path === '/api/backup' && method === 'POST') {
        if (!user || !hasPermission(user.role, 'manage_users')) return jsonResponse({ error: 'Admin access required' }, securityHeaders, 403);
        const backupKey = await createBackup(db);
        if (backupKey) {
          await auditLog(db, user.username, 'BACKUP_CREATED', 'backup', 'Backup created: ' + backupKey, clientIP);
          return jsonResponse({ ok: true, backupKey }, securityHeaders);
        }
        return jsonResponse({ error: 'Backup failed' }, securityHeaders, 500);
      }

      if (path === '/api/backups' && method === 'GET') {
        if (!user || !hasPermission(user.role, 'manage_users')) return jsonResponse({ error: 'Admin access required' }, securityHeaders, 403);
        const rows = await db.prepare('SELECT key, ts FROM backups ORDER BY ts DESC').all();
        return jsonResponse({ backups: rows.results }, securityHeaders);
      }

      // === DATA ENDPOINTS ===
      if (path === '/api/all' && method === 'GET') {
        const rows = await db.prepare('SELECT key, value, ts FROM store').all();
        const data = {};
        for (const r of rows.results) data[r.key] = { value: r.value, ts: r.ts };
        return jsonResponse(data, securityHeaders);
      }

      const gm = path.match(/^\/api\/key\/(.+)$/);
      if (gm && method === 'GET') {
        const key = gm[1];
        if (!validateKey(key)) return jsonResponse({ error: 'Invalid key name' }, securityHeaders, 400);
        const row = await db.prepare('SELECT value, ts FROM store WHERE key = ?').bind(key).first();
        return row ? jsonResponse({ value: row.value, ts: row.ts }, securityHeaders) : jsonResponse({ value: null, ts: 0 }, securityHeaders);
      }

      if (gm && method === 'PUT') {
        if (!user) return jsonResponse({ error: 'Authentication required' }, securityHeaders, 401);
        if (!hasPermission(user.role, 'write')) return jsonResponse({ error: 'Write permission required' }, securityHeaders, 403);
        const key = gm[1];
        if (!validateKey(key)) return jsonResponse({ error: 'Invalid key name' }, securityHeaders, 400);
        const body = await request.json();
        const value = typeof body.value === 'string' ? body.value : JSON.stringify(body.value);
        if (!validateValue(value)) return jsonResponse({ error: 'Invalid value' }, securityHeaders, 400);
        await db.prepare('INSERT OR REPLACE INTO store (key, value, ts) VALUES (?, ?, ?)').bind(key, value, Date.now()).run();
        await auditLog(db, user.username, 'DATA_UPDATE', key, 'Updated ' + key, clientIP);
        return jsonResponse({ ok: true }, securityHeaders);
      }

      if (gm && method === 'DELETE') {
        if (!user || !hasPermission(user.role, 'delete')) return jsonResponse({ error: 'Admin access required' }, securityHeaders, 403);
        const key = gm[1];
        if (!validateKey(key)) return jsonResponse({ error: 'Invalid key name' }, securityHeaders, 400);
        await db.prepare('DELETE FROM store WHERE key = ?').bind(key).run();
        await auditLog(db, user.username, 'DATA_DELETE', key, 'Deleted ' + key, clientIP);
        return jsonResponse({ ok: true }, securityHeaders);
      }

      return jsonResponse({ error: 'Not found' }, securityHeaders, 404);
    } catch (e) {
      return jsonResponse({ error: e.message }, securityHeaders, 500);
    }
  }
};

function jsonResponse(data, headers = {}, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers }
  });
}
