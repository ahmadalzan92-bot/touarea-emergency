// Phase 2: Enhanced Security - RBAC, Rate Limiting, Input Validation, Encryption
// Cloudflare Worker with advanced security features

const JWT_SECRET = 'TOUAREA-GOV-JWT-SECRET-2026-CHANGE-IN-PRODUCTION';
const JWT_EXPIRY = 8 * 60 * 60;
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
const RATE_LIMIT_MAX = 100; // 100 requests per minute per IP
const ENCRYPTION_KEY = 'TOUAREA-GOV-ENC-KEY-2026-CHANGE-IN-PRODUCTION';

// In-memory rate limit store (use KV in production for persistence)
const rateLimitStore = new Map();

// PBKDF2 password hashing
async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: enc.encode(salt),
    iterations: 100000,
    hash: 'SHA-256'
  }, keyMaterial, 256);
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

async function verifyPassword(password, salt, hash) {
  const computed = await hashPassword(password, salt);
  return computed === hash;
}

// JWT
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
  } catch (e) {
    return null;
  }
}

// AES-256-GCM encryption using Web Crypto API
async function encryptData(plaintext) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(ENCRYPTION_KEY), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('touarea-salt'), iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
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
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    return null;
  }
}

// Rate limiting
function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitStore.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW) {
    rateLimitStore.set(ip, { count: 1, windowStart: now });
    return true;
  }
  if (entry.count >= RATE_LIMIT_MAX) {
    return false;
  }
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
  if (typeof value === 'string' && value.length > 10 * 1024 * 1024) return false; // 10MB max
  return true;
}

// RBAC permissions
const PERMISSIONS = {
  admin: ['read', 'write', 'delete', 'manage_users', 'view_audit', 'manage_passwords'],
  staff: ['read', 'write'],
  viewer: ['read']
};

function hasPermission(role, permission) {
  const perms = PERMISSIONS[role] || [];
  return perms.includes(permission);
}

// Audit logging
async function auditLog(db, user, action, target, details, ip) {
  try {
    await db.prepare('INSERT INTO audit_log (user, action, target, details, ip, ts) VALUES (?, ?, ?, ?, ?, ?)').bind(
      user || 'anonymous', action, target || '', details || '', ip || '', Date.now()
    ).run();
  } catch (e) {
    console.error('Audit log error:', e.message);
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
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { headers: securityHeaders });
    }

    const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';

    // Rate limiting
    if (!checkRateLimit(clientIP)) {
      return new Response(JSON.stringify({ error: 'Rate limit exceeded. Try again later.' }), {
        status: 429,
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'Retry-After': '60', ...securityHeaders }
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
        const { username, password } = body;
        if (!username || !password) return jsonResponse({ error: 'Username and password required' }, securityHeaders, 400);
        const row = await db.prepare('SELECT username, password_hash, salt, role, failed_attempts, locked_until FROM users WHERE username = ?').bind(username).first();
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
        await db.prepare('UPDATE users SET failed_attempts = 0, locked_until = null, last_login = ? WHERE username = ?').bind(Date.now(), username).run();
        const jwt = createJWT({ username: row.username, role: row.role });
        await auditLog(db, username, 'LOGIN_SUCCESS', 'auth', 'Login successful', clientIP);
        return jsonResponse({ token: jwt, username: row.username, role: row.role }, securityHeaders);
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

      if (path === '/api/auth/me' && method === 'GET') {
        if (!user) return jsonResponse({ error: 'Not authenticated' }, securityHeaders, 401);
        return jsonResponse({ username: user.username, role: user.role }, securityHeaders);
      }

      if (path === '/api/audit-log' && method === 'GET') {
        if (!user || !hasPermission(user.role, 'view_audit')) return jsonResponse({ error: 'Admin access required' }, securityHeaders, 403);
        const limit = Math.min(parseInt(url.searchParams.get('limit') || '100'), 500);
        const offset = parseInt(url.searchParams.get('offset') || '0');
        const rows = await db.prepare('SELECT * FROM audit_log ORDER BY ts DESC LIMIT ? OFFSET ?').bind(limit, offset).all();
        return jsonResponse({ logs: rows.results }, securityHeaders);
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
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers }
  });
}
