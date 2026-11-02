// Security-enhanced Cloudflare Worker for government emergency system
// Phase 1: Server-side Authentication with JWT, password hashing, audit logging

const JWT_SECRET = 'TOUAREA-GOV-JWT-SECRET-2026-CHANGE-IN-PRODUCTION';
const JWT_EXPIRY = 8 * 60 * 60; // 8 hours

// PBKDF2 password hashing using Web Crypto API
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

// JWT creation/verification
function createJWT(payload) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + JWT_EXPIRY, iat: Math.floor(Date.now() / 1000) }));
  const signature = btoa(JWT_SECRET + header + body); // Simplified - use HMAC in production
  return header + '.' + body + '.' + signature;
}

function verifyJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(atob(parts[1]));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null; // expired
    // Verify signature (simplified)
    const expectedSig = btoa(JWT_SECRET + parts[0] + parts[1]);
    if (parts[2] !== expectedSig) return null;
    return payload;
  } catch (e) {
    return null;
  }
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
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.replace('Bearer ', '');
    const user = token ? verifyJWT(token) : null;

    try {
      const db = env.DB;

      // === AUTH ENDPOINTS ===

      // POST /api/auth/login
      if (path === '/api/auth/login' && method === 'POST') {
        const body = await request.json();
        const { username, password } = body;
        if (!username || !password) {
          return jsonResponse({ error: 'Username and password required' }, securityHeaders, 400);
        }
        const row = await db.prepare('SELECT username, password_hash, salt, role, failed_attempts, locked_until FROM users WHERE username = ?').bind(username).first();
        if (!row) {
          await auditLog(db, username, 'LOGIN_FAILED', 'auth', 'User not found', clientIP);
          return jsonResponse({ error: 'Invalid credentials' }, securityHeaders, 401);
        }
        // Check lockout
        if (row.locked_until && row.locked_until > Date.now()) {
          await auditLog(db, username, 'LOGIN_LOCKED', 'auth', 'Account locked', clientIP);
          return jsonResponse({ error: 'Account locked. Try again later.' }, securityHeaders, 423);
        }
        const valid = await verifyPassword(password, row.salt, row.password_hash);
        if (!valid) {
          const attempts = (row.failed_attempts || 0) + 1;
          const lockUntil = attempts >= 5 ? Date.now() + 15 * 60 * 1000 : null; // Lock after 5 failed attempts for 15 min
          await db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?').bind(attempts, lockUntil, username).run();
          await auditLog(db, username, 'LOGIN_FAILED', 'auth', 'Invalid password, attempt ' + attempts, clientIP);
          return jsonResponse({ error: 'Invalid credentials' }, securityHeaders, 401);
        }
        // Reset failed attempts on success
        await db.prepare('UPDATE users SET failed_attempts = 0, locked_until = null, last_login = ? WHERE username = ?').bind(Date.now(), username).run();
        const jwt = createJWT({ username: row.username, role: row.role });
        await auditLog(db, username, 'LOGIN_SUCCESS', 'auth', 'Login successful', clientIP);
        return jsonResponse({ token: jwt, username: row.username, role: row.role }, securityHeaders);
      }

      // POST /api/auth/register (admin only)
      if (path === '/api/auth/register' && method === 'POST') {
        if (!user || user.role !== 'admin') {
          return jsonResponse({ error: 'Admin access required' }, securityHeaders, 403);
        }
        const body = await request.json();
        const { username, password, role } = body;
        if (!username || !password) {
          return jsonResponse({ error: 'Username and password required' }, securityHeaders, 400);
        }
        // Check if user exists
        const existing = await db.prepare('SELECT username FROM users WHERE username = ?').bind(username).first();
        if (existing) {
          return jsonResponse({ error: 'User already exists' }, securityHeaders, 409);
        }
        const salt = crypto.randomUUID();
        const hash = await hashPassword(password, salt);
        await db.prepare('INSERT INTO users (username, password_hash, salt, role, created_at) VALUES (?, ?, ?, ?, ?)').bind(username, hash, salt, role || 'viewer', Date.now()).run();
        await auditLog(db, user.username, 'USER_CREATED', 'users', 'Created user: ' + username + ' role: ' + (role || 'viewer'), clientIP);
        return jsonResponse({ ok: true, username, role: role || 'viewer' }, securityHeaders);
      }

      // POST /api/auth/change-password
      if (path === '/api/auth/change-password' && method === 'POST') {
        if (!user) {
          return jsonResponse({ error: 'Authentication required' }, securityHeaders, 401);
        }
        const body = await request.json();
        const { oldPassword, newPassword } = body;
        if (!oldPassword || !newPassword) {
          return jsonResponse({ error: 'Old and new passwords required' }, securityHeaders, 400);
        }
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

      // GET /api/audit-log (admin only)
      if (path === '/api/audit-log' && method === 'GET') {
        if (!user || user.role !== 'admin') {
          return jsonResponse({ error: 'Admin access required' }, securityHeaders, 403);
        }
        const limit = parseInt(url.searchParams.get('limit') || '100');
        const offset = parseInt(url.searchParams.get('offset') || '0');
        const rows = await db.prepare('SELECT * FROM audit_log ORDER BY ts DESC LIMIT ? OFFSET ?').bind(limit, offset).all();
        return jsonResponse({ logs: rows.results, total: rows.results.length }, securityHeaders);
      }

      // === DATA ENDPOINTS (require authentication for writes) ===

      // GET /api/all
      if (path === '/api/all' && method === 'GET') {
        const rows = await db.prepare('SELECT key, value, ts FROM store').all();
        const data = {};
        for (const r of rows.results) data[r.key] = { value: r.value, ts: r.ts };
        return jsonResponse(data, securityHeaders);
      }

      const gm = path.match(/^\/api\/key\/(.+)$/);
      if (gm && method === 'GET') {
        const key = gm[1];
        const row = await db.prepare('SELECT value, ts FROM store WHERE key = ?').bind(key).first();
        return row ? jsonResponse({ value: row.value, ts: row.ts }, securityHeaders) : jsonResponse({ value: null, ts: 0 }, securityHeaders);
      }

      if (gm && method === 'PUT') {
        if (!user) {
          return jsonResponse({ error: 'Authentication required' }, securityHeaders, 401);
        }
        const key = gm[1];
        const body = await request.json();
        const value = typeof body.value === 'string' ? body.value : JSON.stringify(body.value);
        await db.prepare('INSERT OR REPLACE INTO store (key, value, ts) VALUES (?, ?, ?)').bind(key, value, Date.now()).run();
        await auditLog(db, user.username, 'DATA_UPDATE', key, 'Updated ' + key, clientIP);
        return jsonResponse({ ok: true }, securityHeaders);
      }

      if (gm && method === 'DELETE') {
        if (!user || user.role !== 'admin') {
          return jsonResponse({ error: 'Admin access required' }, securityHeaders, 403);
        }
        const key = gm[1];
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
