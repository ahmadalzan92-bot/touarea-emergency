export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

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

    if (method === 'OPTIONS') {
      return new Response(null, { headers: securityHeaders });
    }

    const apiKey = request.headers.get('X-API-Key') || (request.headers.get('Authorization') || '').replace('Bearer ', '');
    const validApiKey = env.API_KEY || 'TOUAREA-GOV-2026-SECURE-KEY';
    const isWrite = method === 'PUT' || method === 'DELETE' || method === 'POST';
    if (isWrite && apiKey !== validApiKey) {
      return new Response(JSON.stringify({ error: 'Unauthorized: Invalid or missing API key' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json; charset=utf-8', ...securityHeaders }
      });
    }

    try {
      const db = env.DB;

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
        const key = gm[1];
        const body = await request.json();
        const value = typeof body.value === 'string' ? body.value : JSON.stringify(body.value);
        await db.prepare('INSERT OR REPLACE INTO store (key, value, ts) VALUES (?, ?, ?)').bind(key, value, Date.now()).run();
        return jsonResponse({ ok: true }, securityHeaders);
      }

      if (gm && method === 'DELETE') {
        const key = gm[1];
        await db.prepare('DELETE FROM store WHERE key = ?').bind(key).run();
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
