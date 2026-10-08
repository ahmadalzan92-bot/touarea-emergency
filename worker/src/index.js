export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, PUT, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      const db = env.DB;

      // GET /api/all — كل بيانات التخزين (المزامنة الكاملة عند فتح النظام)
      if (path === '/api/all' && method === 'GET') {
        const rows = await db.prepare('SELECT key, value, ts FROM store').all();
        const data = {};
        for (const r of rows.results) data[r.key] = { value: r.value, ts: r.ts };
        return j(data, corsHeaders);
      }

      // GET /api/key/:key — قراءة مفتاح واحد
      const gm = path.match(/^\/api\/key\/(.+)$/);
      if (gm && method === 'GET') {
        const key = gm[1];
        const row = await db.prepare('SELECT value, ts FROM store WHERE key = ?').bind(key).first();
        return row ? j({ value: row.value, ts: row.ts }, corsHeaders) : j({ value: null, ts: 0 }, corsHeaders);
      }

      // PUT /api/key/:key — كتابة مفتاح واحد (upsert)
      if (gm && method === 'PUT') {
        const key = gm[1];
        const body = await request.json();
        const value = typeof body.value === 'string' ? body.value : JSON.stringify(body.value);
        await db.prepare('INSERT OR REPLACE INTO store (key, value, ts) VALUES (?, ?, ?)').bind(key, value, Date.now()).run();
        return j({ ok: true }, corsHeaders);
      }

      // DELETE /api/key/:key — حذف مفتاح
      if (gm && method === 'DELETE') {
        const key = gm[1];
        await db.prepare('DELETE FROM store WHERE key = ?').bind(key).run();
        return j({ ok: true }, corsHeaders);
      }

      return j({ error: 'Not found' }, corsHeaders, 404);
    } catch (e) {
      return j({ error: e.message }, corsHeaders, 500);
    }
  }
};

function j(data, headers = {}, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers }
  });
}