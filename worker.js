export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // Ping serveur
    if (url.pathname === "/") {
      return new Response("Server online 😈");
    }

    // Vérification clé
    if (url.pathname === "/verify" && req.method === "POST") {
      try {
        const body = await req.json();
        const key = String(body.key || "").trim();

        if (!key) {
          return json({ ok: false, error: "missing key" });
        }

        // 👉 KV lookup
        const data = await env.KEYS_DB.get(`key:${key}`);

        if (!data) {
          return json({ ok: false, error: "not found" });
        }

        const parsed = JSON.parse(data);

        if (parsed.banned) {
          return json({ ok: false, error: "banned" });
        }

        if (Date.now() > parsed.exp) {
          return json({ ok: false, error: "expired" });
        }

        // Token simple
        const token = btoa(key + ":" + Date.now());

        return json({
          ok: true,
          token
        });

      } catch (e) {
        return json({ ok: false, error: "server error" });
      }
    }

    // Menu fake pour test
    if (url.pathname === "/menu") {
      return new Response(`
        <html>
        <body style="background:black;color:white;font-size:40px;">
        ✅ MENU LOADED 😈
        </body>
        </html>
      `, { headers: { "content-type": "text/html" } });
    }

    return new Response("404", { status: 404 });
  }
};

function json(obj) {
  return new Response(JSON.stringify(obj), {
    headers: { "content-type": "application/json" }
  });
}
