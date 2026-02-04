function cors(res) {
  const headers = new Headers(res.headers);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Headers", "*");
  headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  return new Response(res.body, { ...res, headers });
}

export default {
  async fetch(request, env) {

    if (request.method === "OPTIONS") {
      return cors(new Response(null, { status: 204 }));
    }

    const url = new URL(request.url);

    // health check
    if (url.pathname === "/health") {
      return cors(new Response(JSON.stringify({
        ok: true,
        hasKV: !!env.KEYS_DB,
        now: Date.now()
      }), { headers: { "content-type": "application/json" }}));
    }

    // check key
    if (url.pathname === "/check") {
      const key = url.searchParams.get("key");

      if (!key) {
        return cors(new Response(JSON.stringify({
          ok: false,
          error: "no key"
        }), { headers: { "content-type": "application/json" }}));
      }

      const raw = await env.KEYS_DB.get(key);

      if (!raw) {
        return cors(new Response(JSON.stringify({
          ok: false,
          error: "invalid"
        }), { headers: { "content-type": "application/json" }}));
      }

      const data = JSON.parse(raw);

      if (data.banned) {
        return cors(new Response(JSON.stringify({
          ok: false,
          error: "banned"
        }), { headers: { "content-type": "application/json" }}));
      }

      if (Date.now() > data.exp) {
        return cors(new Response(JSON.stringify({
          ok: false,
          error: "expired"
        }), { headers: { "content-type": "application/json" }}));
      }

      return cors(new Response(JSON.stringify({
        ok: true,
        valid: true
      }), { headers: { "content-type": "application/json" }}));
    }

    return cors(new Response("Server online 😈"));
  }
};
