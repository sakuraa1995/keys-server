export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") return cors(new Response("", { status: 204 }));

    if (url.pathname === "/" && request.method === "GET") {
      return cors(new Response("Server online 😈", { status: 200 }));
    }

    if (url.pathname === "/verify" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      const key = (body.key || "").trim();

      if (!key) return cors(json({ ok:false, error:"missing key" }));

      const recRaw = await env.KEYS_DB.get("key:" + key);
      if (!recRaw) return cors(json({ ok:false, error:"invalid" }));

      const rec = JSON.parse(recRaw);

      if (rec.banned) return cors(json({ ok:false, error:"banned" }));
      if (Date.now() > rec.exp) return cors(json({ ok:false, error:"expired" }));

      return cors(json({ ok:true }));
    }

    return cors(json({ ok:false, error:"not found" }));
  }
};

function json(obj) {
  return new Response(JSON.stringify(obj), {
    headers: { "Content-Type": "application/json" }
  });
}

function cors(res) {
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  h.set("Access-Control-Allow-Headers", "Content-Type");
  return new Response(res.body, { status: res.status, headers: h });
}
