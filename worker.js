export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/verify" && request.method === "POST") {
      const body = await request.json();
      const key = body.key;

      if (!key) return json({ ok:false, error:"missing key" });

      const rec = await env.KEYS_DB.get("key:" + key);

      if (!rec) return json({ ok:false, error:"invalid key" });

      const data = JSON.parse(rec);

      if (data.banned) return json({ ok:false, error:"banned" });

      if (Date.now() > data.exp) return json({ ok:false, error:"expired" });

      return json({ ok:true });
    }

    return new Response("Server online 😈");
  }
};

function json(obj) {
  return new Response(JSON.stringify(obj), {
    headers: { "Content-Type": "application/json" }
  });
}
