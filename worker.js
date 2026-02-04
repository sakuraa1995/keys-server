export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ✅ CORS preflight
    if (request.method === "OPTIONS") {
      return cors(new Response(null, { status: 204 }));
    }

    // ✅ Health check (pour voir si KV est bien bind)
    if (url.pathname === "/health") {
      return cors(json({
        ok: true,
        hasKV: !!env.KEYS_DB,
        now: Date.now()
      }, 200));
    }

    // ✅ Home
    if (url.pathname === "/" && request.method === "GET") {
      return cors(new Response("Server online 😈", { status: 200 }));
    }

    // ✅ Verify
    if (url.pathname === "/verify" && request.method === "POST") {
      try {
        if (!env.KEYS_DB) {
          return cors(json({ ok:false, error:"no_kv_binding", hint:"Vérifie Bindings -> KV -> KEYS_DB" }, 500));
        }

        const body = await request.json().catch(() => ({}));
        const key = String(body.key || "").trim();
        if (!key) return cors(json({ ok:false, error:"missing_key" }, 400));

        const raw = await env.KEYS_DB.get(`key:${key}`);
        if (!raw) return cors(json({ ok:false, error:"invalid" }, 401));

        let rec;
        try {
          rec = JSON.parse(raw);
        } catch (e) {
          return cors(json({
            ok:false,
            error:"bad_json_in_kv",
            hint:"La VALUE KV doit être un JSON valide, ex: {\"banned\":false,\"exp\":1893456000000}",
            raw
          }, 500));
        }

        if (rec.banned) return cors(json({ ok:false, error:"banned" }, 403));
        if (typeof rec.exp === "number" && Date.now() > rec.exp) return cors(json({ ok:false, error:"expired" }, 403));

        const token = crypto.randomUUID().replace(/-/g, "");
        await env.KEYS_DB.put(`token:${token}`, "1", { expirationTtl: 2 * 60 * 60 }); // 2h

        return cors(json({ ok:true, token }, 200));
      } catch (e) {
        return cors(json({ ok:false, error:"server_error", detail: String(e?.message || e) }, 500));
      }
    }

    // ✅ Menu
    if (url.pathname === "/menu" && request.method === "GET") {
      try {
        if (!env.KEYS_DB) return cors(json({ ok:false, error:"no_kv_binding" }, 500));

        const auth = request.headers.get("Authorization") || "";
        const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
        if (!token) return cors(json({ ok:false, error:"missing_token" }, 401));

        const ok = await env.KEYS_DB.get(`token:${token}`);
        if (!ok) return cors(json({ ok:false, error:"bad_token" }, 401));

        return cors(json({
          ok: true,
          title: "😈 CHEAT MENU",
          items: [
            { id:"snow", label:"Neige ❄️", type:"toggle", value:true }
          ]
        }, 200));
      } catch (e) {
        return cors(json({ ok:false, error:"server_error", detail: String(e?.message || e) }, 500));
      }
    }

    return cors(json({ ok:false, error:"not_found", path:url.pathname }, 404));
  }
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}

function cors(res) {
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  h.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  h.set("Access-Control-Max-Age", "86400");
  return new Response(res.body, { status: res.status, headers: h });
}
