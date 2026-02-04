export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ✅ CORS preflight (obligatoire sur iOS)
    if (request.method === "OPTIONS") {
      return cors(new Response(null, { status: 204 }));
    }

    // ✅ HOME
    if (url.pathname === "/" && request.method === "GET") {
      return cors(new Response("Server online 😈", { status: 200 }));
    }

    // ✅ VERIFY KEY -> TOKEN (2h)
    if (url.pathname === "/verify" && request.method === "POST") {
      try {
        const body = await request.json().catch(() => ({}));
        const key = String(body.key || "").trim();

        if (!key) return cors(json({ ok: false, error: "missing_key" }, 400));

        // On stocke dans KV sous la forme: key:TEST-1234
        const raw = await env.KEYS_DB.get(`key:${key}`);
        if (!raw) return cors(json({ ok: false, error: "invalid" }, 401));

        let rec;
        try {
          rec = JSON.parse(raw);
        } catch {
          return cors(json({ ok: false, error: "bad_record" }, 500));
        }

        if (rec.banned) return cors(json({ ok: false, error: "banned" }, 403));
        if (typeof rec.exp === "number" && Date.now() > rec.exp) {
          return cors(json({ ok: false, error: "expired" }, 403));
        }

        // Token 2h
        const token = crypto.randomUUID().replace(/-/g, "");
        await env.KEYS_DB.put(`token:${token}`, "1", { expirationTtl: 2 * 60 * 60 });

        return cors(json({ ok: true, token }, 200));
      } catch (e) {
        return cors(json({ ok: false, error: "server_error" }, 500));
      }
    }

    // ✅ MENU JSON (protégé par token)
    if (url.pathname === "/menu" && request.method === "GET") {
      const auth = request.headers.get("Authorization") || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";

      if (!token) return cors(json({ ok: false, error: "missing_token" }, 401));

      const ok = await env.KEYS_DB.get(`token:${token}`);
      if (!ok) return cors(json({ ok: false, error: "bad_token" }, 401));

      // ⚙️ Ton menu (tu peux modifier ici)
      return cors(
        json(
          {
            ok: true,
            title: "😈 CHEAT MENU",
            theme: "blue",
            items: [
              { id: "snow", label: "Neige ❄️", type: "toggle", value: true },
              { id: "glow", label: "Glow UI ✨", type: "toggle", value: true },
              {
                id: "color",
                label: "Couleur 🎨",
                type: "select",
                options: ["Bleu", "Rouge", "Violet"],
                value: "Bleu"
              },
              { id: "alpha", label: "Opacité", type: "range", min: 0.2, max: 1, step: 0.05, value: 0.92 }
            ]
          },
          200
        )
      );
    }

    return cors(json({ ok: false, error: "not_found" }, 404));
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
