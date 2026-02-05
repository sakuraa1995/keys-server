export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Preflight CORS
    if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));

    // Health
    if (url.pathname === "/health") {
      return cors(json({ ok: true, hasKV: !!env.KEYS_DB, now: Date.now() }, 200));
    }

    // Home
    if (url.pathname === "/" && request.method === "GET") {
      return cors(new Response("Server online 😈", { status: 200 }));
    }

    // =======================
    // ✅ USER CHECK
    // GET /check?key=XXXX
    // KV: key = "XXXX" ; value = {"banned":false,"exp":...}
    // =======================
    if (url.pathname === "/check" && request.method === "GET") {
      if (!env.KEYS_DB) return cors(json({ ok: false, error: "no_kv_binding" }, 500));

      const key = (url.searchParams.get("key") || "").trim();
      if (!key) return cors(json({ ok: false, error: "no_key" }, 400));

      const raw = await env.KEYS_DB.get(key);
      if (!raw) return cors(json({ ok: false, error: "invalid" }, 401));

      let rec;
      try { rec = JSON.parse(raw); }
      catch { return cors(json({ ok: false, error: "bad_json" }, 500)); }

      if (rec.banned) return cors(json({ ok: false, error: "banned" }, 403));
      if (typeof rec.exp === "number" && Date.now() > rec.exp) return cors(json({ ok: false, error: "expired" }, 403));

      return cors(json({ ok: true, valid: true, exp: rec.exp }, 200));
    }

    // =======================
    // 🔐 ADMIN PANEL PAGE
    // GET /admin
    // =======================
    if (url.pathname === "/admin" && request.method === "GET") {
      return new Response(adminHTML(), {
        status: 200,
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store"
        }
      });
    }

    // =======================
    // 🔐 ADMIN APIs (need x-admin header)
    // =======================
    if (url.pathname.startsWith("/admin/api/")) {
      if (!isAdmin(request, env)) return cors(json({ ok: false, error: "unauthorized" }, 401));
      if (!env.KEYS_DB) return cors(json({ ok: false, error: "no_kv_binding" }, 500));

      // POST /admin/api/create  { days, note? }
      if (url.pathname === "/admin/api/create" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const days = clampInt(body.days, 1, 3650, 30);
        const note = String(body.note || "").slice(0, 120);

        const key = genKey(4, 4); // XXXX-XXXX-XXXX-XXXX
        const exp = Date.now() + days * 86400000;

        const rec = {
          banned: false,
          exp,
          createdAt: Date.now(),
          note
        };

        await env.KEYS_DB.put(key, JSON.stringify(rec));
        await indexAdd(env, key);

        return cors(json({ ok: true, key, rec }, 200));
      }

      // GET /admin/api/list
      if (url.pathname === "/admin/api/list" && request.method === "GET") {
        const keys = await indexList(env);
        const out = [];
        for (const k of keys) {
          const raw = await env.KEYS_DB.get(k);
          if (!raw) continue;
          try {
            const rec = JSON.parse(raw);
            out.push({ key: k, ...rec });
          } catch {}
        }
        // Tri: plus récent d'abord
        out.sort((a,b) => (b.createdAt||0) - (a.createdAt||0));
        return cors(json({ ok: true, items: out }, 200));
      }

      // POST /admin/api/ban { key, banned:true/false }
      if (url.pathname === "/admin/api/ban" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const key = String(body.key || "").trim();
        const banned = !!body.banned;
        if (!key) return cors(json({ ok:false, error:"missing_key" }, 400));

        const raw = await env.KEYS_DB.get(key);
        if (!raw) return cors(json({ ok:false, error:"not_found" }, 404));

        const rec = safeParse(raw);
        if (!rec) return cors(json({ ok:false, error:"bad_json" }, 500));
        rec.banned = banned;

        await env.KEYS_DB.put(key, JSON.stringify(rec));
        return cors(json({ ok:true }, 200));
      }

      // POST /admin/api/extend { key, addDays }  (peut être négatif)
      if (url.pathname === "/admin/api/extend" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const key = String(body.key || "").trim();
        const addDays = Number(body.addDays || 0);
        if (!key) return cors(json({ ok:false, error:"missing_key" }, 400));

        const raw = await env.KEYS_DB.get(key);
        if (!raw) return cors(json({ ok:false, error:"not_found" }, 404));

        const rec = safeParse(raw);
        if (!rec) return cors(json({ ok:false, error:"bad_json" }, 500));

        const base = (typeof rec.exp === "number" ? rec.exp : Date.now());
        rec.exp = base + addDays * 86400000;

        await env.KEYS_DB.put(key, JSON.stringify(rec));
        return cors(json({ ok:true, exp: rec.exp }, 200));
      }

      // POST /admin/api/delete { key }
      if (url.pathname === "/admin/api/delete" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const key = String(body.key || "").trim();
        if (!key) return cors(json({ ok:false, error:"missing_key" }, 400));

        await env.KEYS_DB.delete(key);
        await indexRemove(env, key);

        return cors(json({ ok:true }, 200));
      }

      return cors(json({ ok:false, error:"not_found" }, 404));
    }

    return cors(json({ ok: false, error: "not_found", path: url.pathname }, 404));
  }
};

// ---------- Admin auth ----------
function isAdmin(request, env) {
  const secret = env.ADMIN_SECRET;
  const hdr = request.headers.get("x-admin") || "";
  return !!secret && hdr === secret;
}

// ---------- Helpers ----------
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
  h.set("Access-Control-Allow-Headers", "Content-Type, Authorization, x-admin");
  h.set("Access-Control-Max-Age", "86400");
  return new Response(res.body, { status: res.status, headers: h });
}

function safeParse(raw) {
  try { return JSON.parse(raw); } catch { return null; }
}

function clampInt(v, min, max, def) {
  const n = Math.floor(Number(v));
  if (!Number.isFinite(n)) return def;
  return Math.max(min, Math.min(max, n));
}

// Key generator: XXXX-XXXX-XXXX-XXXX (sans 0/O/I)
function genKey(groups = 4, per = 4) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = new Uint8Array(groups * per);
  crypto.getRandomValues(bytes);
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    s += chars[bytes[i] % chars.length];
    if ((i + 1) % per === 0 && i < bytes.length - 1) s += "-";
  }
  return s;
}

// ---------- KV index (pour lister les clés) ----------
const INDEX_KEY = "__keys_index__";

async function indexList(env) {
  const raw = await env.KEYS_DB.get(INDEX_KEY);
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

async function indexAdd(env, key) {
  const arr = await indexList(env);
  if (!arr.includes(key)) arr.push(key);
  await env.KEYS_DB.put(INDEX_KEY, JSON.stringify(arr));
}

async function indexRemove(env, key) {
  const arr = await indexList(env);
  const next = arr.filter(k => k !== key);
  await env.KEYS_DB.put(INDEX_KEY, JSON.stringify(next));
}

// ---------- Admin panel HTML ----------
function adminHTML() {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SP Admin</title>
<style>
  body{margin:0;background:#070a12;color:#e9f2ff;font-family:-apple-system,BlinkMacSystemFont,Arial}
  .wrap{max-width:980px;margin:0 auto;padding:16px}
  .card{background:rgba(12,16,30,.92);border:1px solid rgba(0,180,255,.25);border-radius:16px;box-shadow:0 18px 50px rgba(0,0,0,.5);padding:14px}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  input,select,button{border-radius:12px;border:1px solid rgba(255,255,255,.14);background:#0b122a;color:#e9f2ff;padding:10px 12px}
  button{font-weight:900;cursor:pointer}
  .btn{border:1px solid rgba(0,180,255,.35);background:rgba(0,180,255,.12)}
  .danger{border:1px solid rgba(255,80,80,.35);background:rgba(255,80,80,.12)}
  table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}
  th,td{padding:10px;border-top:1px solid rgba(255,255,255,.08);vertical-align:top}
  .muted{opacity:.65}
  .tag{display:inline-block;padding:3px 8px;border-radius:999px;border:1px solid rgba(255,255,255,.14);opacity:.85;font-size:12px}
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;">
        <div>
          <div style="font-weight:900;letter-spacing:.8px;">😈 SP-SPOOF ADMIN</div>
          <div class="muted" style="font-size:12px;margin-top:4px;">Génération & gestion des clés (KV)</div>
        </div>
      </div>

      <div style="height:10px"></div>

      <div class="row">
        <input id="secret" placeholder="ADMIN_SECRET (password)" type="password" style="flex:1;min-width:220px"/>
        <input id="days" placeholder="Jours" value="30" inputmode="numeric" style="width:110px"/>
        <input id="note" placeholder="Note (optionnel)" style="flex:1;min-width:200px"/>
        <button class="btn" id="create">➕ Générer</button>
        <button class="btn" id="refresh">🔄 Refresh</button>
      </div>

      <div style="height:10px"></div>

      <div id="out" class="muted" style="font-size:13px;"></div>

      <table id="tbl">
        <thead>
          <tr>
            <th>Clé</th>
            <th>Infos</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>

    </div>
  </div>

<script>
const api = (path, method="GET", body=null) => {
  const secret = document.getElementById("secret").value.trim();
  return fetch(path, {
    method,
    headers: {
      "Content-Type": "application/json",
      "x-admin": secret
    },
    body: body ? JSON.stringify(body) : null
  }).then(r => r.json());
};

const fmtDate = (ms) => {
  try { return new Date(ms).toLocaleString(); } catch { return String(ms); }
};

async function refresh() {
  const out = document.getElementById("out");
  out.textContent = "Loading...";
  const res = await api("/admin/api/list");
  if (!res.ok) { out.textContent = "❌ " + (res.error || "error"); return; }
  out.textContent = "✅ " + res.items.length + " clé(s)";
  const tbody = document.querySelector("#tbl tbody");
  tbody.innerHTML = "";

  for (const it of res.items) {
    const tr = document.createElement("tr");

    const tdKey = document.createElement("td");
    tdKey.innerHTML = "<div style='font-weight:900'>" + it.key + "</div>";
    tr.appendChild(tdKey);

    const tdInfo = document.createElement("td");
    tdInfo.innerHTML = \`
      <div class="muted">exp: <span class="tag">\${fmtDate(it.exp)}</span></div>
      <div class="muted">ban: <span class="tag">\${it.banned ? "YES" : "NO"}</span></div>
      <div class="muted">note: \${(it.note||"")}</div>
    \`;
    tr.appendChild(tdInfo);

    const tdAct = document.createElement("td");
    tdAct.className = "row";
    tdAct.style.gap = "8px";

    const banBtn = document.createElement("button");
    banBtn.className = it.banned ? "btn" : "danger";
    banBtn.textContent = it.banned ? "UNBAN" : "BAN";
    banBtn.onclick = async () => {
      await api("/admin/api/ban","POST",{ key: it.key, banned: !it.banned });
      refresh();
    };

    const addBtn = document.createElement("button");
    addBtn.className = "btn";
    addBtn.textContent = "+7j";
    addBtn.onclick = async () => {
      await api("/admin/api/extend","POST",{ key: it.key, addDays: 7 });
      refresh();
    };

    const subBtn = document.createElement("button");
    subBtn.className = "btn";
    subBtn.textContent = "-7j";
    subBtn.onclick = async () => {
      await api("/admin/api/extend","POST",{ key: it.key, addDays: -7 });
      refresh();
    };

    const delBtn = document.createElement("button");
    delBtn.className = "danger";
    delBtn.textContent = "DELETE";
    delBtn.onclick = async () => {
      if (!confirm("Supprimer la clé " + it.key + " ?")) return;
      await api("/admin/api/delete","POST",{ key: it.key });
      refresh();
    };

    tdAct.appendChild(banBtn);
    tdAct.appendChild(addBtn);
    tdAct.appendChild(subBtn);
    tdAct.appendChild(delBtn);
    tr.appendChild(tdAct);

    tbody.appendChild(tr);
  }
}

document.getElementById("create").onclick = async () => {
  const days = Number(document.getElementById("days").value || 30);
  const note = document.getElementById("note").value || "";
  const out = document.getElementById("out");
  out.textContent = "Creating...";
  const res = await api("/admin/api/create","POST",{ days, note });
  if (!res.ok) { out.textContent = "❌ " + (res.error || "error"); return; }
  out.textContent = "✅ Nouvelle clé: " + res.key;
  document.getElementById("note").value = "";
  refresh();
};

document.getElementById("refresh").onclick = refresh;

refresh();
</script>
</body>
</html>`;
}
