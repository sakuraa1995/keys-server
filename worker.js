export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const now = Date.now();

    // -------- helpers --------
    const withCors = (res) => {
      const h = new Headers(res.headers);
      h.set("Access-Control-Allow-Origin", "*");
      h.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
      h.set("Access-Control-Allow-Headers", "content-type, x-admin-secret");
      h.set("Access-Control-Max-Age", "86400");
      return new Response(res.body, { status: res.status, headers: h });
    };

    const json = (obj, status = 200) =>
      withCors(
        new Response(JSON.stringify(obj), {
          status,
          headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
        })
      );

    const html = (str, status = 200) =>
      withCors(
        new Response(str, {
          status,
          headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
        })
      );

    const kvKey = (k) => `KEY:${k}`;

    const randKey = () => {
      const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      const b = new Uint8Array(16);
      crypto.getRandomValues(b);
      let s = "";
      for (let i = 0; i < b.length; i++) s += alphabet[b[i] % alphabet.length];
      return `SP-${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}`;
    };

    const msToClock = (ms) => {
      if (ms == null) return "∞";
      ms = Math.max(0, Math.floor(ms));
      const s = Math.floor(ms / 1000);
      const d = Math.floor(s / 86400);
      const h = Math.floor((s % 86400) / 3600);
      const m = Math.floor((s % 3600) / 60);
      const sec = s % 60;
      const pad = (n) => String(n).padStart(2, "0");
      if (d > 0) return `${d}d ${pad(h)}:${pad(m)}:${pad(sec)}`;
      return `${pad(h)}:${pad(m)}:${pad(sec)}`;
    };

    const addLog = (rec, event, did, extra = {}) => {
      const item = { t: now, event, did: did || null, ...extra };
      rec.logs = Array.isArray(rec.logs) ? rec.logs : [];
      rec.logs.push(item);
      if (rec.logs.length > 10) rec.logs = rec.logs.slice(-10);
    };

    const isExpired = (rec) => typeof rec.exp === "number" && now >= rec.exp;

    const getSecret = async () => {
      if (request.method === "GET") {
        return request.headers.get("x-admin-secret") || url.searchParams.get("secret") || "";
      }
      const h = request.headers.get("x-admin-secret");
      if (h) return h;
      try {
        const body = await request.json();
        return body?.secret || "";
      } catch {
        return "";
      }
    };

    // -------- preflight --------
    if (request.method === "OPTIONS") return withCors(new Response("", { status: 204 }));

    // -------- health --------
    if (path === "/" || path === "/health") {
      return json({ ok: true, online: true, now, hasKV: !!env.KEYS_DB, hasSecret: !!env.ADMIN_SECRET });
    }

    // -------- admin panel --------
    if (path === "/admin" && request.method === "GET") {
      return html(ADMIN_HTML);
    }

    // =====================================================
    // ✅ PUBLIC CHECK (Stay)
    // GET /api/check?key=...&did=...
    // =====================================================
    if (path === "/api/check" && request.method === "GET") {
      if (!env.KEYS_DB) return json({ ok: false, reason: "kv_missing" }, 500);

      const key = (url.searchParams.get("key") || "").trim();
      const did = (url.searchParams.get("did") || "").trim();

      if (!key) return json({ ok: false, reason: "missing_key" }, 400);
      if (!did) return json({ ok: false, reason: "missing_device" }, 400);

      const raw = await env.KEYS_DB.get(kvKey(key));
      if (!raw) return json({ ok: false, reason: "not_found" }, 404);

      let rec;
      try {
        rec = JSON.parse(raw);
      } catch {
        return json({ ok: false, reason: "bad_record" }, 500);
      }

      rec.created = typeof rec.created === "number" ? rec.created : now;
      rec.banned = !!rec.banned;
      rec.uses = Number(rec.uses || 0) || 0;
      rec.note = typeof rec.note === "string" ? rec.note : "";
      rec.did = rec.did || null;
      rec.lockedAt = typeof rec.lockedAt === "number" ? rec.lockedAt : null;

      if (rec.banned) {
        addLog(rec, "blocked_banned", did);
        await env.KEYS_DB.put(kvKey(key), JSON.stringify(rec));
        return json({ ok: false, reason: "banned" }, 403);
      }

      if (isExpired(rec)) {
        addLog(rec, "blocked_expired", did);
        await env.KEYS_DB.put(kvKey(key), JSON.stringify(rec));
        return json({ ok: false, reason: "expired", exp: rec.exp }, 403);
      }

      // 🔒 1 DEVICE LOCK
      if (!rec.did) {
        rec.did = did;
        rec.lockedAt = now;
        addLog(rec, "first_lock", did);
      } else if (String(rec.did) !== String(did)) {
        // 🚨 share attempt
        addLog(rec, "share_attempt", did, { lockedDid: rec.did });
        await env.KEYS_DB.put(kvKey(key), JSON.stringify(rec));
        return json({ ok: false, reason: "device_mismatch", lockedAt: rec.lockedAt || null }, 403);
      }

      rec.uses += 1;
      addLog(rec, "login", did);

      await env.KEYS_DB.put(kvKey(key), JSON.stringify(rec));

      return json({
        ok: true,
        key,
        exp: rec.exp || null,
        remainingMs: rec.exp ? Math.max(0, rec.exp - now) : null,
        uses: rec.uses,
        did: rec.did,
      });
    }

    // =====================================================
    // ✅ ADMIN API (secret required)
    // =====================================================
    if (path.startsWith("/api/admin/")) {
      if (!env.KEYS_DB) return json({ ok: false, reason: "kv_missing" }, 500);
      if (!env.ADMIN_SECRET) return json({ ok: false, reason: "admin_secret_missing" }, 500);

      const secret = await getSecret();
      if (String(secret) !== String(env.ADMIN_SECRET)) return json({ ok: false, reason: "unauthorized" }, 401);

      // POST /api/admin/create  {days,count,note}
      if (path === "/api/admin/create" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const days = Math.max(1, Math.min(3650, Number(body.days || 30)));
        const count = Math.max(1, Math.min(50, Number(body.count || 1)));
        const note = String(body.note || "").slice(0, 120);

        const created = [];
        for (let i = 0; i < count; i++) {
          const key = randKey();
          const rec = {
            created: now,
            exp: now + days * 86400000,
            banned: false,
            uses: 0,
            note,
            did: null,
            lockedAt: null,
            logs: [],
          };
          addLog(rec, "created", null);
          await env.KEYS_DB.put(kvKey(key), JSON.stringify(rec));
          created.push({ key, exp: rec.exp, note });
        }
        return json({ ok: true, created, now });
      }

      // POST /api/admin/list {limit}
      if (path === "/api/admin/list" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const limit = Math.max(1, Math.min(800, Number(body.limit || 300)));

        const list = await env.KEYS_DB.list({ prefix: "KEY:", limit: 1000 });
        const items = [];

        for (const k of list.keys) {
          const raw = await env.KEYS_DB.get(k.name);
          if (!raw) continue;
          try {
            const d = JSON.parse(raw);
            items.push({
              key: k.name.replace(/^KEY:/, ""),
              created: typeof d.created === "number" ? d.created : null,
              exp: typeof d.exp === "number" ? d.exp : null,
              banned: !!d.banned,
              uses: Number(d.uses || 0) || 0,
              note: typeof d.note === "string" ? d.note : "",
              did: d.did || null,
              lockedAt: typeof d.lockedAt === "number" ? d.lockedAt : null,
              logs: Array.isArray(d.logs) ? d.logs : [],
            });
          } catch {}
          if (items.length >= limit) break;
        }

        // stats
        const stats = {
          total: items.length,
          active: items.filter((x) => !x.banned && (!x.exp || now < x.exp)).length,
          expired: items.filter((x) => x.exp && now >= x.exp).length,
          banned: items.filter((x) => x.banned).length,
          linked: items.filter((x) => !!x.did).length,
        };

        // newest first
        items.sort((a, b) => (b.created || 0) - (a.created || 0));

        return json({ ok: true, items, stats, now });
      }

      // POST /api/admin/ban {key,banned}
      if (path === "/api/admin/ban" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const key = String(body.key || "").trim();
        const banned = !!body.banned;
        if (!key) return json({ ok: false, reason: "missing_key" }, 400);

        const raw = await env.KEYS_DB.get(kvKey(key));
        if (!raw) return json({ ok: false, reason: "not_found" }, 404);

        const rec = JSON.parse(raw);
        rec.banned = banned;
        addLog(rec, banned ? "banned" : "unbanned", null);
        await env.KEYS_DB.put(kvKey(key), JSON.stringify(rec));
        return json({ ok: true, key, banned });
      }

      // POST /api/admin/delete {key}
      if (path === "/api/admin/delete" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const key = String(body.key || "").trim();
        if (!key) return json({ ok: false, reason: "missing_key" }, 400);

        await env.KEYS_DB.delete(kvKey(key));
        return json({ ok: true, key, deleted: true });
      }

      // POST /api/admin/reset {key}
      if (path === "/api/admin/reset" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const key = String(body.key || "").trim();
        if (!key) return json({ ok: false, reason: "missing_key" }, 400);

        const raw = await env.KEYS_DB.get(kvKey(key));
        if (!raw) return json({ ok: false, reason: "not_found" }, 404);

        const rec = JSON.parse(raw);
        rec.did = null;
        rec.lockedAt = null;
        addLog(rec, "reset_device", null);
        await env.KEYS_DB.put(kvKey(key), JSON.stringify(rec));

        return json({ ok: true, key, reset: true });
      }

      return json({ ok: false, reason: "unknown_admin_route" }, 404);
    }

    return json({ ok: false, reason: "not_found" }, 404);
  },
};

// =========================
// ✅ ADMIN PANEL (FULL UI)
// =========================
const ADMIN_HTML = `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SP-SPOOF ADMIN</title>
<style>
:root{
  --bg:#060912;
  --stroke:#1c2b55;
  --txt:#dbe6ff;
  --muted:#8ea7ffcc;
  --ok:#34d399;
  --bad:#fb7185;
  --warn:#fbbf24;
  --shadow: 0 14px 60px rgba(0,0,0,.55);
}
*{box-sizing:border-box}
body{
  margin:0; min-height:100vh; overflow-x:hidden;
  background:
    radial-gradient(1200px 700px at 20% 0%, #0a1c55 0%, transparent 55%),
    radial-gradient(900px 600px at 80% 10%, #3b0764 0%, transparent 55%),
    var(--bg);
  color:var(--txt);
  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
}
.wrap{max-width:1100px;margin:0 auto;padding:16px}
.card{
  position:relative;
  border:1px solid var(--stroke);
  background:linear-gradient(180deg, rgba(12,18,40,.88), rgba(7,10,20,.55));
  border-radius:18px;
  box-shadow:var(--shadow);
  padding:14px;
  overflow:hidden;
}
h1{margin:0 0 6px;font-size:20px;letter-spacing:.8px}
.sub{color:var(--muted);font-size:13px;margin-bottom:10px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input, button{
  border-radius:14px;
  border:1px solid var(--stroke);
  background:rgba(6,10,20,.72);
  color:var(--txt);
  padding:12px 12px;
  outline:none;
}
input::placeholder{color:#90a4ff66}
.btn{
  background:linear-gradient(180deg, rgba(244,63,94,.22), rgba(244,63,94,.06));
  border:1px solid rgba(244,63,94,.55);
  cursor:pointer;
  font-weight:900;
}
.btn2{
  background:linear-gradient(180deg, rgba(59,130,246,.32), rgba(59,130,246,.10));
  border:1px solid rgba(59,130,246,.55);
  cursor:pointer;
  font-weight:900;
}
.btnTiny{
  padding:8px 10px;border-radius:12px;font-size:13px;cursor:pointer;
  border:1px solid rgba(255,255,255,.14);
  background:rgba(10,18,40,.55);
}
.btnBad{
  padding:8px 10px;border-radius:12px;font-size:13px;cursor:pointer;
  border:1px solid rgba(244,63,94,.55);
  background:rgba(244,63,94,.10);
  font-weight:900;
}
.grow{flex:1}
.w140{width:140px}
.pill{
  display:inline-flex;align-items:center;gap:6px;
  padding:7px 10px;border-radius:999px;border:1px solid rgba(255,255,255,.10);
  background:rgba(10,18,40,.45);font-size:13px;color:var(--muted)
}
.ok{color:var(--ok)} .bad{color:var(--bad)} .warn{color:var(--warn)}
.hr{height:1px;background:rgba(255,255,255,.06);margin:12px 0}
table{width:100%;border-collapse:separate;border-spacing:0 10px}
th{font-size:12px;color:var(--muted);text-align:left;padding:0 10px}
td{padding:12px 10px;background:rgba(10,18,40,.52);border:1px solid rgba(28,43,85,.75);vertical-align:top}
td:first-child{border-radius:14px 0 0 14px}
td:last-child{border-radius:0 14px 14px 0}
.mono{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace}
.small{font-size:12px;color:var(--muted)}
.right{text-align:right}
.toast{
  position:fixed;left:50%;bottom:18px;transform:translateX(-50%);
  background:rgba(0,0,0,.65);border:1px solid rgba(255,255,255,.12);
  padding:10px 14px;border-radius:14px;backdrop-filter: blur(10px);
  display:none;z-index:9999;
}
.panel{
  display:grid;
  grid-template-columns: 1.4fr .9fr;
  gap:12px;
}
.box{
  border:1px solid rgba(255,255,255,.10);
  background:rgba(10,18,40,.42);
  border-radius:16px;
  padding:12px;
}
.logs{
  max-height:360px;
  overflow:auto;
  font-family: ui-monospace, Menlo, monospace;
  font-size:12px;
}
.logItem{padding:8px 8px;border-bottom:1px solid rgba(255,255,255,.06)}
.tag{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid rgba(255,255,255,.14);margin-right:6px}
.tagShare{border-color:rgba(244,63,94,.6);color:var(--bad)}
.tagLogin{border-color:rgba(52,211,153,.6);color:var(--ok)}
.tagInfo{border-color:rgba(59,130,246,.6);color:#9cc2ff}
.snow{position:fixed;inset:0;pointer-events:none;z-index:2;opacity:.9}

input, button { font-size: 16px; } /* anti zoom iOS */

@media (max-width: 900px){
  .panel{grid-template-columns:1fr}
}
@media (max-width: 520px){
  .wrap{padding:12px}
  table, thead, tbody, th, tr{display:block;width:100%}
  thead{display:none}
  tr{margin-bottom:10px}
  td{display:block;width:100%;border-radius:14px !important;margin-top:8px}
  td[data-label]::before{
    content: attr(data-label);
    display:block;font-size:12px;color:var(--muted);
    margin-bottom:6px;
  }
  .right{text-align:left}
}
</style>
</head>
<body>
<canvas class="snow" id="snow"></canvas>

<div class="wrap">
  <div class="card">
    <h1>😈 SP-SPOOF ADMIN</h1>
    <div class="sub">Keys • Device lock • Reset • Logs live • Share alert</div>

    <div class="row">
      <input id="secret" class="grow" placeholder="ADMIN_SECRET (mot de passe)" type="password"/>
      <button class="btn2" id="saveSecret">💾 Sauver</button>
      <button class="btn2" id="refresh">🔄 Refresh</button>
    </div>

    <div class="hr"></div>

    <div class="row">
      <input id="days" class="w140" type="number" value="30" min="1" max="3650"/>
      <input id="count" class="w140" type="number" value="1" min="1" max="50"/>
      <input id="note" class="grow" placeholder="Note (optionnel)"/>
      <button class="btn" id="gen">➕ Générer</button>
      <input id="search" class="grow" placeholder="Recherche clé / note / did..."/>
    </div>

    <div class="hr"></div>

    <div class="row">
      <span class="pill">Total: <b id="st_total">0</b></span>
      <span class="pill ok">Actives: <b id="st_active">0</b></span>
      <span class="pill warn">Expirées: <b id="st_expired">0</b></span>
      <span class="pill bad">Bannies: <b id="st_banned">0</b></span>
      <span class="pill">Linked: <b id="st_linked">0</b></span>
      <span class="pill">Live: <b id="st_live">ON</b></span>
    </div>

    <div class="hr"></div>

    <div class="panel">
      <div class="box">
        <div class="small">Clés</div>
        <table>
          <thead>
            <tr>
              <th>Key</th><th>Status</th><th>Device</th><th>Time</th><th class="right">Actions</th>
            </tr>
          </thead>
          <tbody id="rows"></tbody>
        </table>
      </div>

      <div class="box">
        <div class="row" style="justify-content:space-between">
          <div class="small">Logs live (global + clé sélectionnée)</div>
          <button class="btnTiny" id="toggleLive">⏸ Pause</button>
        </div>
        <div class="small" style="margin-top:6px">Sélection: <span class="mono" id="selKey">none</span></div>
        <div class="logs" id="logs"></div>
      </div>
    </div>

  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const $ = (id)=>document.getElementById(id);
const API = location.origin;

let live = true;
let cache = { items: [], now: Date.now(), stats: {} };
let selectedKey = "";

const toast = (msg)=>{
  const t=$("toast");
  t.textContent=msg;
  t.style.display="block";
  clearTimeout(toast._t);
  toast._t=setTimeout(()=>t.style.display="none",1500);
};

const msToClock = (ms)=>{
  if (ms==null) return "∞";
  ms = Math.max(0, ms|0);
  const s = Math.floor(ms/1000);
  const d = Math.floor(s/86400);
  const h = Math.floor((s%86400)/3600);
  const m = Math.floor((s%3600)/60);
  const sec = s%60;
  const pad=(n)=>String(n).padStart(2,"0");
  if(d>0) return d+"d "+pad(h)+":"+pad(m)+":"+pad(sec);
  return pad(h)+":"+pad(m)+":"+pad(sec);
};

const secretVal = ()=> $("secret").value.trim() || localStorage.getItem("SP_ADMIN_SECRET") || "";

const post = async (path, body)=>{
  const res = await fetch(API+path,{
    method:"POST",
    headers:{ "content-type":"application/json", "x-admin-secret": secretVal() },
    body: JSON.stringify(body||{})
  });
  const j = await res.json().catch(()=>({}));
  if(!res.ok || !j.ok) throw new Error(j.reason || "API error");
  return j;
};

$("saveSecret").onclick = ()=>{
  localStorage.setItem("SP_ADMIN_SECRET", $("secret").value.trim());
  toast("✅ secret saved");
};

$("toggleLive").onclick = ()=>{
  live = !live;
  $("st_live").textContent = live ? "ON" : "OFF";
  $("toggleLive").textContent = live ? "⏸ Pause" : "▶️ Live";
};

function statusOf(it){
  const expired = it.exp && cache.now >= it.exp;
  if(it.banned) return "⛔ banned";
  if(expired) return "⌛ expired";
  return "✅ active";
}

function deviceOf(it){
  return it.did ? ("📱 linked ("+ String(it.did).slice(0,10)+"…)") : "🟢 free";
}

function matchesSearch(it, q){
  if(!q) return true;
  const s = (it.key+" "+(it.note||"")+" "+(it.did||"")).toLowerCase();
  return s.includes(q);
}

function buildLogs(items){
  const out = [];
  for(const it of items){
    const logs = it.logs || [];
    for(const l of logs){
      out.push({ key: it.key, ...l });
    }
  }
  out.sort((a,b)=>(a.t||0)-(b.t||0));
  return out.slice(-25).reverse();
}

function renderLogs(){
  const box = $("logs");
  box.innerHTML = "";

  const all = buildLogs(cache.items);

  const filter = selectedKey ? all.filter(x=>x.key===selectedKey) : all;

  for(const l of filter){
    const div = document.createElement("div");
    div.className="logItem";

    let tagClass="tagInfo";
    if(l.event==="login" || l.event==="first_lock") tagClass="tagLogin";
    if(l.event==="share_attempt") tagClass="tagShare";

    div.innerHTML = \`
      <div>
        <span class="tag \${tagClass}">\${l.event}</span>
        <span class="mono">\${new Date(l.t).toLocaleTimeString()}</span>
      </div>
      <div class="small mono">\${selectedKey ? "" : ("KEY: "+l.key+" • ")}DID: \${(l.did||"").slice(0,18)}\${(l.did && l.did.length>18)?"…":""}</div>
    \`;
    box.appendChild(div);
  }
}

function render(){
  const q = ($("search").value||"").trim().toLowerCase();
  const rows = $("rows");
  rows.innerHTML = "";

  const items = cache.items.filter(it=>matchesSearch(it,q));

  for(const it of items){
    const expired = it.exp && cache.now >= it.exp;
    const rem = it.exp ? (it.exp - cache.now) : null;

    const tr = document.createElement("tr");

    tr.innerHTML = \`
      <td data-label="Key" class="mono">\${it.key}</td>
      <td data-label="Status">\${statusOf(it)}<div class="small">uses: \${it.uses||0}</div></td>
      <td data-label="Device">\${deviceOf(it)}<div class="small">\${it.lockedAt ? ("locked: "+new Date(it.lockedAt).toLocaleString()) : ""}</div></td>
      <td data-label="Time">
        \${it.exp ? \`<div class="mono" data-exp="\${it.exp}">\${msToClock(rem)}</div><div class="small">exp: \${new Date(it.exp).toLocaleString()}</div>\` : \`<div class="mono">∞</div><div class="small">no expiry</div>\`}
        \${it.note ? \`<div class="small">📝 \${it.note}</div>\` : "" }
      </td>
      <td data-label="Actions" class="right">
        <button class="btnTiny" data-sel="\${it.key}">👁</button>
        <button class="btnTiny" data-copy="\${it.key}">📋</button>
        <button class="btnTiny" data-ban="\${it.key}" data-b="\${it.banned?1:0}">\${it.banned?"✅":"⛔"}</button>
        <button class="btnTiny" data-reset="\${it.key}">🔓</button>
        <button class="btnBad" data-del="\${it.key}">🗑</button>
      </td>
    \`;

    rows.appendChild(tr);
  }

  rows.querySelectorAll("[data-copy]").forEach(b=>{
    b.onclick = async ()=>{
      const k = b.getAttribute("data-copy");
      try{ await navigator.clipboard.writeText(k); toast("📋 copied"); }catch{ toast("❌ copy fail"); }
    };
  });

  rows.querySelectorAll("[data-sel]").forEach(b=>{
    b.onclick = ()=>{
      selectedKey = b.getAttribute("data-sel");
      $("selKey").textContent = selectedKey;
      renderLogs();
    };
  });

  rows.querySelectorAll("[data-ban]").forEach(b=>{
    b.onclick = async ()=>{
      const k = b.getAttribute("data-ban");
      const banned = b.getAttribute("data-b")==="1";
      try{
        await post("/api/admin/ban",{ key:k, banned: !banned });
        toast(!banned ? "⛔ banned" : "✅ unbanned");
        await refresh();
      }catch(e){ toast("❌ "+e.message); }
    };
  });

  rows.querySelectorAll("[data-reset]").forEach(b=>{
    b.onclick = async ()=>{
      const k = b.getAttribute("data-reset");
      if(!confirm("Reset device lock ?\\n"+k)) return;
      try{
        await post("/api/admin/reset",{ key:k });
        toast("🔓 reset ok");
        await refresh();
      }catch(e){ toast("❌ "+e.message); }
    };
  });

  rows.querySelectorAll("[data-del]").forEach(b=>{
    b.onclick = async ()=>{
      const k = b.getAttribute("data-del");
      if(!confirm("Delete key ?\\n"+k)) return;
      try{
        await post("/api/admin/delete",{ key:k });
        toast("🗑 deleted");
        await refresh();
      }catch(e){ toast("❌ "+e.message); }
    };
  });

  renderLogs();
}

async function refresh(){
  try{
    const j = await post("/api/admin/list",{ limit: 600 });
    cache.items = j.items || [];
    cache.now = j.now || Date.now();
    cache.stats = j.stats || {};

    $("st_total").textContent = cache.stats.total || 0;
    $("st_active").textContent = cache.stats.active || 0;
    $("st_expired").textContent = cache.stats.expired || 0;
    $("st_banned").textContent = cache.stats.banned || 0;
    $("st_linked").textContent = cache.stats.linked || 0;

    render();
  }catch(e){
    toast("❌ "+e.message);
  }
}

$("refresh").onclick = refresh;
$("search").oninput = render;

$("gen").onclick = async ()=>{
  try{
    const days = Number($("days").value || 30);
    const count = Number($("count").value || 1);
    const note = $("note").value || "";
    const j = await post("/api/admin/create",{ days, count, note });
    const first = j.created?.[0]?.key;
    if(first){
      try{ await navigator.clipboard.writeText(first); }catch{}
      toast("✅ generated (first copied)");
    }else toast("✅ generated");
    $("note").value="";
    await refresh();
  }catch(e){ toast("❌ "+e.message); }
};

// live update countdown + logs
setInterval(()=>{
  if(!live) return;
  cache.now = Date.now();
  document.querySelectorAll("[data-exp]").forEach(el=>{
    const exp = Number(el.getAttribute("data-exp"));
    el.textContent = msToClock(exp - cache.now);
  });
}, 1000);

// live refresh (logs live)
setInterval(()=>{
  if(!live) return;
  refresh();
}, 2500);

// init
$("secret").value = localStorage.getItem("SP_ADMIN_SECRET") || "";
refresh();

// ❄️ snow
const c=$("snow"), ctx=c.getContext("2d");
const resize=()=>{ c.width=innerWidth*devicePixelRatio; c.height=innerHeight*devicePixelRatio; };
resize(); addEventListener("resize", resize);

const flakes = Array.from({length: 110}, ()=>({
  x: Math.random(), y: Math.random(),
  r: 0.6 + Math.random()*1.8,
  s: 0.15 + Math.random()*0.65,
  w: (Math.random()-0.5)*0.25,
  a: 0.35 + Math.random()*0.45
}));

(function loop(){
  const w=c.width,h=c.height;
  ctx.clearRect(0,0,w,h);
  for(const f of flakes){
    f.y += f.s * 0.003 * h;
    f.x += f.w * 0.002 * w;
    if(f.y>1.02){ f.y=-0.02; f.x=Math.random(); }
    if(f.x>1.02) f.x=-0.02;
    if(f.x<-0.02) f.x=1.02;
    ctx.globalAlpha = f.a;
    ctx.beginPath();
    ctx.arc(f.x*w, f.y*h, f.r*devicePixelRatio, 0, Math.PI*2);
    ctx.fillStyle="#ffffff";
    ctx.fill();
  }
  requestAnimationFrame(loop);
})();
</script>
</body>
</html>`;
