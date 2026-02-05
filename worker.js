export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // CORS preflight
      if (request.method === "OPTIONS") return cors(new Response("", { status: 204 }));

      // ---------- HOME ----------
      if (path === "/" || path === "/health") {
        return cors(json({ ok: true, online: true, ts: Date.now() }));
      }

      // ---------- ADMIN PANEL (UI) ----------
      if (path === "/admin" && request.method === "GET") {
        return cors(new Response(adminHtml(), {
          status: 200,
          headers: { "content-type": "text/html; charset=utf-8" }
        }));
      }

      // ---------- CLIENT CHECK ----------
      // /api/check?key=...&did=...
      if (path === "/api/check") {
        const key = (url.searchParams.get("key") || "").trim();
        const did = (url.searchParams.get("did") || "").trim();

        if (!key) return cors(json({ ok: false, reason: "missing_key" }, 400));
        if (!did) return cors(json({ ok: false, reason: "missing_device" }, 400));

        const rec = await getKey(env, key);
        if (!rec) return cors(json({ ok: false, reason: "not_found" }, 404));
        if (rec.banned) return cors(json({ ok: false, reason: "banned" }, 403));

        const now = Date.now();
        if (rec.exp && now > rec.exp) {
          return cors(json({ ok: false, reason: "expired", exp: rec.exp }, 403));
        }

        // device lock (1 appareil)
        if (!rec.device) {
          rec.device = did;
          rec.lockedAt = rec.lockedAt || now;
          await putKey(env, key, rec);
        } else if (rec.device !== did) {
          return cors(json({
            ok: false,
            reason: "device_mismatch",
            lockedDevice: rec.device,
            lockedAt: rec.lockedAt || null
          }, 403));
        }

        const remainingMs = rec.exp ? Math.max(0, rec.exp - now) : null;

        return cors(json({
          ok: true,
          key,
          did,
          remainingMs,
          exp: rec.exp || null,
          banned: !!rec.banned,
          device: rec.device || null,
          lockedAt: rec.lockedAt || null
        }));
      }

      // ---------- ADMIN API ----------
      if (path.startsWith("/api/admin/")) {
        const adminKey = request.headers.get("x-admin-key") || (url.searchParams.get("admin") || "");
        if (!env.ADMIN_KEY || adminKey !== env.ADMIN_KEY) {
          return cors(json({ ok: false, reason: "unauthorized" }, 401));
        }

        // GET /api/admin/get?key=...
        if (path === "/api/admin/get" && request.method === "GET") {
          const key = (url.searchParams.get("key") || "").trim();
          if (!key) return cors(json({ ok: false, reason: "missing_key" }, 400));
          const rec = await getKey(env, key);
          if (!rec) return cors(json({ ok: false, reason: "not_found" }, 404));
          return cors(json({ ok: true, key, rec }));
        }

        // POST /api/admin/add { key, minutes? , hours? , days? , exp? }
        if (path === "/api/admin/add" && request.method === "POST") {
          const body = await safeJson(request);
          const key = (body?.key || "").trim();
          if (!key) return cors(json({ ok: false, reason: "missing_key" }, 400));

          const now = Date.now();
          let exp = null;

          if (typeof body?.exp === "number") {
            exp = body.exp;
          } else {
            const days = Number(body?.days || 0);
            const hours = Number(body?.hours || 0);
            const minutes = Number(body?.minutes || 0);
            const ms = ((days * 24 + hours) * 60 + minutes) * 60 * 1000;
            exp = ms > 0 ? now + ms : null; // null = infinite
          }

          const rec = {
            createdAt: now,
            exp,
            banned: false,
            device: null,
            lockedAt: null
          };

          await putKey(env, key, rec);
          return cors(json({ ok: true, key, rec }));
        }

        // POST /api/admin/ban { key, banned: true/false }
        if (path === "/api/admin/ban" && request.method === "POST") {
          const body = await safeJson(request);
          const key = (body?.key || "").trim();
          const banned = !!body?.banned;
          if (!key) return cors(json({ ok: false, reason: "missing_key" }, 400));

          const rec = await getKey(env, key);
          if (!rec) return cors(json({ ok: false, reason: "not_found" }, 404));

          rec.banned = banned;
          await putKey(env, key, rec);
          return cors(json({ ok: true, key, banned }));
        }

        // POST /api/admin/extend { key, addMinutes }
        if (path === "/api/admin/extend" && request.method === "POST") {
          const body = await safeJson(request);
          const key = (body?.key || "").trim();
          const addMinutes = Number(body?.addMinutes || 0);
          if (!key) return cors(json({ ok: false, reason: "missing_key" }, 400));
          if (!Number.isFinite(addMinutes) || addMinutes === 0) {
            return cors(json({ ok: false, reason: "bad_addMinutes" }, 400));
          }

          const rec = await getKey(env, key);
          if (!rec) return cors(json({ ok: false, reason: "not_found" }, 404));

          // infinite key: no change
          if (rec.exp == null) return cors(json({ ok: true, key, exp: null, note: "infinite_key_no_change" }));

          const now = Date.now();
          const addMs = addMinutes * 60 * 1000;
          const base = Math.max(now, rec.exp);
          rec.exp = base + addMs;

          await putKey(env, key, rec);
          return cors(json({ ok: true, key, exp: rec.exp }));
        }

        // POST /api/admin/resetDevice { key }
        if (path === "/api/admin/resetDevice" && request.method === "POST") {
          const body = await safeJson(request);
          const key = (body?.key || "").trim();
          if (!key) return cors(json({ ok: false, reason: "missing_key" }, 400));

          const rec = await getKey(env, key);
          if (!rec) return cors(json({ ok: false, reason: "not_found" }, 404));

          rec.device = null;
          rec.lockedAt = null;
          await putKey(env, key, rec);

          return cors(json({ ok: true, key, reset: true }));
        }

        // POST /api/admin/delete { key }
        if (path === "/api/admin/delete" && request.method === "POST") {
          const body = await safeJson(request);
          const key = (body?.key || "").trim();
          if (!key) return cors(json({ ok: false, reason: "missing_key" }, 400));

          await env.LICENSES.delete(kvKey(key));
          return cors(json({ ok: true, key, deleted: true }));
        }

        return cors(json({ ok: false, reason: "unknown_admin_route" }, 404));
      }

      return cors(json({ ok: false, reason: "not_found" }, 404));
    } catch (e) {
      return cors(json({ ok: false, reason: "server_error", message: String(e?.message || e) }, 500));
    }
  }
};

function kvKey(key) { return `lic:${key}`; }

async function getKey(env, key) {
  const raw = await env.LICENSES.get(kvKey(key));
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

async function putKey(env, key, obj) {
  await env.LICENSES.put(kvKey(key), JSON.stringify(obj));
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}

function cors(res) {
  const h = new Headers(res.headers);
  h.set("access-control-allow-origin", "*");
  h.set("access-control-allow-methods", "GET,POST,OPTIONS");
  h.set("access-control-allow-headers", "content-type,x-admin-key");
  return new Response(res.body, { status: res.status, headers: h });
}

async function safeJson(request) {
  try { return await request.json(); } catch { return null; }
}

function adminHtml() {
  return `<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SP Admin</title>
<style>
  body{margin:0;background:#070b12;color:#eaf2ff;font-family:ui-monospace,Menlo,monospace}
  .wrap{max-width:980px;margin:0 auto;padding:16px}
  .card{background:linear-gradient(180deg,rgba(8,14,30,.92),rgba(3,6,16,.92));border:1px solid rgba(90,140,255,.25);border-radius:18px;padding:14px;box-shadow:0 18px 60px rgba(0,0,0,.55)}
  .row{display:flex;gap:10px;flex-wrap:wrap}
  input,button,select{border-radius:14px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.06);color:#fff;padding:10px 12px;font-family:inherit}
  button{cursor:pointer}
  .btn{border-color:rgba(255,60,90,.35)}
  .btn2{border-color:rgba(90,140,255,.35)}
  .small{font-size:12px;opacity:.75}
  table{width:100%;border-collapse:collapse;margin-top:12px}
  th,td{padding:10px;border-bottom:1px solid rgba(255,255,255,.08);font-size:12px}
  .pill{display:inline-block;padding:3px 8px;border-radius:999px;border:1px solid rgba(255,255,255,.14);font-size:11px}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
      <div>
        <div style="font-weight:900;letter-spacing:.18em">SP-SPOOF ADMIN</div>
        <div class="small">Generate / Ban / Reset device / Delete</div>
      </div>
      <div class="row">
        <input id="adminKey" placeholder="ADMIN_KEY"/>
        <button class="btn2" onclick="saveKey()">Save</button>
      </div>
    </div>

    <hr style="border:none;border-top:1px solid rgba(255,255,255,.08);margin:14px 0"/>

    <div class="row">
      <input id="newKey" placeholder="Key (blank = auto)"/>
      <input id="days" type="number" placeholder="Days" style="width:90px"/>
      <input id="hours" type="number" placeholder="Hours" style="width:90px"/>
      <input id="minutes" type="number" placeholder="Minutes" style="width:90px"/>
      <button class="btn" onclick="gen()">Generate/Add</button>
    </div>

    <div class="row" style="margin-top:10px">
      <input id="searchKey" placeholder="Search key"/>
      <button class="btn2" onclick="getOne()">Get</button>
      <button class="btn2" onclick="copyKey()">Copy</button>
      <button class="btn" onclick="ban(true)">Ban</button>
      <button class="btn2" onclick="ban(false)">Unban</button>
      <button class="btn2" onclick="resetDevice()">Reset device</button>
      <button class="btn" onclick="delKey()">Delete</button>
    </div>

    <div id="out" class="small" style="margin-top:10px"></div>
  </div>
</div>

<script>
const API_BASE = location.origin;

function randKey(){
  const chars="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s="";
  for(let i=0;i<20;i++) s+=chars[Math.floor(Math.random()*chars.length)];
  return "SP-" + s;
}
function fmt(ms){
  if(ms==null) return "∞";
  ms=Math.max(0, ms);
  const s=Math.floor(ms/1000);
  const d=Math.floor(s/86400);
  const h=Math.floor((s%86400)/3600);
  const m=Math.floor((s%3600)/60);
  if(d>0) return d+"d "+h+"h";
  if(h>0) return h+"h "+m+"m";
  if(m>0) return m+"m";
  return (s%60)+"s";
}

function saveKey(){
  localStorage.setItem("ADMIN_KEY", document.getElementById("adminKey").value.trim());
  log("✅ admin key saved");
}
function adminKey(){
  return (document.getElementById("adminKey").value.trim() || localStorage.getItem("ADMIN_KEY") || "").trim();
}

async function api(path, opts={}){
  const key=adminKey();
  if(!key){ log("❌ missing admin key"); throw new Error("no admin"); }
  const headers = Object.assign({}, opts.headers||{}, { "x-admin-key": key, "content-type":"application/json" });
  const res = await fetch(API_BASE+path, Object.assign({}, opts, { headers }));
  const j = await res.json().catch(()=>({}));
  if(!res.ok) throw new Error(j.reason||("http "+res.status));
  return j;
}

function log(s){ document.getElementById("out").textContent = s; }

async function gen(){
  const kIn = document.getElementById("newKey").value.trim();
  const key = kIn || randKey();
  const days = Number(document.getElementById("days").value||0);
  const hours = Number(document.getElementById("hours").value||0);
  const minutes = Number(document.getElementById("minutes").value||0);

  const j = await api("/api/admin/add", { method:"POST", body: JSON.stringify({ key, days, hours, minutes }) });
  log("✅ added: " + j.key + " (exp: " + (j.rec.exp? new Date(j.rec.exp).toLocaleString() : "∞") + ")");
  document.getElementById("searchKey").value = j.key;
}

async function getOne(){
  const key = document.getElementById("searchKey").value.trim();
  if(!key){ log("❌ enter key"); return; }
  const j = await api("/api/admin/get?key="+encodeURIComponent(key), { method:"GET" });
  const rec = j.rec;
  const now = Date.now();
  const rem = rec.exp ? Math.max(0, rec.exp - now) : null;

  log("✅ key: " + key +
      " | banned: " + !!rec.banned +
      " | remaining: " + fmt(rem) +
      " | device: " + (rec.device? (rec.device.slice(0,10)+"…") : "none"));
}

function copyKey(){
  const key = document.getElementById("searchKey").value.trim();
  if(!key){ log("❌ no key"); return; }
  navigator.clipboard.writeText(key).then(()=>log("📋 copied: " + key)).catch(()=>log("❌ copy failed"));
}

async function ban(v){
  const key = document.getElementById("searchKey").value.trim();
  if(!key){ log("❌ enter key"); return; }
  const j = await api("/api/admin/ban", { method:"POST", body: JSON.stringify({ key, banned: v }) });
  log("✅ " + (v ? "banned" : "unbanned") + ": " + j.key);
}

async function resetDevice(){
  const key = document.getElementById("searchKey").value.trim();
  if(!key){ log("❌ enter key"); return; }
  const j = await api("/api/admin/resetDevice", { method:"POST", body: JSON.stringify({ key }) });
  log("✅ device reset: " + j.key);
}

async function delKey(){
  const key = document.getElementById("searchKey").value.trim();
  if(!key){ log("❌ enter key"); return; }
  const j = await api("/api/admin/delete", { method:"POST", body: JSON.stringify({ key }) });
  log("🗑️ deleted: " + j.key);
}

// load saved admin key into input
document.getElementById("adminKey").value = localStorage.getItem("ADMIN_KEY") || "";
</script>
</body>
</html>`;
}
