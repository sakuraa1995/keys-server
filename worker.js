export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      // --- Helpers ---
      const json = (obj, status = 200, headers = {}) =>
        new Response(JSON.stringify(obj), {
          status,
          headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
            ...headers,
          },
        });

      const html = (str, status = 200, headers = {}) =>
        new Response(str, {
          status,
          headers: {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
            ...headers,
          },
        });

      const text = (str, status = 200, headers = {}) =>
        new Response(str, {
          status,
          headers: {
            "content-type": "text/plain; charset=utf-8",
            "cache-control": "no-store",
            ...headers,
          },
        });

      const now = Date.now();

      const getIP = (req) =>
        req.headers.get("cf-connecting-ip") ||
        req.headers.get("x-forwarded-for") ||
        "0.0.0.0";

      const safeJson = async (req) => {
        try {
          return await req.json();
        } catch {
          return null;
        }
      };

      const requireKV = () => {
        if (!env.KEYS_DB) throw new Error("KV binding manquant: KEYS_DB");
      };

      const requireAdminSecret = () => {
        if (!env.ADMIN_SECRET) throw new Error("Variable manquante: ADMIN_SECRET");
      };

      const isAuthed = (secret) => {
        if (!env.ADMIN_SECRET) return false;
        return String(secret || "") === String(env.ADMIN_SECRET);
      };

      const kvKey = (key) => `KEY:${key}`;

      const randomKey = (len = 20) => {
        const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // sans 0O1I
        let s = "";
        for (let i = 0; i < len; i++) s += alphabet[Math.floor(Math.random() * alphabet.length)];
        return `SP-${s.slice(0, 4)}-${s.slice(4, 8)}-${s.slice(8, 12)}-${s.slice(12)}`;
      };

      const msToHuman = (ms) => {
        if (ms <= 0) return "expirée";
        const s = Math.floor(ms / 1000);
        const d = Math.floor(s / 86400);
        const h = Math.floor((s % 86400) / 3600);
        const m = Math.floor((s % 3600) / 60);
        const sec = s % 60;
        if (d > 0) return `${d}j ${h}h ${m}m`;
        if (h > 0) return `${h}h ${m}m ${sec}s`;
        if (m > 0) return `${m}m ${sec}s`;
        return `${sec}s`;
      };

      const discord = async (content) => {
        if (!env.DISCORD_WEBHOOK) return;
        try {
          await fetch(env.DISCORD_WEBHOOK, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ content }),
          });
        } catch {}
      };

      // --- Routes ---
      if (path === "/" || path === "/health") {
        const hasKV = !!env.KEYS_DB;
        return json({ ok: true, hasKV, now });
      }

      // ===== API CHECK (pour Stay / ton menu) =====
      // GET /api/check?key=SP-XXXX-....&did=optionalDeviceId
      if (path === "/api/check" && request.method === "GET") {
        requireKV();
        const key = url.searchParams.get("key")?.trim() || "";
        const did = url.searchParams.get("did")?.trim() || "";
        const ip = getIP(request);

        if (!key || key.length < 6) return json({ ok: false, reason: "missing_key" }, 400);

        const raw = await env.KEYS_DB.get(kvKey(key));
        if (!raw) return json({ ok: false, reason: "not_found" }, 404);

        let data;
        try {
          data = JSON.parse(raw);
        } catch {
          return json({ ok: false, reason: "bad_record" }, 500);
        }

        // expired / banned
        if (data.banned) return json({ ok: false, reason: "banned" }, 403);
        if (typeof data.exp === "number" && now >= data.exp)
          return json({ ok: false, reason: "expired" }, 403);

        // touches / usage
        data.uses = (data.uses || 0) + 1;

        // option anti-partage (device lock / ip lock)
        const DEVICE_LOCK = String(env.DEVICE_LOCK || "0") === "1";
        const IP_LOCK = String(env.IP_LOCK || "0") === "1";

        if (DEVICE_LOCK) {
          if (!did) return json({ ok: false, reason: "missing_device" }, 400);
          if (!data.did) data.did = did;
          else if (data.did !== did) return json({ ok: false, reason: "device_mismatch" }, 403);
        }

        if (IP_LOCK) {
          if (!data.ip) data.ip = ip;
          else if (data.ip !== ip) return json({ ok: false, reason: "ip_mismatch" }, 403);
        }

        await env.KEYS_DB.put(kvKey(key), JSON.stringify(data));

        return json({
          ok: true,
          key,
          exp: data.exp || null,
          remainingMs: data.exp ? Math.max(0, data.exp - now) : null,
          note: data.note || "",
          uses: data.uses || 0,
        });
      }

      // ===== ADMIN UI =====
      if (path === "/admin" && request.method === "GET") {
        requireAdminSecret();
        return html(ADMIN_HTML);
      }

      // ===== ADMIN API =====
      if (path.startsWith("/api/admin/")) {
        requireKV();
        requireAdminSecret();
        const body = await safeJson(request);
        const secret =
          body?.secret ||
          request.headers.get("x-admin-secret") ||
          url.searchParams.get("secret");

        if (!isAuthed(secret)) return json({ ok: false, error: "unauthorized" }, 401);

        // LIST
        if (path === "/api/admin/list" && request.method === "POST") {
          const prefix = body?.prefix ?? "KEY:";
          const limit = Math.min(1000, Math.max(1, Number(body?.limit ?? 200)));
          let cursor = body?.cursor || undefined;

          const items = [];
          let listed = 0;

          while (listed < limit) {
            const res = await env.KEYS_DB.list({ prefix, cursor, limit: Math.min(1000, limit - listed) });
            cursor = res.cursor;
            for (const k of res.keys) {
              const raw = await env.KEYS_DB.get(k.name);
              if (!raw) continue;
              try {
                const d = JSON.parse(raw);
                const keyName = k.name.replace(/^KEY:/, "");
                items.push({
                  key: keyName,
                  banned: !!d.banned,
                  exp: typeof d.exp === "number" ? d.exp : null,
                  created: typeof d.created === "number" ? d.created : null,
                  note: d.note || "",
                  uses: d.uses || 0,
                  did: d.did || "",
                  ip: d.ip || "",
                });
              } catch {}
            }
            listed = items.length;
            if (!res.list_complete && cursor) continue;
            break;
          }

          // stats
          const stats = {
            total: items.length,
            active: items.filter((x) => !x.banned && (x.exp ? now < x.exp : true)).length,
            expired: items.filter((x) => x.exp && now >= x.exp).length,
            banned: items.filter((x) => x.banned).length,
          };

          return json({ ok: true, items, cursor, stats, now });
        }

        // CREATE (single or bulk)
        if (path === "/api/admin/create" && request.method === "POST") {
          const days = Math.max(1, Math.min(3650, Number(body?.days ?? 30)));
          const note = String(body?.note ?? "").slice(0, 120);
          const count = Math.max(1, Math.min(100, Number(body?.count ?? 1)));

          const createdKeys = [];

          for (let i = 0; i < count; i++) {
            const key = randomKey();
            const exp = now + days * 24 * 60 * 60 * 1000;

            const data = {
              banned: false,
              exp,
              created: now,
              note,
              uses: 0,
            };

            await env.KEYS_DB.put(kvKey(key), JSON.stringify(data));
            createdKeys.push({ key, exp, note });
          }

          ctx.waitUntil(discord(`🟣 **SP-SPOOF** | ${count} clé(s) créée(s) (${days} jours) ✅`));

          return json({ ok: true, created: createdKeys, now });
        }

        // DELETE
        if (path === "/api/admin/delete" && request.method === "POST") {
          const key = String(body?.key || "").trim();
          if (!key) return json({ ok: false, error: "missing_key" }, 400);
          await env.KEYS_DB.delete(kvKey(key));
          ctx.waitUntil(discord(`🗑️ **SP-SPOOF** | Clé supprimée: \`${key}\``));
          return json({ ok: true });
        }

        // BAN / UNBAN
        if (path === "/api/admin/ban" && request.method === "POST") {
          const key = String(body?.key || "").trim();
          const banned = !!body?.banned;
          if (!key) return json({ ok: false, error: "missing_key" }, 400);

          const raw = await env.KEYS_DB.get(kvKey(key));
          if (!raw) return json({ ok: false, error: "not_found" }, 404);

          const d = JSON.parse(raw);
          d.banned = banned;
          await env.KEYS_DB.put(kvKey(key), JSON.stringify(d));

          ctx.waitUntil(discord(`${banned ? "⛔️" : "✅"} **SP-SPOOF** | ${banned ? "Ban" : "Unban"}: \`${key}\``));

          return json({ ok: true, banned });
        }

        // EXPORT JSON
        if (path === "/api/admin/export" && request.method === "POST") {
          const res = await env.KEYS_DB.list({ prefix: "KEY:", limit: 1000 });
          const out = [];
          for (const k of res.keys) {
            const raw = await env.KEYS_DB.get(k.name);
            if (!raw) continue;
            try {
              out.push({ kv: k.name, data: JSON.parse(raw) });
            } catch {}
          }
          return json({ ok: true, export: out, now });
        }

        return json({ ok: false, error: "not_found" }, 404);
      }

      return text("Not found", 404);
    } catch (e) {
      return new Response(
        JSON.stringify({ ok: false, error: String(e?.message || e), now: Date.now() }),
        { status: 500, headers: { "content-type": "application/json; charset=utf-8" } }
      );
    }
  },
};

const ADMIN_HTML = `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ADMIN SP-SPOOF</title>
  <style>
    :root{
      --bg:#060912;
      --card:#0b1223cc;
      --stroke:#1c2b55;
      --txt:#dbe6ff;
      --muted:#8ea7ffcc;
      --ok:#34d399;
      --bad:#fb7185;
      --warn:#fbbf24;
      --btn:#0b3a8a;
      --btn2:#0ea5e9;
      --shadow: 0 14px 60px rgba(0,0,0,.55);
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      min-height:100vh;
      background: radial-gradient(1200px 700px at 20% 0%, #0a1c55 0%, transparent 55%),
                  radial-gradient(900px 600px at 80% 10%, #3b0764 0%, transparent 55%),
                  var(--bg);
      color:var(--txt);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      overflow-x:hidden;
    }
    .wrap{max-width:980px;margin:0 auto;padding:18px}
    .card{
      position:relative;
      border:1px solid var(--stroke);
      background:linear-gradient(180deg, rgba(12,18,40,.85), rgba(7,10,20,.55));
      border-radius:18px;
      box-shadow:var(--shadow);
      padding:16px;
      overflow:hidden;
    }
    h1{margin:0 0 6px;font-size:20px;letter-spacing:.6px}
    .sub{color:var(--muted);font-size:13px;margin-bottom:14px}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    input, button, select, textarea{
      border-radius:14px;
      border:1px solid var(--stroke);
      background:rgba(6,10,20,.7);
      color:var(--txt);
      padding:12px 12px;
      outline:none;
      font-size:14px;
    }
    input::placeholder{color:#90a4ff66}
    .grow{flex:1}
    .w120{width:120px}
    .w150{width:150px}
    .btn{
      background:linear-gradient(180deg, rgba(14,165,233,.25), rgba(14,165,233,.08));
      border:1px solid rgba(14,165,233,.55);
      cursor:pointer;
      padding:12px 14px;
      font-weight:700;
    }
    .btn2{
      background:linear-gradient(180deg, rgba(59,130,246,.35), rgba(59,130,246,.10));
      border:1px solid rgba(59,130,246,.55);
      cursor:pointer;
      padding:12px 14px;
      font-weight:700;
    }
    .btnBad{
      background:linear-gradient(180deg, rgba(244,63,94,.25), rgba(244,63,94,.08));
      border:1px solid rgba(244,63,94,.55);
      cursor:pointer;
      padding:10px 12px;
      font-weight:700;
    }
    .btnTiny{
      padding:8px 10px;
      border-radius:12px;
      font-size:13px;
      cursor:pointer;
      border:1px solid var(--stroke);
      background:rgba(10,18,40,.65);
    }
    .pill{display:inline-flex;align-items:center;gap:6px;padding:7px 10px;border-radius:999px;border:1px solid var(--stroke);background:rgba(10,18,40,.55);font-size:13px;color:var(--muted)}
    .ok{color:var(--ok)} .bad{color:var(--bad)} .warn{color:var(--warn)}
    .hr{height:1px;background:rgba(255,255,255,.06);margin:14px 0}
    table{width:100%;border-collapse:separate;border-spacing:0 10px}
    th{font-size:12px;color:var(--muted);text-align:left;padding:0 10px}
    td{padding:12px 10px;background:rgba(10,18,40,.55);border:1px solid rgba(28,43,85,.75)}
    td:first-child{border-radius:14px 0 0 14px}
    td:last-child{border-radius:0 14px 14px 0}
    .mono{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace}
    .right{text-align:right}
    .small{font-size:12px;color:var(--muted)}
    .snow{position:fixed;inset:0;pointer-events:none;z-index:2;opacity:.9}
    .toast{
      position:fixed;left:50%;bottom:18px;transform:translateX(-50%);
      background:rgba(0,0,0,.65);border:1px solid rgba(255,255,255,.12);
      padding:10px 14px;border-radius:14px;backdrop-filter: blur(10px);
      display:none;z-index:3;
    }
  </style>
</head>
<body>
  <!-- ❄️ Neige (ADMIN only) -->
  <canvas class="snow" id="snow"></canvas>

  <div class="wrap">
    <div class="card">
      <h1>😈 ADMINISTRATEUR SP-SPOOF</h1>
      <div class="sub">Génération & gestion des clés (KV) • Copie rapide • Timer live • Export • Ban/Delete • Bulk</div>

      <div class="row">
        <input id="secret" class="grow" placeholder="ADMIN_SECRET (mot de passe)" type="password" />
        <button class="btn2" id="saveSecret">💾 Sauver</button>
      </div>

      <div class="hr"></div>

      <div class="row">
        <input id="days" class="w120" value="30" type="number" min="1" max="3650" />
        <input id="count" class="w120" value="1" type="number" min="1" max="100" />
        <input id="note" class="grow" placeholder="Note (optionnel)" />
        <button class="btn" id="gen">➕ Générer</button>
        <button class="btn2" id="refresh">🔄 Actualiser</button>
        <button class="btn2" id="export">📦 Export JSON</button>
      </div>

      <div class="hr"></div>

      <div class="row">
        <input id="search" class="grow" placeholder="Rechercher une clé / note..." />
        <span class="pill">Total: <b id="st_total">0</b></span>
        <span class="pill ok">Actives: <b id="st_active">0</b></span>
        <span class="pill warn">Expirées: <b id="st_expired">0</b></span>
        <span class="pill bad">Bannies: <b id="st_banned">0</b></span>
      </div>

      <div class="hr"></div>

      <div class="small">Astuce: clique sur <b>Copier</b> pour envoyer une clé en 1 tap ✅</div>

      <table>
        <thead>
          <tr>
            <th>Clé</th>
            <th>Info</th>
            <th>Temps restant</th>
            <th class="right">Actions</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
  </div>

  <div class="toast" id="toast"></div>

  <script>
    const $ = (id)=>document.getElementById(id);

    const toast = (msg)=>{
      const t=$("toast");
      t.textContent=msg;
      t.style.display="block";
      clearTimeout(toast._t);
      toast._t=setTimeout(()=>t.style.display="none",1400);
    };

    const loadSecret = ()=>{
      const s = localStorage.getItem("SP_ADMIN_SECRET") || "";
      $("secret").value = s;
    };

    $("saveSecret").onclick = ()=>{
      localStorage.setItem("SP_ADMIN_SECRET", $("secret").value.trim());
      toast("✅ Secret sauvegardé");
    };

    const post = async (path, body)=>{
      const secret = $("secret").value.trim() || localStorage.getItem("SP_ADMIN_SECRET") || "";
      const res = await fetch(path, {
        method:"POST",
        headers:{ "content-type":"application/json" },
        body: JSON.stringify({ ...body, secret })
      });
      const j = await res.json().catch(()=>({ok:false,error:"bad_json"}));
      if(!res.ok || !j.ok) throw new Error(j.error || j.reason || "Erreur API");
      return j;
    };

    const msToClock = (ms)=>{
      ms = Math.max(0, ms|0);
      const s = Math.floor(ms/1000);
      const d = Math.floor(s/86400);
      const h = Math.floor((s%86400)/3600);
      const m = Math.floor((s%3600)/60);
      const sec = s%60;
      const pad=(n)=>String(n).padStart(2,"0");
      if(d>0) return d+"j "+pad(h)+":"+pad(m)+":"+pad(sec);
      return pad(h)+":"+pad(m)+":"+pad(sec);
    };

    let cache = { items:[], now: Date.now() };

    const render = ()=>{
      const q = $("search").value.trim().toLowerCase();
      const rows = $("rows");
      rows.innerHTML = "";

      const items = cache.items.filter(it=>{
        if(!q) return true;
        return (it.key||"").toLowerCase().includes(q) || (it.note||"").toLowerCase().includes(q);
      });

      for(const it of items){
        const exp = it.exp || null;
        const remaining = exp ? (exp - cache.now) : null;

        const expired = exp && remaining <= 0;
        const status = it.banned ? "bannie" : (expired ? "expirée" : "active");

        const tr = document.createElement("tr");

        const tdKey = document.createElement("td");
        tdKey.className="mono";
        tdKey.textContent = it.key;

        const tdInfo = document.createElement("td");
        tdInfo.innerHTML = \`
          <div><b>\${status}</b> • <span class="small">uses: \${it.uses||0}</span></div>
          <div class="small">\${it.note ? "📝 "+it.note : ""}</div>
        \`;

        const tdTime = document.createElement("td");
        tdTime.innerHTML = exp
          ? \`<div class="mono" data-exp="\${exp}">\${msToClock(exp - cache.now)}</div><div class="small">exp: \${new Date(exp).toLocaleString()}</div>\`
          : \`<div class="mono">∞</div><div class="small">sans expiration</div>\`;

        const tdAct = document.createElement("td");
        tdAct.className="right";
        tdAct.innerHTML = \`
          <button class="btnTiny" data-copy="\${it.key}">📋 Copier</button>
          <button class="btnTiny" data-ban="\${it.key}" data-banned="\${it.banned ? 1 : 0}">
            \${it.banned ? "✅ Unban" : "⛔ Ban"}
          </button>
          <button class="btnBad" data-del="\${it.key}">🗑️</button>
        \`;

        tr.appendChild(tdKey);
        tr.appendChild(tdInfo);
        tr.appendChild(tdTime);
        tr.appendChild(tdAct);
        rows.appendChild(tr);
      }

      // bind actions
      rows.querySelectorAll("[data-copy]").forEach(btn=>{
        btn.onclick = async ()=>{
          const k = btn.getAttribute("data-copy");
          try{
            await navigator.clipboard.writeText(k);
            toast("✅ Clé copiée");
          }catch{
            // fallback
            const ta=document.createElement("textarea");
            ta.value=k; document.body.appendChild(ta);
            ta.select(); document.execCommand("copy");
            ta.remove();
            toast("✅ Clé copiée");
          }
        };
      });

      rows.querySelectorAll("[data-del]").forEach(btn=>{
        btn.onclick = async ()=>{
          const k = btn.getAttribute("data-del");
          if(!confirm("Supprimer la clé ?\\n"+k)) return;
          try{
            await post("/api/admin/delete", { key:k });
            toast("🗑️ supprimée");
            await refresh();
          }catch(e){ toast("❌ "+e.message); }
        };
      });

      rows.querySelectorAll("[data-ban]").forEach(btn=>{
        btn.onclick = async ()=>{
          const k = btn.getAttribute("data-ban");
          const banned = btn.getAttribute("data-banned")==="1";
          try{
            await post("/api/admin/ban", { key:k, banned: !banned });
            toast(!banned ? "⛔ bannie" : "✅ unban");
            await refresh();
          }catch(e){ toast("❌ "+e.message); }
        };
      });
    };

    const refresh = async ()=>{
      try{
        const j = await post("/api/admin/list", { limit: 500 });
        cache.items = j.items || [];
        cache.now = j.now || Date.now();

        $("st_total").textContent = j.stats?.total ?? cache.items.length;
        $("st_active").textContent = j.stats?.active ?? 0;
        $("st_expired").textContent = j.stats?.expired ?? 0;
        $("st_banned").textContent = j.stats?.banned ?? 0;

        render();
        toast("🔄 OK");
      }catch(e){
        toast("❌ "+e.message);
      }
    };

    $("refresh").onclick = refresh;
    $("search").oninput = render;

    $("gen").onclick = async ()=>{
      try{
        const days = Number($("days").value || 30);
        const count = Number($("count").value || 1);
        const note = $("note").value || "";
        const j = await post("/api/admin/create", { days, note, count });
        const first = j.created?.[0]?.key;
        if(first){
          try{ await navigator.clipboard.writeText(first); }catch{}
          toast("✅ Généré (1ère clé copiée)");
        }else{
          toast("✅ Généré");
        }
        $("note").value = "";
        await refresh();
      }catch(e){ toast("❌ "+e.message); }
    };

    $("export").onclick = async ()=>{
      try{
        const j = await post("/api/admin/export", {});
        const blob = new Blob([JSON.stringify(j.export, null, 2)], {type:"application/json"});
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "sp-spoof-keys-export.json";
        a.click();
        toast("📦 Export téléchargé");
      }catch(e){ toast("❌ "+e.message); }
    };

    // Live countdown
    setInterval(()=>{
      cache.now = Date.now();
      document.querySelectorAll("[data-exp]").forEach(el=>{
        const exp = Number(el.getAttribute("data-exp"));
        el.textContent = msToClock(exp - cache.now);
      });
    }, 1000);

    // ❄️ Snow effect (canvas)
    const c = $("snow"), ctx = c.getContext("2d");
    const resize=()=>{ c.width=innerWidth*devicePixelRatio; c.height=innerHeight*devicePixelRatio; };
    resize(); addEventListener("resize", resize);

    const flakes = Array.from({length: 120}, ()=>({
      x: Math.random(),
      y: Math.random(),
      r: 0.6 + Math.random()*1.8,
      s: 0.15 + Math.random()*0.65,
      w: (Math.random()-0.5)*0.25,
      a: 0.35 + Math.random()*0.45
    }));

    (function loop(){
      const w=c.width, h=c.height;
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
        ctx.fillStyle = "#ffffff";
        ctx.fill();
      }
      requestAnimationFrame(loop);
    })();

    // init
    loadSecret();
    refresh();
  </script>
</body>
</html>`;
