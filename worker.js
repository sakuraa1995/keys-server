if (url.pathname === "/menu" && request.method === "GET") {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token) return cors(json({ ok:false, error:"missing token" }, 401));

  const ok = await env.KEYS_DB.get("token:" + token);
  if (!ok) return cors(json({ ok:false, error:"bad token" }, 401));

  return cors(json({
    ok: true,
    title: "😈 CHEAT MENU",
    items: [
      { id: "snow", label: "Neige", type: "toggle", value: true },
      { id: "theme", label: "Thème", type: "select", options: ["Bleu", "Rouge", "Violet"], value: "Bleu" }
    ]
  }, 200));
}
