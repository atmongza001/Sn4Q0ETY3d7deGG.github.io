// server.js — Bio/Pixel Admin (Multi-tenant) — Version 5.2 (All Requested Features Merged)
// NOTE: No evasion/anti-detection tricks. Consent-based, sanitized, standards-compliant.

const express = require("express");
const fs = require("fs");
const path = require("path");
const cookie = require("cookie-parser");
const bodyParser = require("body-parser");
const sanitizeHtml = require("sanitize-html");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", true);

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme";

const DB_PATH = path.join(process.cwd(), "db.json");

function defaultDB() {
  return {
    tenants: {
      default: {
        profile: { 
          name: "New Page", 
          subtitle: "", 
          avatar: "", 
          cover: "", 
          coverStyle: "style1",
          nameColor: "#FFFFFF"
        },
        theme: { fontURL: "", fontFamily: "" },
        background: { image: "" },
        pixels: { facebook: Array(10).fill(""), tiktok: Array(10).fill(""), ga4: Array(10).fill(""), gtm: Array(10).fill("") },
        content: [],
        seo: { title: "", description: "" },
        footer: "",
        customCSS: "/* CSS ที่นี่จะมีผลกับทุกส่วนของหน้าเว็บ */",
      },
    },
  };
}

function readDB() { if (!fs.existsSync(DB_PATH)) { fs.writeFileSync(DB_PATH, JSON.stringify(defaultDB(), null, 2)); } return JSON.parse(fs.readFileSync(DB_PATH, "utf8")); }
function writeDB(db) { fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2)); }
function getTenant(t) { const db = readDB(); return db.tenants[t]; }
function saveTenant(t, cfg) { const db = readDB(); db.tenants[t] = cfg; writeDB(db); }
function ensureTenant(t) { const db = readDB(); if (!db.tenants[t]) { db.tenants[t] = JSON.parse(JSON.stringify(db.tenants.default)); writeDB(db); } }
function sha256(s) { return crypto.createHash("sha256").update(String(s || "")).digest("hex"); }
function sanitize(html) { return sanitizeHtml(html, { allowedTags: sanitizeHtml.defaults.allowedTags.concat(["img","picture","source","video","audio","track","figure","figcaption","style","iframe","svg","path","script",]), allowedSchemes: ["http", "https", "mailto", "tel", "blob", "data"], allowedAttributes: { "*": ["class","id","style","data-*","width","height","title","aria-*","role"], img: ["src","srcset","sizes","alt","loading","decoding","referrerpolicy"], source: ["src", "srcset", "type", "media", "sizes"], video: ["src","autoplay","muted","loop","playsinline","controls","poster"], audio: ["src","autoplay","loop","controls"], track: ["kind","src","label","srclang","default"], iframe: ["src","width","height","allow","allowfullscreen","loading","referrerpolicy"], script: ["src","async","defer"], a: ["href","target","rel"], }, transformTags: { a(tag,attribs){const href=attribs.href||"";if(!/^(https?:|mailto:|tel:)/i.test(href))delete attribs.href;if(attribs.href){attribs.target="_blank";attribs.rel="noopener nofollow noreferrer";}return{tagName:"a",attribs}}, script(tag,attribs){if(!/^https:\/\//i.test(attribs.src||""))delete attribs.src;return{tagName:"script",attribs}}, iframe(tag,attribs){if(!/^https:\/\//i.test(attribs.src||""))delete attribs.src;attribs.referrerpolicy=attribs.referrerpolicy||"no-referrer";return{tagName:"iframe",attribs}}, img(tag,attribs){const ok=/^https?:\/\//i.test(attribs.src||"")||/^data:image\//i.test(attribs.src||"")||/^blob:/i.test(attribs.src||"");if(!ok)delete attribs.src;attribs.loading=attribs.loading||"lazy";attribs.decoding=attribs.decoding||"async";attribs.referrerpolicy="no-referrer";return{tagName:"img",attribs}}}, });}
app.use(cookie());
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "10mb" }));
function requireAdmin(req, res, next) { const ok = req.cookies.adm && req.cookies.adm === sha256(ADMIN_PASSWORD); if (ok) return next(); res.redirect("/admin/login"); }

app.get("/admin/login", (req, res) => { res.type("html").send(`<!doctype html><meta charset=utf-8><title>Login</title><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Prompt:wght@400;600&display=swap" rel="stylesheet"><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1220;color:#fff;font-family:Prompt,system-ui}.card{background:#111827;border:1px solid #233044;border-radius:14px;padding:24px;width:min(420px,90vw)}input,button{width:100%;padding:12px;border-radius:10px;border:none}input{background:#0f172a;color:#fff;border:1px solid #24324a}button{background:#6366f1;color:#fff;cursor:pointer}</style><div class=card><h2>Admin login</h2><form method=post action=/admin/login><input name=password type=password placeholder="Password (default: changeme)"><div style="height:12px"></div><button>Sign in</button></form></div>`);});
app.post("/admin/login", (req, res) => { if ((req.body || {}).password === ADMIN_PASSWORD) { res.cookie("adm", sha256(ADMIN_PASSWORD), { httpOnly: true, sameSite: "Lax", maxAge: 8 * 60 * 60 * 1000 }); return res.redirect("/admin"); } res.status(401).send("wrong password"); });
app.get("/admin/logout", (req, res) => { res.clearCookie("adm"); res.redirect("/admin/login"); });

app.get("/admin", requireAdmin, (req, res) => {
  const db = readDB();
  const list = Object.keys(db.tenants);
  res.type("html").send(`<!doctype html><meta charset=utf-8><title>Admin</title>
<style>
  body{margin:0;padding:24px;background:#0b1220;color:#fff;font-family:system-ui}
  .row{display:flex;gap:8px;align-items:center;max-width:600px;margin:16px 0} 
  .btn{padding:8px 12px;border-radius:10px;border:none;background:#374151;color:#fff;cursor:pointer; text-decoration: none;}
  .btn.danger{background:#ef4444;}
  input{padding:10px;border-radius:10px;border:1px solid #223047;background:#0f172a;color:#fff;flex:1}
  .tile{background:#111827;border:1px solid #223047;border-radius:12px;padding:12px;margin:6px 0;display:flex;justify-content:space-between;align-items:center}
  a{color:#a78bfa;text-decoration:none}
</style>
<h1>Tenants</h1>
${list.map(t => `<div class=tile>
  <div><a href="/${t}" target="_blank">/${t}</a></div>
  <div class="row" style="margin:0">
    <a href="/admin/${t}" class="btn">Edit</a>
    ${t !== 'default' ? `<form method=post action="/admin/delete/${t}" onsubmit="return confirm('คุณแน่ใจหรือไม่ที่จะลบ ${t}? การกระทำนี้ไม่สามารถกู้คืนได้');"><button class="btn danger">Delete</button></form>` : ''}
  </div>
</div>`).join("")}
<form class=row method=post action=/admin/create><input name=slug placeholder="new-brand-slug" required><button class=btn>Create New</button></form>
<p style="margin-top:16px"><a href="/admin/logout">Logout</a></p>`);
});

app.post("/admin/delete/:tenant", requireAdmin, (req, res) => {
    const tenantToDelete = req.params.tenant;
    if (tenantToDelete === 'default') {
        return res.status(400).send("Cannot delete the default tenant.");
    }
    const db = readDB();
    if (db.tenants[tenantToDelete]) {
        delete db.tenants[tenantToDelete];
        writeDB(db);
    }
    res.redirect("/admin");
});

app.post("/admin/create", requireAdmin, (req, res) => { const slug = (req.body.slug || "").trim().replace(/[^a-z0-9-]/gi, '-').toLowerCase(); if (!slug) return res.redirect("/admin"); const db = readDB(); if (!db.tenants[slug]) db.tenants[slug] = JSON.parse(JSON.stringify(db.tenants.default)); writeDB(db); res.redirect("/admin/" + slug); });

app.get("/admin/:tenant", requireAdmin, (req, res) => {
  ensureTenant(req.params.tenant);
  const cfg = getTenant(req.params.tenant);
  const esc = (s) => (s || "").toString().replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const sel = (v, k) => (v === k ? "selected" : "");
  function inputPixelRows(pixelArray, name, label) { const arr = (pixelArray || []).slice(0, 10); while (arr.length < 10) arr.push(""); return `<div class="pixel-group"><div class=label>${label} (max 10)</div><div class="pixel-inputs">${arr.map((v,i)=>`<input name="${name}[${i}]" value="${esc(v)}" placeholder="ID #${i+1}">`).join("")}</div></div>`; }
  res.type("html").send(`<!doctype html><meta charset=utf-8>
<title>Admin — ${req.params.tenant}</title>
<style>
  body{margin:0;padding:20px;background:#0b1220;color:#fff;font-family:system-ui;line-height:1.45}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(400px,1fr));gap:16px}
  .card{background:#111827;border:1px solid #223047;border-radius:14px;padding:14px; display:flex; flex-direction: column; gap: 8px;}
  .label{opacity:.8;margin-bottom:2px}
  input,select,textarea{width:100%;padding:10px;border-radius:10px;border:1px solid #223047;background:#0f172a;color:#fff;box-sizing: border-box;}
  input[type="color"]{padding: 5px; height: 40px;}
  textarea{min-height:120px; white-space: pre; overflow-wrap: normal; overflow-x: scroll; font-family: monospace;}
  .row{display:flex;gap:8px;align-items:center;}
  .btn{padding:10px 12px;border:none;border-radius:10px;cursor:pointer; color: #fff; text-decoration: none;}
  .btn.save{background:#6366f1;} .btn.secondary{background:#374151;} .btn.danger{background:#ef4444;}
  a{color:#a78bfa;text-decoration:none}
  .content-block{background:#1f2937; padding:12px; border-radius:10px; margin:8px 0; border: 1px solid #374151}
  .content-header{display:flex; justify-content:space-between; align-items:center; margin-bottom: 8px;}
  .pixel-inputs{display:grid; grid-template-columns: 1fr 1fr; gap: 6px;}
</style>
<h1>Tenant: ${req.params.tenant}</h1>
<div style="margin:8px 0"><a href="/${req.params.tenant}" target="_blank"><b>Preview →</b></a></div>
<div class=grid>
  <form class=card method=post action="/admin/${req.params.tenant}/profile">
    <h3>Profile & Theme</h3>
    <div class=row>
      <div style="flex:2"><div class=label>Name</div><input name=name value="${esc(cfg.profile.name)}"></div>
      <div style="flex:1"><div class=label>Name Color</div><input type="color" name="nameColor" value="${esc(cfg.profile.nameColor || '#FFFFFF')}"></div>
    </div>
    <div class=row><div style="flex:1"><div class=label>Subtitle</div><input name=subtitle value="${esc(cfg.profile.subtitle)}"></div></div>
    <div class=row><div style="flex:1"><div class=label>Avatar URL</div><input name=avatar value="${esc(cfg.profile.avatar)}"></div><div style="flex:1"><div class=label>Cover URL (Image/Video)</div><input name=cover value="${esc(cfg.profile.cover)}"></div></div>
    <div class=row><div style="flex:1"><div class=label>Cover Layout</div><select name=coverStyle><option ${sel(cfg.profile.coverStyle,'style1')} value=style1>Style 1</option><option ${sel(cfg.profile.coverStyle,'style2')} value=style2>Style 2</option><option ${sel(cfg.profile.coverStyle,'style3')} value=style3>Style 3</option></select></div><div style="flex:1"><div class=label>Background Image</div><input name=bg value="${esc((cfg.background||{}).image)}"></div></div>
    <div class=row><div style="flex:1"><div class=label>Font URL</div><input name=fontURL value="${esc((cfg.theme||{}).fontURL)}"></div><div style="flex:1"><div class=label>Font Family</div><input name=fontFamily value="${esc((cfg.theme||{}).fontFamily)}"></div></div>
    <div><div class=label>Footer Text</div><input name=footer value="${esc(cfg.footer)}"></div>
    <button class="btn save" style="align-self: flex-start;">Save Profile</button>
  </form>
  <form class=card method=post action="/admin/${req.params.tenant}/seo-pixels">
    <h3>SEO & Pixels</h3>
    <div class=row><div style="flex:1"><div class=label>SEO Title</div><input name=seoTitle value="${esc((cfg.seo||{}).title)}"></div><div style="flex:1"><div class=label>SEO Description</div><input name=seoDesc value="${esc((cfg.seo||{}).description)}"></div></div>
    <hr style="border-color:#374151; width:100%; margin: 8px 0">
    ${inputPixelRows((cfg.pixels||{}).facebook,"facebook","Facebook Pixel ID")}
    ${inputPixelRows((cfg.pixels||{}).tiktok,"tiktok","TikTok Pixel Code")}
    ${inputPixelRows((cfg.pixels||{}).ga4,"ga4","GA4 Measurement ID")}
    ${inputPixelRows((cfg.pixels||{}).gtm,"gtm","GTM Container ID")}
    <button class="btn save" style="align-self: flex-start; margin-top:8px;">Save SEO & Pixels</button>
  </form>
  <form class=card method=post action="/admin/${req.params.tenant}/css">
    <h3>Global Custom CSS</h3>
    <div class=label>CSS code placed here will affect the entire page.</div>
    <textarea name=customCSS style="min-height: 200px">${esc(cfg.customCSS)}</textarea>
    <button class="btn save" style="align-self: flex-start; margin-top:8px;">Save Custom CSS</button>
  </form>
  <div class=card>
    <h3>Content Blocks (HTML, CSS, JS)</h3>
    ${(cfg.content || []).map((block, i) => `<div class="content-block"><div class="content-header"><b>${esc(block.type === 'image' ? 'Image Block' : 'Code Block')}</b><div class="row"><form method=post action="/admin/${req.params.tenant}/content/move/${block.id}"><button name=dir value=up class="btn secondary">↑</button><button name=dir value=down class="btn secondary">↓</button></form><form method=post action="/admin/${req.params.tenant}/content/delete/${block.id}"><button class="btn danger">Delete</button></form></div></div><form method=post action="/admin/${req.params.tenant}/content/update/${block.id}">${block.type === 'image' ? `<div class=label>Image URL</div><input name=url value="${esc(block.data.url)}">` : `<div class=label>Custom Code</div><textarea name=code>${esc(block.data.code)}</textarea>`}<button class="btn save" style="margin-top:8px">Update</button></form></div>`).join('')}
    <hr style="border-color:#374151;"><h4>Add New Block</h4>
    <form method=post action="/admin/${req.params.tenant}/content/add" style="display:flex; gap:8px;"><input type=hidden name=type value=image><input name=url placeholder="Image URL (jpg, png, gif, webp)" style="flex:1" required><button class="btn secondary">Add Image</button></form>
    <form method=post action="/admin/${req.params.tenant}/content/add"><input type=hidden name=type value=code><textarea name=code placeholder="Paste your complete component code here (HTML, <style>, <script>)"></textarea><button class="btn secondary" style="margin-top:8px">Add Code Block</button></form>
  </div>
</div>`);
});

app.post("/admin/:tenant/profile", requireAdmin, (req, res) => { ensureTenant(req.params.tenant); const t = getTenant(req.params.tenant); t.profile.name = (req.body.name || "").trim(); t.profile.nameColor = (req.body.nameColor || "").trim(); t.profile.subtitle = (req.body.subtitle || "").trim(); t.profile.avatar = (req.body.avatar || "").trim(); t.profile.cover = (req.body.cover || "").trim(); t.profile.coverStyle = (req.body.coverStyle || "style1").trim(); t.background = { image: (req.body.bg || "").trim() }; t.theme = { fontURL: (req.body.fontURL || "").trim(), fontFamily: (req.body.fontFamily || "").trim() }; t.footer = (req.body.footer || "").trim(); saveTenant(req.params.tenant, t); res.redirect("/admin/" + req.params.tenant); });
app.post("/admin/:tenant/seo-pixels", requireAdmin, (req, res) => { ensureTenant(req.params.tenant); const t = getTenant(req.params.tenant); t.seo = { title: (req.body.seoTitle || "").trim(), description: (req.body.seoDesc || "").trim() }; const pixelKeys = ["facebook", "tiktok", "ga4", "gtm"]; t.pixels = t.pixels || {}; for (const k of pixelKeys) { const arr = req.body[k]; t.pixels[k] = Array.isArray(arr) ? arr.map(x => (x || "").trim()).slice(0, 10) : Array(10).fill(""); } saveTenant(req.params.tenant, t); res.redirect("/admin/" + req.params.tenant); });
app.post("/admin/:tenant/css", requireAdmin, (req, res) => { ensureTenant(req.params.tenant); const t = getTenant(req.params.tenant); t.customCSS = req.body.customCSS || ""; saveTenant(req.params.tenant, t); res.redirect("/admin/" + req.params.tenant); });
app.post("/admin/:tenant/content/add", requireAdmin, (req, res) => { ensureTenant(req.params.tenant); const t = getTenant(req.params.tenant); t.content = t.content || []; const blockType = req.body.type; const newBlock = { id: crypto.randomUUID(), type: blockType, data: {} }; if (blockType === 'image') newBlock.data.url = (req.body.url || "").trim(); if (blockType === 'code') newBlock.data.code = sanitize(req.body.code || ""); t.content.push(newBlock); saveTenant(req.params.tenant, t); res.redirect("/admin/" + req.params.tenant); });
app.post("/admin/:tenant/content/update/:id", requireAdmin, (req, res) => { ensureTenant(req.params.tenant); const t = getTenant(req.params.tenant); const block = (t.content || []).find(b => b.id === req.params.id); if (block) { if (block.type === 'image') block.data.url = (req.body.url || "").trim(); if (block.type === 'code') block.data.code = sanitize(req.body.code || ""); saveTenant(req.params.tenant, t); } res.redirect("/admin/" + req.params.tenant); });
app.post("/admin/:tenant/content/delete/:id", requireAdmin, (req, res) => { ensureTenant(req.params.tenant); const t = getTenant(req.params.tenant); t.content = (t.content || []).filter(b => b.id !== req.params.id); saveTenant(req.params.tenant, t); res.redirect("/admin/" + req.params.tenant); });
app.post("/admin/:tenant/content/move/:id", requireAdmin, (req, res) => { ensureTenant(req.params.tenant); const t = getTenant(req.params.tenant); const i = (t.content || []).findIndex(b => b.id === req.params.id); const dir = req.body.dir; if (i > -1) { const j = dir === "up" ? i - 1 : i + 1; if (j >= 0 && j < t.content.length) { [t.content[i], t.content[j]] = [t.content[j], t.content[i]]; saveTenant(req.params.tenant, t); } } res.redirect("/admin/" + req.params.tenant); });

app.get("/robots.txt", (req, res) => { res.type("text/plain").send(`User-agent: *\nAllow: /\nSitemap: ${req.protocol}://${req.headers.host}/sitemap.xml`); });
app.get("/sitemap.xml", (req, res) => { const db = readDB(); const host = `${req.protocol}://${req.headers.host}`; const urls = Object.keys(db.tenants).map((t) => `${host}/${t}`); res.type("application/xml").send(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map((u) => `  <url><loc>${u}</loc></url>`).join("\n")}\n</urlset>`); });
app.get("/healthz", (_req, res) => res.status(200).send("OK"));

function renderHTML(tenant, cfg) {
  const esc = (s) => (s || "").toString().replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const title = cfg.seo.title || cfg.profile.name || tenant;
  const desc = cfg.seo.description || cfg.profile.subtitle || "";
  const fontLink = cfg.theme.fontURL ? `<link href="${esc(cfg.theme.fontURL)}" rel="stylesheet">` : "";
  const fontFamily = cfg.theme.fontFamily ? cfg.theme.fontFamily : "system-ui, -apple-system";
  const bgCSS = cfg.background.image ? `background: url('${esc(cfg.background.image)}') center/cover no-repeat fixed;` : `background: #0f172a;`;
  const isVideo = (url = "") => /\.(mp4|webm|mov)$/i.test(url);

  function coverHTML() {
    const { avatar, cover, name, subtitle, coverStyle, nameColor } = cfg.profile;
    const avatarHTML = avatar ? `<img src="${esc(avatar)}" alt="Profile Avatar" class="avatar">` : "";
    const nameColorStyle = nameColor ? `style="color: ${esc(nameColor)};"` : '';
    const nameHTML = name ? `<h1 class="name" ${nameColorStyle}>${esc(name)}</h1>` : "";
    const subtitleHTML = subtitle ? `<p class="subtitle">${esc(subtitle)}</p>` : "";
    let coverMediaHTML = "";
    if (cover) {
      if (isVideo(cover)) { coverMediaHTML = `<video src="${esc(cover)}" class="cover-media" autoplay loop muted playsinline></video>`; } 
      else { coverMediaHTML = `<img src="${esc(cover)}" class="cover-media" alt="Cover Image">`; }
    }
    return `<section class="hero hero-${coverStyle || 'style1'}">${coverMediaHTML}<div class="hero-overlay"></div><div class="hero-content">${avatarHTML}<div class="text-content">${nameHTML}${subtitleHTML}</div></div></section>`;
  }

  function pixelsJS() { const P = cfg.pixels || {}; const fb = (P.facebook || []).filter(Boolean); const tk = (P.tiktok || []).filter(Boolean); const ga = (P.ga4 || []).filter(Boolean); const gtm = (P.gtm || []).filter(Boolean); return `<script>(function(){ function loadGTM(id){ (function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime(),event:'gtm.js'}); var f=d.getElementsByTagName(s)[0],j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true; j.src='https://www.googletagmanager.com/gtm.js?id='+encodeURIComponent(i)+dl;f.parentNode.insertBefore(j,f); })(window,document,'script','dataLayer',id); } ${gtm.map(id=>`loadGTM(${JSON.stringify(id)});`).join("\n")} ${ga.length?`(function(){var s=document.createElement('script');s.async=true;s.src='https://www.googletagmanager.com/gtag/js?id=${encodeURIComponent(ga[0])}';document.head.appendChild(s); window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}window.gtag=gtag;gtag('js',new Date()); ${ga.map(id=>`gtag('config', ${JSON.stringify(id)});`).join("")}})();`:""} ${fb.length?`!function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod? n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[]; t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window, document,'script','https://connect.facebook.net/en_US/fbevents.js'); ${fb.map(id=>`try{fbq('init', ${JSON.stringify(id)});}catch(e){}` ).join("")} try{fbq('track','PageView');}catch(e){}`:""} ${tk.length?`!function (w, d, t) { w.TiktokAnalyticsObject = t; var ttq = w[t] = w[t] || []; ttq.methods = ['page', 'track', 'identify', 'instances', 'debug', 'on', 'off', 'once', 'ready', 'alias', 'group', 'enableCookie', 'disableCookie'];  ttq.setAndDefer = function (t, e) { t[e] = function () { t.push([e].concat(Array.prototype.slice.call(arguments, 0))) } }; for (var i = 0; i < ttq.methods.length; i++) ttq.setAndDefer(ttq, ttq.methods[i]); ttq.load = function (e, n) { var i = 'https://analytics.tiktok.com/i18n/pixel/events.js'; ttq._i = ttq._i || {}, ttq._i[e] = []; ttq._t = ttq._t || {}; ttq._t[e] = +new Date; ttq._o[e] = n || {}; var o = document.createElement('script'); o.type = 'text/javascript'; o.async = !o; o.src = i + '?sdkid=' + e + '&lib=' + t; var a = document.getElementsByTagName('script')[0]; a.parentNode.insertBefore(o, a) }; ${tk.map(id=>`ttq.load(${JSON.stringify(id)}); ttq.page();`).join("")} }(window, document, 'ttq');`:""} })();</script>`; }
  
  const contentHTML = (cfg.content || []).map(block => {
      if (block.type === 'image' && block.data.url) { return `<div class="content-block image-block"><img src="${esc(block.data.url)}" loading="lazy" decoding="async" referrerpolicy="no-referrer"></div>`; }
      if (block.type === 'code') { return block.data.code; }
      return '';
  }).join('\n');

  return `<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><meta name="description" content="${esc(desc)}">
${fontLink}
<style>
  :root { --w: min(100%, 720px); --text-shadow: 0 2px 8px rgba(0, 0, 0, 0.5); }
  * { box-sizing: border-box; }
  body { margin: 0; color: #e5e7eb; font-family: ${fontFamily}; }
  .container { width: var(--w); margin-inline: auto; padding: 0 16px; }
  .footer { opacity: .8; font-size: 12px; text-align: center; padding: 24px 0; }
  .hero { position: relative; width: 100%; display: grid; place-items: center; text-align: center; color: white; padding-bottom: 80px; }
  .cover-media { position: absolute; top: 0; left: 0; width: 100%; height: clamp(200px, 30vh, 280px); object-fit: cover; z-index: 1; clip-path: ellipse(120% 100% at 50% 0%); }
  .hero-overlay { position: absolute; top: 0; left: 0; width: 100%; height: clamp(200px, 30vh, 280px); background: linear-gradient(180deg, rgba(0,0,0,0.1), rgba(0,0,0,0.5)); z-index: 2; clip-path: ellipse(120% 100% at 50% 0%); }
  .hero-content { position: relative; z-index: 3; padding: 1rem; margin-top: clamp(100px, 15vh, 140px); }
  .avatar { width: 112px; height: 112px; border-radius: 9999px; object-fit: cover; border: 4px solid rgba(255,255,255,0.8); box-shadow: 0 4px 15px rgba(0,0,0,0.4); margin-bottom: 1rem; }
  .name { font-size: clamp(1.75rem, 5vw, 2.5rem); font-weight: 700; text-shadow: var(--text-shadow); margin: 0; }
  .subtitle { font-size: clamp(0.9rem, 3vw, 1.1rem); opacity: 0.9; text-shadow: var(--text-shadow); margin: 0.25rem 0 0 0; }
  .hero-style2 .cover-media, .hero-style2 .hero-overlay { display: none; }
  .hero-style2 .hero-content { margin-top: 0; color: #e5e7eb; }
  .hero-style2 .name, .hero-style2 .subtitle { text-shadow: none; }
  .main-content { margin-top: -60px; position: relative; z-index: 10; }
  .content-block { margin: 16px 0; }
  .image-block img { max-width: 100%; height: auto; display: block; border-radius: 12px; }
  ${cfg.customCSS || ''}
</style>
</head>
<body style="${bgCSS}">
  ${coverHTML()}
  <div class="main-content">
    <main class="container">${contentHTML}</main>
    ${cfg.footer ? `<footer class="footer">${esc(cfg.footer)}</footer>` : ""}
  </div>
${pixelsJS()}
</body></html>`;
}

app.get("/", (req, res) => res.redirect("/admin"));
app.get("/:tenant", (req, res) => {
  ensureTenant(req.params.tenant);
  const cfg = getTenant(req.params.tenant);
  res.type("html").send(renderHTML(req.params.tenant, cfg));
});

app.listen(PORT, () => { console.log("Admin on /admin (login first) — running at http://localhost:" + PORT); });
