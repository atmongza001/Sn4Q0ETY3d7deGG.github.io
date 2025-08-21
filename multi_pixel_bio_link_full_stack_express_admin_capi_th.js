// ===============================
// Multi-Pixel BioLink — Full Stack (Express) + Admin + Users + CAPI (TH)
// v4.6 — Media-safe sanitize (img/video/gif), link fix, non-blocking tracking, CAPI hashed user_data
// ===============================

const express = require("express");
const path = require("path");
const fs = require("fs");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const sanitizeHtml = require("sanitize-html");
const axios = require("axios");
const crypto = require("crypto");
const { customAlphabet } = require("nanoid");
const { v4: uuidv4 } = require("uuid");
const dayjs = require("dayjs");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "changeme";

// domain->tenant mapping: TENANT_DOMAIN_MAP="brand1:a.com,brand2:b.com"
const TENANT_DOMAIN_MAP = Object.fromEntries(
  (process.env.TENANT_DOMAIN_MAP || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((pair) => {
      const [tenant, domain] = pair.split(":").map((v) => v.trim());
      return [domain, tenant];
    })
);

// ===== DB =====
const DB_PATH = path.join(process.cwd(), "db.json");
const nanoid = customAlphabet("1234567890abcdefghijklmnopqrstuvwxyz", 16);

function defaultTenantConfig() {
  return {
    theme: "violet",
    profile: {
      displayName: "แสงคำบ้านทุ่ง",
      bio: "รวมลิงก์ทางการ ยิงแอด เก็บคอนเวอร์ชันครบ",
      avatar:
        "https://images.unsplash.com/photo-1588167056540-c9f2c5d4f04b?q=80&w=256&auto=format&fit=crop",
      cover:
        "https://images.unsplash.com/photo-1500530855697-b586d89ba3ee?q=80&w=1200&auto=format&fit=crop",
      background: { type: "gradient", from: "#0f172a", to: "#020617", image: "" },
    },
    footer: "© 2025 The #1 betting website in Thailand",
    badges: [{ text: "โปรแรงวันนี้", href: "#promo", emoji: "🔥" }],

    pixelsSimple: {
      facebook: Array(10).fill(""),
      tiktok: Array(10).fill(""),
      ga4: Array(10).fill(""),
      gtm: Array(10).fill(""),
      googleAds: Array(10).fill(""),
      twitter: Array(10).fill(""),
    },
    pixelsAdvanced: {
      facebook: [{ pixelId: "", accessToken: "", testEventCode: "" }],
      ga4: [{ measurementId: "", apiSecret: "" }],
      tiktok: [{ pixelCode: "", accessToken: "" }],
    },

    customBundles: [],
    customHead: "",
    customBodyEnd: "",

    gallery: [
      "https://images.unsplash.com/photo-1541829070764-84a7d30dd3f8?q=80&w=1200&auto=format&fit=crop",
    ],
    links: [
      {
        title: "สมัครสมาชิก",
        url: "https://example.com/register",
        icon: "⭐",
        highlight: true,
        utm: { source: "bio", medium: "link", campaign: "signup" },
        eventName: "ClickRegister",
      },
      {
        title: "ไลน์แอด (ดูโปร)",
        url: "https://line.me/R/ti/p/@yourline",
        icon: "💬",
        eventName: "ClickLINE",
      },
    ],
  };
}

function defaultDB() {
  return {
    tenants: {
      default: defaultTenantConfig(),
    },
    // users[userSlug] = { tenant:'default', ...same shape as tenant config... }
    users: {},
  };
}

function readDB() {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify(defaultDB(), null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
}
function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// ===== Utils =====
function getClientIP(req) {
  return (req.headers["x-forwarded-for"] || "").split(",")[0] || req.socket.remoteAddress || "";
}
function sha256(s) {
  return crypto.createHash("sha256").update(String(s || "").trim().toLowerCase()).digest("hex");
}

// ===== Sanitize: allow media (img/video/gif), keep scripts https-only, safe anchors =====
function sanitize(html) {
  return sanitizeHtml(html, {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat([
      "img",
      "picture",
      "source",
      "video",
      "audio",
      "track",
      "figure",
      "figcaption",
      "script",
      "style",
      "iframe",
      "svg",
      "path",
      "a",
    ]),
    allowedSchemes: ["http", "https", "mailto", "tel", "blob"],
    allowedSchemesByTag: {
      img: ["http", "https", "data", "blob"],
      source: ["http", "https", "data", "blob"],
      video: ["http", "https", "data", "blob"],
      audio: ["http", "https", "data", "blob"],
    },
    allowedAttributes: {
      "*": [
        "style",
        "class",
        "id",
        "data-*",
        "title",
        "aria-*",
        "role",
        "width",
        "height",
        "loading",
      ],
      a: ["href", "target", "rel", "download", "class", "id", "style", "data-*", "aria-*", "role"],
      iframe: [
        "src",
        "width",
        "height",
        "frameborder",
        "allow",
        "allowfullscreen",
        "loading",
        "referrerpolicy",
      ],
      img: [
        "src",
        "alt",
        "title",
        "width",
        "height",
        "loading",
        "decoding",
        "srcset",
        "sizes",
        "referrerpolicy",
      ],
      picture: ["class", "id"],
      source: ["src", "srcset", "type", "sizes", "media"],
      video: [
        "src",
        "poster",
        "controls",
        "autoplay",
        "muted",
        "loop",
        "playsinline",
        "width",
        "height",
        "preload",
        "crossorigin",
      ],
      audio: ["src", "controls", "autoplay", "loop", "muted", "preload", "crossorigin"],
      track: ["kind", "src", "srclang", "label", "default"],
      script: ["src", "async", "defer"],
    },
    transformTags: {
      a(tag, attribs) {
        const href = attribs.href || "";
        if (!/^(https?:|mailto:|tel:)/i.test(href)) delete attribs.href; // block javascript:
        if (attribs.href) {
          attribs.target = attribs.target || "_blank";
          attribs.rel = "nofollow noopener noreferrer";
        }
        return { tagName: "a", attribs };
      },
      img(tag, attribs) {
        const src = attribs.src || "";
        if (
          !/^https?:\/\//i.test(src) &&
          !/^data:image\//i.test(src) &&
          !/^blob:/i.test(src)
        ) {
          delete attribs.src;
        }
        attribs.loading = attribs.loading || "lazy";
        attribs.decoding = attribs.decoding || "async";
        attribs.referrerpolicy = attribs.referrerpolicy || "no-referrer";
        return { tagName: "img", attribs };
      },
      source(tag, attribs) {
        const src = attribs.src || attribs.srcset || "";
        if (
          !/^https?:\/\//i.test(src) &&
          !/^data:(image|video|audio)\//i.test(src) &&
          !/^blob:/i.test(src)
        ) {
          delete attribs.src;
          delete attribs.srcset;
        }
        return { tagName: "source", attribs };
      },
      video(tag, attribs) {
        const src = attribs.src || "";
        if (
          src &&
          !/^https?:\/\//i.test(src) &&
          !/^blob:/i.test(src) &&
          !/^data:video\//i.test(src)
        ) {
          delete attribs.src;
        }
        if ("autoplay" in attribs) attribs.playsinline = "playsinline";
        return { tagName: "video", attribs };
      },
      audio(tag, attribs) {
        const src = attribs.src || "";
        if (
          src &&
          !/^https?:\/\//i.test(src) &&
          !/^blob:/i.test(src) &&
          !/^data:audio\//i.test(src)
        ) {
          delete attribs.src;
        }
        return { tagName: "audio", attribs };
      },
      script(tag, attribs) {
        const src = attribs.src || "";
        if (src && !/^https?:\/\//i.test(src)) delete attribs.src;
        return { tagName: "script", attribs };
      },
    },
  });
}

function tenantFromReq(req) {
  const host = (req.headers.host || "").split(":")[0];
  if (TENANT_DOMAIN_MAP[host]) return TENANT_DOMAIN_MAP[host];
  const m = req.path.split("/").filter(Boolean);
  if (m.length > 0 && !["admin", "_u", "api", "robots.txt", "sitemap.xml"].includes(m[0])) return m[0];
  return "default";
}
function getTenantConfig(tenant) {
  const db = readDB();
  return db.tenants[tenant] || db.tenants.default;
}
function saveTenantConfig(tenant, cfg) {
  const db = readDB();
  db.tenants[tenant] = cfg;
  writeDB(db);
}
function getUser(userSlug) {
  const db = readDB();
  return db.users[userSlug];
}
function saveUser(userSlug, data) {
  const db = readDB();
  db.users[userSlug] = data;
  writeDB(db);
}
function deleteUser(userSlug) {
  const db = readDB();
  delete db.users[userSlug];
  writeDB(db);
}

// ===== Middlewares =====
app.use(cookieParser());
app.use(bodyParser.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true, limit: "10mb" }));

// ===== SEO =====
app.get("/robots.txt", (req, res) => {
  res
    .type("text/plain")
    .send(`User-agent: *\nAllow: /\nSitemap: ${req.protocol}://${req.headers.host}/sitemap.xml`);
});
app.get("/sitemap.xml", (req, res) => {
  const db = readDB();
  const host = `${req.protocol}://${req.headers.host}`;
  const tenantUrls = Object.keys(db.tenants).map((t) => `${host}/${t}`);
  const userUrls = Object.entries(db.users).map(([slug, u]) => `${host}/${u.tenant}/${slug}`);
  const urls = tenantUrls.concat(userUrls);
  res
    .type("application/xml")
    .send(
      `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls
        .map((u) => `  <url><loc>${u}</loc><lastmod>${dayjs().toISOString()}</lastmod></url>`)
        .join("\n")}\n</urlset>`
    );
});

// ===== Auth =====
function requireAdmin(req, res, next) {
  if (req.cookies.adm === sha256(ADMIN_PASSWORD)) return next();
  return res.redirect("/admin/login");
}
app.get("/admin/login", (req, res) => {
  res
    .type("html")
    .send(`<!doctype html><html lang=th><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Admin Login</title><script src="https://cdn.tailwindcss.com"></script>
<style>body{font-family:system-ui,Prompt}</style></head>
<body class="min-h-dvh flex items-center justify-center bg-slate-950 text-white">
<form method=post action=/admin/login class="bg-white/10 p-6 rounded-2xl w-full max-w-sm">
<h1 class="text-xl font-semibold mb-4">เข้าสู่ระบบแอดมิน</h1>
<input type=password name=password placeholder="รหัสผ่าน" class="w-full p-3 rounded bg-white/10 mb-3"/>
<button class="w-full p-3 rounded bg-sky-500 hover:bg-sky-400">เข้าสู่ระบบ</button>
<p class="mt-3 text-xs text-white/70">ค่าเริ่มต้น: changeme</p>
</form></body></html>`);});
app.post("/admin/login", (req, res) => {
  const { password } = req.body || {};
  if (password === ADMIN_PASSWORD) {
    res.cookie("adm", sha256(ADMIN_PASSWORD), { httpOnly: true, sameSite: "lax" });
    return res.redirect("/admin");
  }
  res.status(401).type("html").send("รหัสผ่านไม่ถูกต้อง");
});
app.get("/admin/logout", (req, res) => {
  res.clearCookie("adm");
  res.redirect("/admin/login");
});

// ===== Admin Home (tenants + users) =====
app.get("/admin", requireAdmin, (req, res) => {
  const db = readDB();
  const ten = Object.keys(db.tenants);
  res.type("html").send(`<!doctype html><html lang=th><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Admin</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="p-4 bg-slate-950 text-white">
<div class="flex items-center justify-between mb-3">
<h1 class="text-2xl font-semibold">เลือกแบรนด์/เว็บ</h1>
<a class="text-sm opacity-80 underline" href="/admin/logout">ออกจากระบบ</a>
</div>
<div class="grid gap-1.5 max-w-md">
${ten
  .map(
    (t) => `<div class="flex gap-1.5">  <a class="flex-1 p-2.5 rounded bg-white/10 hover:bg-white/20" href="/admin/${t}">${t}</a>
  ${t==='default'?'':`<form method="post" action="/admin/${t}/delete" onsubmit="return confirm('ลบแบรนด์นี้?')">    <button class="px-3 py-1.5 rounded bg-rose-500 text-sm">ลบ</button>
  </form>`}</div>`
  )
  .join("")}
</div>

<form method=post action=/admin/create-tenant class="mt-4 max-w-md bg-white/10 p-3 rounded">
<h2 class="font-semibold mb-2">สร้างแบรนด์ใหม่</h2>
<input name=slug placeholder="slug เช่น brand2" class="w-full p-2 rounded bg-white/10 mb-2" required/>
<button class="px-3 py-2 rounded bg-sky-500">สร้าง</button>
</form>

<div class="mt-6 max-w-3xl">
  <div class="flex items-center justify-between">
    <h2 class="text-xl font-semibold mb-2">จัดการสมาชิก (ทั้งหมด)</h2>
    <a class="text-sm underline opacity-80" href="/admin/users">เปิดหน้าเต็ม</a>
  </div>
  <div class="grid gap-1.5">
    ${Object.entries(db.users)
      .map(
        ([slug, u]) =>
          `<div class="p-2.5 bg-white/10 rounded flex items-center justify-between">            <div><div class="font-medium">${slug}</div>
             <div class="text-xs opacity-80">${u.tenant} — <a class="underline" target=_blank href="/${u.tenant}/${slug}">/${u.tenant}/${slug}</a></div></div>
             <form method="post" action="/admin/users/${slug}/delete" onsubmit="return confirm('ลบสมาชิกนี้?')">
               <button class="px-2 py-1 bg-rose-500 rounded text-sm">ลบ</button>
             </form>
           </div>`
      )
      .join("")}
  </div>
</div>
</body></html>`);});
app.post("/admin/create-tenant", requireAdmin, (req, res) => {
  const { slug } = req.body || {};
  if (!slug) return res.status(400).send("กรุณาใส่ slug");
  const db = readDB();
  if (db.tenants[slug]) return res.redirect("/admin/" + slug);
  db.tenants[slug] = defaultTenantConfig();
  writeDB(db);
  res.redirect("/admin/" + slug);
});
app.post("/admin/:tenant/delete", requireAdmin, (req, res) => {
  const { tenant } = req.params;
  const db = readDB();
  if (tenant === "default") return res.status(400).send("ห้ามลบ default");
  delete db.tenants[tenant];
  Object.keys(db.users).forEach((k) => {
    if (db.users[k].tenant === tenant) delete db.users[k];
  });
  writeDB(db);
  res.redirect("/admin");
});

// ===== Admin Users page =====
app.get("/admin/users", requireAdmin, (req, res) => {
  const db = readDB();
  const tenants = Object.keys(db.tenants);
  res.type("html").send(`<!doctype html><html lang=th><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Users</title><script src="https://cdn.tailwindcss.com"></script></head>
<body class="p-4 bg-slate-950 text-white">
<a class="underline" href="/admin">← กลับ</a>
<h1 class="text-2xl font-semibold my-3">จัดการสมาชิก</h1>

<form method="post" action="/admin/users/create" class="bg-white/10 p-3 rounded max-w-xl">
  <h2 class="font-semibold mb-2">เพิ่มสมาชิกใหม่</h2>
  <div class="grid gap-1.5">
    <input name="slug" placeholder="user slug เช่น man01" class="p-2 rounded bg-white/10" required>
    <select name="tenant" class="p-2 rounded bg-white/10">${tenants
      .map((t) => `<option value="${t}">${t}</option>`)
      .join("")}</select>
    <button class="px-3 py-2 rounded bg-emerald-500">สร้าง (ก็อปจาก config ของแบรนด์)</button>
  </div>
</form>

<div class="mt-4 grid gap-1.5 max-w-3xl">
${Object.entries(db.users)
  .map(
    ([slug, u]) => `<div class="p-2.5 bg-white/10 rounded flex items-center justify-between">      <div>
        <div class="font-medium">${slug}</div>
        <div class="text-xs opacity-80">${u.tenant} — 
          <a class="underline" target=_blank href="/${u.tenant}/${slug}">/${u.tenant}/${slug}</a> | 
          <a class="underline" href="/admin/user/${slug}">ตั้งค่า</a>
        </div>
      </div>
      <form method="post" action="/admin/users/${slug}/delete" onsubmit="return confirm('ลบสมาชิกนี้?')">
        <button class="px-2 py-1 rounded bg-rose-500 text-sm">ลบ</button>
      </form>
    </div>`
  )
  .join("")}
</div>
</body></html>`);});
app.post("/admin/users/create", requireAdmin, (req, res) => {
  const { slug, tenant } = req.body || {};
  if (!slug || !tenant) return res.status(400).send("ข้อมูลไม่ครบ");
  const db = readDB();
  if (!db.tenants[tenant]) return res.status(400).send("tenant ไม่มีอยู่");
  if (db.users[slug]) return res.redirect("/admin/user/" + slug);
  db.users[slug] = { tenant, ...JSON.parse(JSON.stringify(db.tenants[tenant])) };
  writeDB(db);
  res.redirect("/admin/user/" + slug);
});
app.post("/admin/users/:slug/delete", requireAdmin, (req, res) => {
  deleteUser(req.params.slug);
  res.redirect("/admin/users");
});

// ===== Admin tenant editor =====
function renderPixelInputsHtml(arr, name, label, esc) {
  const a = (arr || []).slice(0, 10);
  while (a.length < 10) a.push("");
  return `<div class="bg-white/5 p-2.5 rounded">    <div class="font-medium mb-2">${label} (สูงสุด 10)</div>
    ${a.map((v,i)=>`<input name="${name}[${i}]" value="${esc(v)}" placeholder="ช่องที่ ${i+1}" class="w-full p-2 rounded bg-white/10 mb-1.5">`).join("")}
  </div>`;
}
app.get("/admin/:tenant", requireAdmin, (req,res)=>{
  const tenant = req.params.tenant;
  const cfg = getTenantConfig(tenant);
  if(!cfg) return res.status(404).send("no tenant");
  const esc = s => (s||"").toString().replace(/</g,"&lt;").replace(/>/g,"&gt;");
  res.type("html").send(`<!doctype html><html lang=th><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Admin — ${tenant}</title><script src="https://cdn.tailwindcss.com"></script>
<style>textarea{min-height:140px}</style></head>
<body class="p-4 bg-slate-950 text-white">
<a href="/admin" class="underline">← กลับ</a>
<h1 class="text-2xl font-semibold mb-3">ตั้งค่าแบรนด์: ${tenant}</h1>

<div class="grid md:grid-cols-2 gap-4">
<form method=post action="/admin/${tenant}/profile" class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">โปรไฟล์ & หน้าตา</h2>
  <input name="displayName" value="${esc(cfg.profile?.displayName)}" class="w-full p-2 rounded bg-white/10 mb-2" placeholder="ชื่อ"/>
  <input name="bio" value="${esc(cfg.profile?.bio)}" class="w-full p-2 rounded bg-white/10 mb-2" placeholder="คำบรรยาย"/>
  <input name="avatar" value="${esc(cfg.profile?.avatar)}" class="w-full p-2 rounded bg-white/10 mb-2" placeholder="Avatar URL"/>
  <input name="cover" value="${esc(cfg.profile?.cover)}" class="w-full p-2 rounded bg-white/10 mb-2" placeholder="Cover URL"/>
  <div class="grid grid-cols-2 gap-1.5">
    <input name="theme" value="${esc(cfg.theme||'violet')}" class="p-2 rounded bg-white/10" placeholder="theme"/>
    <input name="bgType" value="${esc(cfg.profile?.background?.type||'gradient')}" class="p-2 rounded bg-white/10" placeholder="gradient|image"/>
  </div>
  <div class="grid grid-cols-3 gap-1.5 mt-1.5">
    <input name="bgFrom" value="${esc(cfg.profile?.background?.from||'#0f172a')}" class="p-2 rounded bg-white/10" placeholder="from"/>
    <input name="bgTo" value="${esc(cfg.profile?.background?.to||'#020617')}" class="p-2 rounded bg-white/10" placeholder="to"/>
    <input name="bgImage" value="${esc(cfg.profile?.background?.image||'')}" class="w-full p-2 rounded bg-white/10" placeholder="image url"/>
  </div>
  <input name="footer" value="${esc(cfg.footer)}" class="w-full p-2 rounded bg-white/10 mt-2" placeholder="Footer"/>
  <button class="px-3 py-2 rounded bg-sky-600 mt-2">บันทึก</button>
</form>

<form method=post action="/admin/${tenant}/pixels-simple" class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">พิกเซล (เลข/ID เท่านั้น)</h2>
  ${renderPixelInputsHtml(cfg.pixelsSimple?.facebook,'facebook','Facebook Pixel ID',esc)}
  ${renderPixelInputsHtml(cfg.pixelsSimple?.tiktok,'tiktok','TikTok Pixel Code',esc)}
  ${renderPixelInputsHtml(cfg.pixelsSimple?.ga4,'ga4','GA4 Measurement ID',esc)}
  ${renderPixelInputsHtml(cfg.pixelsSimple?.gtm,'gtm','GTM Container',esc)}
  ${renderPixelInputsHtml(cfg.pixelsSimple?.googleAds,'googleAds','Google Ads Conversion ID',esc)}
  ${renderPixelInputsHtml(cfg.pixelsSimple?.twitter,'twitter','Twitter/X Tag ID',esc)}
  <button class="mt-2 px-3 py-2 rounded bg-sky-600">บันทึก</button>
</form>

<form method=post action="/admin/${tenant}/pixels-advanced" class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">Advanced JSON (CAPI/MP/Events API)</h2>
  <textarea name="pixelsAdvanced" class="w-full p-2 rounded bg-white/10">${esc(JSON.stringify(cfg.pixelsAdvanced||{},null,2))}</textarea>
  <button class="mt-2 px-3 py-2 rounded bg-amber-500">บันทึก Advanced</button>
</form>

<form method=post action="/admin/${tenant}/bundle/add" class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">Custom Code Bundles</h2>
  <textarea name="bundle" class="w-full p-2 rounded bg-white/10" style="min-height:200px" placeholder=""></textarea>
  <button class="mt-2 px-3 py-2 rounded bg-emerald-500">เพิ่มก้อนโค้ด</button>
</form>

<div class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">รายการก้อนโค้ด</h2>
  <div class="grid gap-2">
    ${(cfg.customBundles||[]).map((code,i)=>      `<div class="bg-white/5 p-2.5 rounded">
        <div class="text-xs opacity-80 mb-1">Bundle #${i+1}</div>
        <form method="post" action="/admin/${tenant}/bundle/update" class="grid gap-1.5">
          <input type="hidden" name="idx" value="${i}">
          <textarea name="bundle" class="w-full p-2 rounded bg-white/10" style="min-height:140px">${esc(code)}</textarea>
          <div class="flex gap-1.5">
            <button class="px-3 py-2 rounded bg-sky-600">บันทึก</button>
          </div>
        </form>
        <form method="post" action="/admin/${tenant}/bundle/delete" class="mt-1.5" onsubmit="return confirm('ลบก้อนนี้?')">
          <input type="hidden" name="idx" value="${i}">
          <button class="px-3 py-2 rounded bg-rose-600">ลบ</button>
        </form>
      </div>`).join("")}  </div>
</div>

<div class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">ลิงก์</h2>
  <form method=post action="/admin/${tenant}/links/add" class="grid gap-1.5">
    <input name=title placeholder="ชื่อปุ่ม" class="w-full p-2 rounded bg-white/10" required/>
    <input name=url placeholder="https://…" class="w-full p-2 rounded bg-white/10" required/>
    <input name=icon placeholder="อีโมจิ เช่น ⭐" class="w-full p-2 rounded bg-white/10"/>
    <input name=badge placeholder="ป้าย เช่น HOT" class="w-full p-2 rounded bg-white/10"/>
    <input name=eventName placeholder="ชื่ออีเวนต์ เช่น ClickRegister" class="w-full p-2 rounded bg-white/10"/>
    <label class=text-sm>UTM (JSON)</label>
    <input name=utm placeholder='{"source":"bio","medium":"link","campaign":"main"}' class="w-full p-2 rounded bg-white/10"/>
    <label class="inline-flex items-center gap-2"><input type=checkbox name=highlight/> <span>ไฮไลต์</span></label>
    <button class="px-3 py-2 rounded bg-emerald-600">เพิ่มลิงก์</button>
  </form>
  <div class="mt-3 grid gap-1.5">
    ${(cfg.links||[]).map((l,i)=>      `<div class="p-2.5 bg-white/5 rounded flex items-center justify-between">
        <div><div class="font-medium">${esc(l.title)}</div>
        <div class="text-xs opacity-80">${esc(l.url)}</div></div>
        <form method=post action="/admin/${tenant}/links/del" onsubmit="return confirm('ลบลิงก์นี้?')">
          <input type=hidden name=idx value="${i}"/>
          <button class="px-2 py-1 rounded bg-rose-600 text-sm">ลบ</button>
        </form>
      </div>`).join("")}  </div>
</div>

<div class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">Image Gallery (รองรับ jpg/png/gif/webp)</h2>
  <form method=post action=/admin/${tenant}/gallery/add class="grid gap-1.5">
    <input name=url placeholder="Image URL" class="w-full p-2 rounded bg-white/10" required/>
    <button class="px-3 py-2 rounded bg-indigo-600">เพิ่มรูป</button>
  </form>
  <div class="mt-3 grid grid-cols-2 sm:grid-cols-3 gap-1.5">
    ${(cfg.gallery||[]).map((u,i)=>      `<div class="bg-white/5 p-1.5 rounded">
        <img src="${esc(u)}" class="w-full h-24 object-cover rounded" loading="lazy" referrerpolicy="no-referrer"/>
        <form method=post action="/admin/${tenant}/gallery/del" class="mt-1.5" onsubmit="return confirm('ลบรูปนี้?')">
          <input type=hidden name=idx value="${i}"/>
          <button class="px-2 py-1 rounded bg-rose-600 text-sm">ลบ</button>
        </form>
      </div>`).join("")}  </div>
</div>

</div>
</body></html>`);});
app.post("/admin/:tenant/profile", requireAdmin, (req,res)=>{
  const t = req.params.tenant; const cfg = getTenantConfig(t); if(!cfg) return res.status(404).send("no tenant");
  cfg.theme = req.body.theme || cfg.theme;
  cfg.profile = cfg.profile || {};
  cfg.profile.displayName = req.body.displayName || cfg.profile.displayName;
  cfg.profile.bio = req.body.bio || cfg.profile.bio;
  cfg.profile.avatar = req.body.avatar || cfg.profile.avatar;
  cfg.profile.cover = req.body.cover || cfg.profile.cover;
  cfg.profile.background = {
    type: req.body.bgType || "gradient",
    from: req.body.bgFrom || "#0f172a",
    to: req.body.bgTo || "#020617",
    image: req.body.bgImage || "",
  };
  cfg.footer = req.body.footer || cfg.footer;
  saveTenantConfig(t, cfg); res.redirect("/admin/"+t);
});
app.post("/admin/:tenant/pixels-simple", requireAdmin, (req,res)=>{
  const t = req.params.tenant; const cfg = getTenantConfig(t); if(!cfg) return res.status(404).send("no tenant");
  const map = ["facebook","tiktok","ga4","gtm","googleAds","twitter"];
  cfg.pixelsSimple = cfg.pixelsSimple || {};
  for(const k of map){
    const v = req.body[k];
    if(Array.isArray(v)) cfg.pixelsSimple[k] = v.map(x=>String(x||""));
  }
  saveTenantConfig(t,cfg); res.redirect("/admin/"+t);
});
app.post("/admin/:tenant/pixels-advanced", requireAdmin, (req,res)=>{
  const t = req.params.tenant; const cfg=getTenantConfig(t);
  try{ cfg.pixelsAdvanced = JSON.parse(req.body.pixelsAdvanced||"{}"); }
  catch{ return res.status(400).send("JSON ไม่ถูกต้อง"); }
  saveTenantConfig(t,cfg); res.redirect("/admin/"+t);
});
app.post("/admin/:tenant/bundle/add", requireAdmin, (req,res)=>{
  const t=req.params.tenant; const cfg=getTenantConfig(t); cfg.customBundles=cfg.customBundles||[];
  cfg.customBundles.push(sanitize(req.body.bundle||"")); saveTenantConfig(t,cfg); res.redirect("/admin/"+t);
});
app.post("/admin/:tenant/bundle/update", requireAdmin, (req,res)=>{
  const t=req.params.tenant; const cfg=getTenantConfig(t); const idx=parseInt(req.body.idx,10);
  if(!cfg.customBundles?.[idx]) return res.status(400).send("index ผิด");
  cfg.customBundles[idx]=sanitize(req.body.bundle||""); saveTenantConfig(t,cfg); res.redirect("/admin/"+t);
});
app.post("/admin/:tenant/bundle/delete", requireAdmin, (req,res)=>{
  const t=req.params.tenant; const cfg=getTenantConfig(t); const idx=parseInt(req.body.idx,10);
  if(!cfg.customBundles?.[idx]) return res.status(400).send("index ผิด");
  cfg.customBundles.splice(idx,1); saveTenantConfig(t,cfg); res.redirect("/admin/"+t);
});
app.post("/admin/:tenant/links/add", requireAdmin, (req,res)=>{
  const t=req.params.tenant; const cfg=getTenantConfig(t); let utm={}; try{ utm=req.body.utm?JSON.parse(req.body.utm):{} }catch{}
  cfg.links=cfg.links||[]; cfg.links.push({ title:req.body.title||'', url:req.body.url||'', icon:req.body.icon||'🔗',
    badge:req.body.badge||'', highlight:!!req.body.highlight, utm, eventName:req.body.eventName||'LinkClick' });
  saveTenantConfig(t,cfg); res.redirect("/admin/"+t);
});
app.post("/admin/:tenant/links/del", requireAdmin, (req,res)=>{
  const t=req.params.tenant; const cfg=getTenantConfig(t); const idx=parseInt(req.body.idx,10);
  if(!isFinite(idx)) return res.status(400).send("idx ผิด");
  (cfg.links||[]).splice(idx,1); saveTenantConfig(t,cfg); res.redirect("/admin/"+t);
});
app.post("/admin/:tenant/gallery/add", requireAdmin, (req,res)=>{
  const t=req.params.tenant; const cfg=getTenantConfig(t); cfg.gallery=cfg.gallery||[];
  if(req.body.url) cfg.gallery.push(req.body.url); saveTenantConfig(t,cfg); res.redirect("/admin/"+t);
});
app.post("/admin/:tenant/gallery/del", requireAdmin, (req,res)=>{
  const t=req.params.tenant; const cfg=getTenantConfig(t); const idx=parseInt(req.body.idx,10);
  if(!isFinite(idx)) return res.status(400).send("idx ผิด");
  (cfg.gallery||[]).splice(idx,1); saveTenantConfig(t,cfg); res.redirect("/admin/"+t);
});

// ===== Admin user settings =====
app.get("/admin/user/:slug", requireAdmin, (req, res) => {
  const u = getUser(req.params.slug);
  if (!u) return res.status(404).send("ไม่พบผู้ใช้");
  const slug = req.params.slug;
  const cfg = u;
  const esc = (s) => (s || "").toString().replace(/</g, "&lt;").replace(/>/g, "&gt;");
  function renderPixelInputs(arr, name, label) {
    const a = (arr || []).slice(0, 10);
    while (a.length < 10) a.push("");
    return `<div class="bg-white/5 p-2.5 rounded">      <div class="font-medium mb-2">${label} (สูงสุด 10)</div>
      ${a
        .map(
          (v, i) =>
            `<input name="${name}[${i}]" value="${esc(v)}" placeholder="ช่องที่ ${i + 1}" class="w-full p-2 rounded bg-white/10 mb-1.5">`
        )
        .join("")}
    </div>`;
  }
  res.type("html").send(`<!doctype html><html lang=th><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>User ${slug}</title><script src="https://cdn.tailwindcss.com"></script>
<style>textarea{min-height:160px}</style></head>
<body class="p-4 bg-slate-950 text-white">
<a href="/admin/users" class="underline">← กลับ</a>
<h1 class="text-2xl font-semibold mb-3">ตั้งค่าหน้าไบโอของ: ${slug}</h1>

<div class="grid md:grid-cols-2 gap-4">

<form method=post action="/admin/user/${slug}/profile" class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">โปรไฟล์ & หน้าตา</h2>
  <label class=text-sm>ชื่อที่แสดง</label>
  <input name="displayName" value="${esc(cfg.profile?.displayName)}" class="w-full p-2 rounded bg-white/10 mb-2"/>
  <label class=text-sm>คำบรรยาย</label>
  <input name="bio" value="${esc(cfg.profile?.bio)}" class="w-full p-2 rounded bg-white/10 mb-2"/>
  <label class=text-sm>Avatar URL</label>
  <input name="avatar" value="${esc(cfg.profile?.avatar)}" class="w-full p-2 rounded bg-white/10 mb-2"/>
  <label class=text-sm>Cover URL</label>
  <input name="cover" value="${esc(cfg.profile?.cover)}" class="w-full p-2 rounded bg-white/10 mb-2"/>

  <div class="grid grid-cols-2 gap-1.5">
    <div><label class=text-sm>ธีม (violet|emerald|crimson)</label>
    <input name="theme" value="${esc(cfg.theme)}" class="w-full p-2 rounded bg-white/10 mb-2"/></div>
    <div><label class=text-sm>พื้นหลัง (gradient|image)</label>
    <input name="bgType" value="${esc(cfg.profile?.background?.type||'gradient')}" class="w-full p-2 rounded bg-white/10 mb-2"/></div>
  </div>

  <div class="grid grid-cols-3 gap-1.5">
    <div><label class=text-sm>From</label><input name="bgFrom" value="${esc(cfg.profile?.background?.from||'#0f172a')}" class="w-full p-2 rounded bg-white/10 mb-2"/></div>
    <div><label class=text-sm>To</label><input name="bgTo" value="${esc(cfg.profile?.background?.to||'#020617')}" class="w-full p-2 rounded bg-white/10 mb-2"/></div>
    <div><label class=text-sm>Bg Image</label><input name="bgImage" value="${esc(cfg.profile?.background?.image||'')}" class="w-full p-2 rounded bg-white/10 mb-2"/></div>
  </div>

  <label class=text-sm>Footer</label>
  <input name="footer" value="${esc(cfg.footer)}" class="w-full p-2 rounded bg-white/10 mb-2"/>
  <button class="px-3 py-2 rounded bg-sky-500">บันทึก</button>
</form>

<form method=post action="/admin/user/${slug}/pixels-simple" class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">พิกเซล (เลข/ID เท่านั้น)</h2>
  ${renderPixelInputs(cfg.pixelsSimple?.facebook,'facebook','Facebook Pixel ID')}
  ${renderPixelInputs(cfg.pixelsSimple?.tiktok,'tiktok','TikTok Pixel Code')}
  ${renderPixelInputs(cfg.pixelsSimple?.ga4,'ga4','GA4 Measurement ID')}
  ${renderPixelInputs(cfg.pixelsSimple?.gtm,'gtm','GTM Container')}
  ${renderPixelInputs(cfg.pixelsSimple?.googleAds,'googleAds','Google Ads Conversion ID')}
  ${renderPixelInputs(cfg.pixelsSimple?.twitter,'twitter','Twitter/X Tag ID')}
  <button class="mt-2 px-3 py-2 rounded bg-sky-500">บันทึก</button>
</form>

<form method=post action="/admin/user/${slug}/pixels-advanced" class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">Advanced JSON (CAPI/MP/Events API)</h2>
  <textarea name="pixelsAdvanced" class="w-full p-2 rounded bg-white/10">${esc(JSON.stringify(cfg.pixelsAdvanced||{},null,2))}</textarea>
  <button class="mt-2 px-3 py-2 rounded bg-amber-500">บันทึก Advanced</button>
</form>

<form method=post action="/admin/user/${slug}/bundle/add" class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">Custom Code Bundles</h2>
  <textarea name="bundle" class="w-full p-2 rounded bg-white/10" style="min-height:220px" placeholder=""></textarea>
  <button class="mt-2 px-3 py-2 rounded bg-emerald-500">เพิ่มก้อนโค้ด</button>
</form>

<div class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">รายการก้อนโค้ด</h2>
  <div class="grid gap-2">
    ${(cfg.customBundles||[]).map((code,i)=>      `<div class="bg-white/5 p-2.5 rounded">
        <div class="text-xs opacity-80 mb-1">Bundle #${i+1}</div>
        <form method="post" action="/admin/user/${slug}/bundle/update" class="grid gap-1.5">
          <input type="hidden" name="idx" value="${i}">
          <textarea name="bundle" class="w-full p-2 rounded bg-white/10" style="min-height:160px">${esc(code)}</textarea>
          <div class="flex gap-1.5">
            <button class="px-3 py-2 rounded bg-sky-500">บันทึก</button>
          </div>
        </form>
        <form method="post" action="/admin/user/${slug}/bundle/delete" class="mt-1.5" onsubmit="return confirm('ลบก้อนนี้?')">
          <input type="hidden" name="idx" value="${i}">
          <button class="px-3 py-2 rounded bg-rose-500">ลบ</button>
        </form>
      </div>`).join("")}  </div>
</div>

<div class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">ลิงก์</h2>
  <form method=post action="/admin/user/${slug}/links/add" class="grid gap-1.5">
    <input name=title placeholder="ชื่อปุ่ม" class="w-full p-2 rounded bg-white/10" required/>
    <input name=url placeholder="https://…" class="w-full p-2 rounded bg-white/10" required/>
    <input name=icon placeholder="อีโมจิ เช่น ⭐" class="w-full p-2 rounded bg-white/10"/>
    <input name=badge placeholder="ป้าย เช่น HOT" class="w-full p-2 rounded bg-white/10"/>
    <input name=eventName placeholder="ชื่ออีเวนต์ เช่น ClickRegister" class="w-full p-2 rounded bg-white/10"/>
    <label class=text-sm>UTM (JSON)</label>
    <input name=utm placeholder='{"source":"bio","medium":"link","campaign":"main"}' class="w-full p-2 rounded bg-white/10"/>
    <label class="inline-flex items-center gap-2"><input type=checkbox name=highlight/> <span>ไฮไลต์</span></label>
    <button class="px-3 py-2 rounded bg-emerald-500">เพิ่มลิงก์</button>
  </form>
  <div class="mt-3 grid gap-1.5">
    ${(cfg.links||[]).map((l,i)=>      `<div class="p-2.5 bg-white/5 rounded flex items-center justify-between">
        <div><div class="font-medium">${esc(l.title)}</div>
        <div class="text-xs opacity-80">${esc(l.url)}</div></div>
        <form method=post action="/admin/user/${slug}/links/del" onsubmit="return confirm('ลบลิงก์นี้?')">
          <input type=hidden name=idx value="${i}"/>
          <button class="px-2 py-1 rounded bg-rose-500">ลบ</button>
        </form>
      </div>`).join("")}  </div>
</div>

<div class="bg-white/10 p-3 rounded">
  <h2 class="font-semibold mb-2">Image Gallery (รองรับ jpg/png/gif/webp)</h2>
  <form method=post action="/admin/user/${slug}/gallery/add" class="grid gap-1.5">
    <input name=url placeholder="Image URL" class="w-full p-2 rounded bg-white/10" required/>
    <button class="px-3 py-2 rounded bg-indigo-500">เพิ่มรูป</button>
  </form>
  <div class="mt-3 grid grid-cols-2 sm:grid-cols-3 gap-2">
    ${(cfg.gallery||[]).map((u,i)=>      `<div class="bg-white/5 p-1.5 rounded">
        <img src="${esc(u)}" class="w-full h-28 object-cover rounded" loading="lazy" referrerpolicy="no-referrer"/>
        <form method=post action="/admin/user/${slug}/gallery/del" class="mt-1.5" onsubmit="return confirm('ลบรูปนี้?')">
          <input type=hidden name=idx value="${i}"/>
          <button class="px-2 py-1 rounded bg-rose-500 text-sm">ลบ</button>
        </form>
      </div>`).join("")}  </div>
</div>

</div>
</body></html>`);});

// user actions
app.post("/admin/user/:slug/profile", requireAdmin, (req, res) => {
  const slug = req.params.slug;
  const u = getUser(slug);
  if (!u) return res.status(404).send("ไม่พบผู้ใช้");
  u.theme = req.body.theme || u.theme;
  u.profile = u.profile || {};
  u.profile.displayName = req.body.displayName || u.profile.displayName;
  u.profile.bio = req.body.bio || u.profile.bio;
  u.profile.avatar = req.body.avatar || u.profile.avatar;
  u.profile.cover = req.body.cover || u.profile.cover;
  u.profile.background = {
    type: req.body.bgType || "gradient",
    from: req.body.bgFrom || "#0f172a",
    to: req.body.bgTo || "#020617",
    image: req.body.bgImage || "",
  };
  u.footer = req.body.footer || u.footer;
  saveUser(slug, u);
  res.redirect("/admin/user/" + slug);
});
app.post("/admin/user/:slug/pixels-simple", requireAdmin, (req, res) => {
  const slug = req.params.slug;
  const u = getUser(slug);
  if (!u) return res.status(404).send("ไม่พบผู้ใช้");
  const map = ["facebook", "tiktok", "ga4", "gtm", "googleAds", "twitter"];
  u.pixelsSimple = u.pixelsSimple || {};
  for (const k of map) {
    const v = req.body[k];
    if (Array.isArray(v)) u.pixelsSimple[k] = v.map((x) => String(x || ""));
  }
  saveUser(slug, u);
  res.redirect("/admin/user/" + slug);
});
app.post("/admin/user/:slug/pixels-advanced", requireAdmin, (req, res) => {
  const slug = req.params.slug;
  const u = getUser(slug);
  if (!u) return res.status(404).send("ไม่พบผู้ใช้");
  try {
    u.pixelsAdvanced = JSON.parse(req.body.pixelsAdvanced || "{}");
  } catch (e) {
    return res.status(400).send("JSON ไม่ถูกต้อง");
  }
  saveUser(slug, u);
  res.redirect("/admin/user/" + slug);
});
app.post("/admin/user/:slug/bundle/add", requireAdmin, (req, res) => {
  const u = getUser(req.params.slug);
  if (!u) return res.status(404).send("ไม่พบผู้ใช้");
  u.customBundles = u.customBundles || [];
  u.customBundles.push(sanitize(req.body.bundle || ""));
  saveUser(req.params.slug, u);
  res.redirect("/admin/user/" + req.params.slug);
});
app.post("/admin/user/:slug/bundle/update", requireAdmin, (req, res) => {
  const u = getUser(req.params.slug);
  const idx = parseInt(req.body.idx, 10);
  if (!u || !isFinite(idx) || !u.customBundles?.[idx]) return res.status(400).send("index ผิด");
  u.customBundles[idx] = sanitize(req.body.bundle || "");
  saveUser(req.params.slug, u);
  res.redirect("/admin/user/" + req.params.slug);
});
app.post("/admin/user/:slug/bundle/delete", requireAdmin, (req, res) => {
  const u = getUser(req.params.slug);
  const idx = parseInt(req.body.idx, 10);
  if (!u || !isFinite(idx) || !u.customBundles?.[idx]) return res.status(400).send("index ผิด");
  u.customBundles.splice(idx, 1);
  saveUser(req.params.slug, u);
  res.redirect("/admin/user/" + req.params.slug);
});
app.post("/admin/user/:slug/links/add", requireAdmin, (req, res) => {
  const u = getUser(req.params.slug);
  if (!u) return res.status(404).send("ไม่พบผู้ใช้");
  let utm = {};
  try {
    utm = req.body.utm ? JSON.parse(req.body.utm) : {};
  } catch {}
  u.links = u.links || [];
  u.links.push({
    title: req.body.title || "",
    url: req.body.url || "",
    icon: req.body.icon || "🔗",
    badge: req.body.badge || "",
    highlight: !!req.body.highlight,
    utm,
    eventName: req.body.eventName || "LinkClick",
  });
  saveUser(req.params.slug, u);
  res.redirect("/admin/user/" + req.params.slug);
});
app.post("/admin/user/:slug/links/del", requireAdmin, (req, res) => {
  const u = getUser(req.params.slug);
  const idx = parseInt(req.body.idx, 10);
  if (!u || !isFinite(idx)) return res.status(400).send("idx ผิด");
  (u.links || []).splice(idx, 1);
  saveUser(req.params.slug, u);
  res.redirect("/admin/user/" + req.params.slug);
});
app.post("/admin/user/:slug/gallery/add", requireAdmin, (req, res) => {
  const u = getUser(req.params.slug);
  if (!u) return res.status(404).send("ไม่พบผู้ใช้");
  u.gallery = u.gallery || [];
  if (req.body.url) u.gallery.push(req.body.url);
  saveUser(req.params.slug, u);
  res.redirect("/admin/user/" + req.params.slug);
});
app.post("/admin/user/:slug/gallery/del", requireAdmin, (req, res) => {
  const u = getUser(req.params.slug);
  const idx = parseInt(req.body.idx, 10);
  if (!u || !isFinite(idx)) return res.status(400).send("idx ผิด");
  (u.gallery || []).splice(idx, 1);
  saveUser(req.params.slug, u);
  res.redirect("/admin/user/" + req.params.slug);
});

// ===== Client renderer =====
function renderClientHTML(cfg) {
  const title = `${cfg.profile?.displayName || "Bio Link"} — โปรไฟล์ & ลิงก์`;
  const desc = cfg.profile?.bio || "บิโอลิงก์ ยิงพิกเซลหลายตัว เพิ่มลิงก์ได้ไม่อั้น";
  const og = cfg.profile?.cover || cfg.profile?.avatar || "https://picsum.photos/1200/630";
  const bg = cfg.profile?.background || {};
  const gtmNoscript = (cfg.pixelsSimple?.gtm || [])
    .filter(Boolean)
    .map(
      (id) =>
        `<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=${id}" height=0 width=0 style="display:none;visibility:hidden"></iframe></noscript>`
    )
    .join("\n");
  const bgStyle =
    bg.type === "image" && bg.image
      ? `background-image:url('${bg.image}'); background-size:cover; background-position:center;`
      : `background-image:linear-gradient(to bottom, ${bg.from || "#0f172a"}, ${bg.to || "#020617"});`;

  return `<!doctype html><html lang=th><head><meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1">
<title>${title}</title>
<meta name=description content="${desc}">
<meta property=og:type content=website>
<meta property=og:title content="${title}">
<meta property=og:description content="${desc}">
<meta property=og:image content="${og}">
<meta name=twitter:card content=summary_large_image>
<meta name=twitter:title content="${title}">
<meta name=twitter:description content="${desc}">
<meta name=twitter:image content="${og}">
<link rel=preconnect href=https://fonts.googleapis.com><link rel=preconnect href=https://fonts.gstatic.com crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Prompt:wght@300;400;500;600;700&display=swap" rel=stylesheet>
<script src=https://cdn.tailwindcss.com></script>
<style>
  :root{--bg-from:#0f172a;--bg-to:#020617;--card:rgba(255,255,255,.06);--card-hover:rgba(255,255,255,.12);--accent:#a78bfa;--text:#e5e7eb;--muted:#a1a1aa;--ring:rgba(167,139,250,.6)}
  [data-theme="emerald"]{--accent:#34d399;--ring:rgba(52,211,153,.6);--bg-from:#052e2b;--bg-to:#031a18}
  [data-theme="crimson"]{--accent:#ef4444;--ring:rgba(239,68,68,.6);--bg-from:#2a0b10;--bg-to:#180507}
  body{font-family:Prompt,system-ui;-webkit-font-smoothing:antialiased;min-height:100dvh;display:flex;flex-direction:column}
  .glass{background:var(--card);backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,.08)}
  .link-card{transition:transform .15s ease, box-shadow .15s ease, background .15s ease; cursor: pointer;}
  .link-card:hover{transform:translateY(-1px);background:var(--card-hover);box-shadow:0 0 0 2px var(--ring)}
  .shine{position:relative;overflow:hidden}
  .shine:before{content:"";position:absolute;inset:-200%;background:conic-gradient(from 180deg, transparent 0 340deg, rgba(255,255,255,.12) 360deg);animation:spin 6s linear infinite}
  @keyframes spin{to{transform:rotate(360deg)}}
  footer{margin-top:auto}
</style>
${cfg.customHead || ""}
</head>
<body class="text-[color:var(--text)]" data-theme="${cfg.theme || "violet"}" style="${bgStyle}">
${gtmNoscript}
  ${
    (cfg.gallery || []).length
      ? `<section class="mt-3 grid grid-cols-2 gap-1.5">${(cfg.gallery || [])
          .map((u) => `<img src="${u}" class="w-full h-24 object-cover rounded-lg" loading="lazy" referrerpolicy="no-referrer">`)
          .join("")}</section>`
      : ""
  }

  <section id="links" class="mt-3 grid gap-1.5">
    ${(cfg.links || [])
      .map((l, i) => {
        try {
          const u = new URL(l.url);
          if (l.utm) Object.entries(l.utm).forEach(([k, v]) => { if (v) u.searchParams.set(k, v); });
          const badge = l.badge
            ? `<span class="ml-2 text-[10px] px-1.5 py-0.5 rounded bg-[color:var(--accent)]/10 text-[color:var(--accent)]">${l.badge}</span>`
            : "";
          return `<a href="${u.toString()}" data-href="${u.toString()}"
                    class="link-card glass rounded-xl p-2.5 flex items-center gap-2.5 ${l.highlight ? "ring-2 ring-[color:var(--accent)]" : ""}"
                    data-event="${l.eventName || "LinkClick"}"
                    data-title="${(l.title || "Link") + i}"
                    target="_blank" rel="noopener">
            <div class="text-xl">${l.icon || "🔗"}</div>
            <div class="flex-1 min-w-0">
              <div class="font-medium truncate">${l.title || ""} ${badge}</div>
              <div class="text-xs text-[color:var(--muted)] break-all">${u.hostname}</div>
            </div>
            <div class="text-sm opacity-80">↗</div></a>`;
        } catch { return ""; }
      }).join("")}
  </section>
</main>

<footer class="mt-3 mb-3 text-center text-xs text-white/80">${cfg.footer || ""}</footer>

<div id=consent class="fixed inset-x-0 bottom-2 mx-auto max-w-xl glass rounded-xl p-2.5 shadow hidden">
  <div class="text-sm">เราใช้คุกกี้เพื่อวิเคราะห์และปรับปรุงประสบการณ์ของคุณ ยอมรับการวัดผลโฆษณาหรือไม่?</div>
  <div class="mt-1.5 flex gap-1.5 justify-end">
    <button id=deny class="px-3 py-1.5 rounded bg-white/10">ปฏิเสธ</button>
    <button id=allow class="px-3 py-1.5 rounded bg-[color:var(--accent)]">ยอมรับ</button>
  </div>
</div>

${(cfg.customBundles || []).join("\n")}
${cfg.customBodyEnd || ""}

<script>
  // Theme switch
  const themes=['violet','emerald','crimson'], btn=document.getElementById('themeBtn');
  if(btn){ btn.onclick=()=>{ const i=themes.indexOf(document.body.getAttribute('data-theme')); const next=themes[(i+1)%themes.length]; document.body.setAttribute('data-theme',next); }; }

  // Consent
  const consentKey='bio_consent'; const box=document.getElementById('consent');
  const consent=localStorage.getItem(consentKey); if(consent===null && box){ box.classList.remove('hidden'); }
  document.getElementById('deny')?.addEventListener('click',()=>{ localStorage.setItem(consentKey,'0'); box.remove(); });
  document.getElementById('allow')?.addEventListener('click',()=>{ localStorage.setItem(consentKey,'1'); box.remove(); loadPixels(); });
</script>

<script>
// ===== Universal Link Tracking (non-blocking) + fbp/fbc helper =====
function getCookie(n){return document.cookie.split('; ').find(x=>x.startsWith(n+'='))?.split('=')[1]||'';}
function getFbp(){ return getCookie('_fbp')||''; }
function getFbc(){
  const fbclid=new URLSearchParams(location.search).get('fbclid');
  if(fbclid) return \`fb.1.\${Date.now()}.\${fbclid}\`;
  return getCookie('_fbc')||'';
}
function beacon(url, payload){
  try{
    if(navigator.sendBeacon){
      const data = new Blob([JSON.stringify(payload)], {type:'application/json'});
      navigator.sendBeacon(url, data);
      return true;
    }
    fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload),keepalive:true});
  }catch(e){}
}
function track(name, params={}, userData={}){
  const event_id=(crypto?.randomUUID?.()||(Date.now().toString(36)+Math.random().toString(36).slice(2))).slice(0,36);
  const payload={
    name,
    params,
    event_id,
    url: location.href,
    user_data: {
      fbp: getFbp() || undefined,
      fbc: getFbc() || undefined,
      external_id: userData.external_id,
      email: userData.email,
      phone: userData.phone
    }
  };
  beacon('/api/track', payload);

  try{ window.fbq && fbq('trackCustom', name, {...params, event_id}); }catch(e){}
  try{ window.ttq && ttq.track(name, {...params, event_id}); }catch(e){}
  try{ window.gtag && gtag('event', name, {...params, event_id}); }catch(e){}
  try{ window.dataLayer && window.dataLayer.push({event:name, event_id, ...params}); }catch(e){}
  return event_id;
}

// Track <a href> without blocking navigation
document.addEventListener('click', function(e){
  const a = e.target.closest('a[href]');
  if(!a) return;
  if(a.closest('[data-no-track]')) return;
  const label=(a.dataset.title || (a.textContent||'').trim()).slice(0,80);
  track(a.dataset.event || 'LinkClick', {label, to:a.href});
}, {capture:true});

// Support any non-<a> with data-href (if you add custom buttons)
document.addEventListener('click', function(e){
  const el = e.target.closest('[data-href]');
  if(!el) return;
  if (el.matches('a[href]')) return; // let normal <a> flow
  e.preventDefault();
  const to = el.dataset.href;
  const label=(el.dataset.title || (el.textContent||'').trim()).slice(0,80);
  track(el.dataset.event || 'LinkClick', {label, to});
  const a=document.createElement('a'); a.href=to; a.target='_blank'; a.rel='noopener'; document.body.appendChild(a); a.click(); a.remove();
});

// Middle-click tracking too (no blocking)
document.addEventListener('auxclick', function(e){
  if(e.button!==1) return;
  const el = e.target.closest('[data-href],a[href]');
  if(!el) return;
  const to = el.getAttribute('href') || el.dataset.href;
  const label=(el.dataset.title || (el.textContent||'').trim()).slice(0,80);
  track(el.dataset.event || 'LinkClick', {label, to});
}, {capture:true});
</script>

<script>
  // Injected arrays directly from server (safe)
  const __SIMPLE = ${JSON.stringify({
    facebook: (cfg.pixelsSimple?.facebook || []).filter(Boolean),
    tiktok: (cfg.pixelsSimple?.tiktok || []).filter(Boolean),
    ga4: (cfg.pixelsSimple?.ga4 || []).filter(Boolean),
    gtm: (cfg.pixelsSimple?.gtm || []).filter(Boolean),
    googleAds: (cfg.pixelsSimple?.googleAds || []).filter(Boolean),
    twitter: (cfg.pixelsSimple?.twitter || []).filter(Boolean),
  })};

  function loadPixels(){
    if(localStorage.getItem('bio_consent')!=='1') return;

    // GTM
    (__SIMPLE.gtm||[]).forEach(id=>{
      (function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start': new Date().getTime(),event:'gtm.js'});
      var f=d.getElementsByTagName(s)[0], j=d.createElement(s), dl=l!='dataLayer'?'&l='+l:'';
      j.async=true; j.src='https://www.googletagmanager.com/gtm.js?id='+encodeURIComponent(i)+dl;
      f.parentNode.insertBefore(j,f);})(window,document,'script','dataLayer',id);
    });

    // GA4 + Google Ads via gtag
    const firstGtag = (__SIMPLE.ga4||[])[0] || (__SIMPLE.googleAds||[])[0];
    if(firstGtag){
      const s=document.createElement('script'); s.async=true; s.src='https://www.googletagmanager.com/gtag/js?id='+encodeURIComponent(firstGtag); document.head.appendChild(s);
      window.dataLayer=window.dataLayer||[]; function gtag(){dataLayer.push(arguments);} window.gtag=gtag; gtag('js', new Date());
      (__SIMPLE.ga4||[]).forEach(id=> gtag('config', id));
      (__SIMPLE.googleAds||[]).forEach(id=> gtag('config', id));
    }

    // Facebook Pixel
    if((__SIMPLE.facebook||[]).length){
      !function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod? n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window, document,'script','https://connect.facebook.net/en_US/fbevents.js');
      (__SIMPLE.facebook||[]).forEach(id=>{ try{ fbq('init', id); }catch(e){} });
      try{ fbq('track','PageView'); }catch(e){}
    }

    // TikTok
    if((__SIMPLE.tiktok||[]).length){
      !function (w, d, t) { w.TiktokAnalyticsObject = t; var ttq = w[t] = w[t] || []; ttq.methods = ['page', 'track', 'identify', 'instances', 'debug', 'on', 'off', 'once', 'ready', 'alias', 'group', 'enableCookie', 'disableCookie'], ttq.setAndDefer = function (t, e) { t[e] = function () { t.push([e].concat(Array.prototype.slice.call(arguments, 0))) } }; for (var i = 0; i < ttq.methods.length; i++) ttq.setAndDefer(ttq, ttq.methods[i]); ttq.instance = function (t) { for (var e = ttq._i[t] || [], n = 0; n < ttq.methods.length; n++) ttq.setAndDefer(e, ttq.methods[n]); return e }, ttq.load = function (e, n) { var i = 'https://analytics.tiktok.com/i18n/pixel/events.js'; ttq._i = ttq._i || {}, ttq._i[e] = []; ttq._t = ttq._t || {}; ttq._t[e] = +new Date; ttq._o[e] = n || {}; var o = document.createElement('script'); o.type = 'text/javascript'; o.async = !0; o.src = i + '?sdkid=' + e + '&lib=' + t; var a = document.getElementsByTagName('script')[0]; a.parentNode.insertBefore(o, a) }; }(window, document, 'ttq');
      (__SIMPLE.tiktok||[]).forEach(id=>{ try{ ttq.load(id); ttq.page(); }catch(e){} });
    }

    // Twitter/X
    if((__SIMPLE.twitter||[]).length){
      !function(e,t,n,s,u,a){e.twq||(s=e.twq=function(){s.exe?s.exe.apply(s,arguments):s.queue.push(arguments);},s.version='1.1',s.queue=[],u=t.createElement(n),u.async=!0,u.src='https://static.ads-twitter.com/uwt.js',a=t.getElementsByTagName(n)[0],a.parentNode.insertBefore(u,a))}(window,document,'script');
      (__SIMPLE.twitter||[]).forEach(id=>{ try{ twq('init', id); }catch(e){} });
      try{ twq('track','PageView'); }catch(e){}
    }
  }
  if(localStorage.getItem('bio_consent')==='1'){ loadPixels(); }
</script>
</body></html>`;
}

// ===== Public routes =====
app.get(["/", "/:tenant"], (req, res) => {
  const tenant = tenantFromReq(req);
  const cfg = getTenantConfig(tenant);
  res.type("html").send(renderClientHTML(cfg));
});

// User page: /:tenant/:userSlug
app.get("/:tenant/:user", (req, res, next) => {
  const { tenant, user } = req.params;
  const u = getUser(user);
  if (!u || u.tenant !== tenant) return next();
  res.type("html").send(renderClientHTML(u));
});
// Shortcut: /_u/:userSlug
app.get("/_u/:user", (req, res, next) => {
  const u = getUser(req.params.user);
  if (!u) return next();
  res.redirect(`/${u.tenant}/${req.params.user}`);
});

// ===== Tracking (server fan-out to CAPI/GA4/TikTok) =====
app.post("/api/track", async (req, res) => {
  try {
    const name = req.body?.name || "Event";
    const params = req.body?.params || {};
    const url = req.body?.url || "";
    const event_id = req.body?.event_id || uuidv4();

    // detect page owner (user or tenant) by referrer path if available
    const path = new URL(url, "http://x").pathname || "/";
    const seg = path.split("/").filter(Boolean);
    let cfg = null;
    if (seg[0] === "_u" && seg[1]) {
      const u = getUser(seg[1]);
      if (u) cfg = u;
    } else if (seg[0] && seg[1]) {
      const u = getUser(seg[1]);
      if (u && u.tenant === seg[0]) cfg = u;
    }
    if (!cfg && seg[0]) cfg = getTenantConfig(seg[0]) || getTenantConfig("default");
    if (!cfg) cfg = getTenantConfig("default");

    const client_ip = getClientIP(req);
    const user_agent = req.headers["user-agent"] || "";
    const now = Math.floor(Date.now() / 1000);

    // ---- Build user_data for CAPI (hash PII) ----
    const rawUD = req.body?.user_data || {};
    function H(x){ return x ? sha256(x) : undefined; }
    const user_data = {
      client_ip_address: client_ip,
      client_user_agent: user_agent,
      fbp: rawUD.fbp || undefined,
      fbc: rawUD.fbc || undefined,
      external_id: H(rawUD.external_id),
      em: H(rawUD.email),
      ph: H(rawUD.phone),
    };

    const tasks = [];

    // Facebook CAPI
    for (const fbp of cfg.pixelsAdvanced?.facebook || []) {
      const { pixelId, accessToken, testEventCode } = fbp || {};
      if (!pixelId || !accessToken) continue;
      const fbEvent = {
        data: [
          {
            event_name: name,
            event_time: now,
            event_id,
            action_source: "website",
            event_source_url: url,
            user_data,
            custom_data: params,
          },
        ],
        test_event_code: testEventCode || undefined,
      };
      tasks.push(
        axios
          .post(`https://graph.facebook.com/v20.0/${encodeURIComponent(pixelId)}/events`, fbEvent, {
            params: { access_token: accessToken },
          })
          .catch((e) => ({ error: e?.response?.data || e.message }))
      );
    }

    // GA4 Measurement Protocol
    for (const g of cfg.pixelsAdvanced?.ga4 || []) {
      const { measurementId, apiSecret } = g || {};
      if (!measurementId || !apiSecret) continue;
      const body = { client_id: nanoid(), events: [{ name, params: { ...params, event_id } }] };
      tasks.push(
        axios
          .post(
            `https://www.google-analytics.com/mp/collect?measurement_id=${encodeURIComponent(measurementId)}&api_secret=${encodeURIComponent(apiSecret)}`,
            body
          )
          .catch((e) => ({ error: e?.response?.data || e.message }))
      );
    }

    // TikTok Events API
    for (const t of cfg.pixelsAdvanced?.tiktok || []) {
      const { pixelCode, accessToken } = t || {};
      if (!pixelCode || !accessToken) continue;
      const body = {
        pixel_code: pixelCode,
        event: name,
        timestamp: new Date().toISOString(),
        context: { page: { url }, user: { user_agent } },
        properties: { ...params, event_id },
      };
      tasks.push(
        axios
          .post("https://business-api.tiktok.com/open_api/v1.3/pixel/track/", body, {
            headers: { "Access-Token": accessToken, "Content-Type": "application/json" },
          })
          .catch((e) => ({ error: e?.response?.data || e.message }))
      );
    }

    await Promise.allSettled(tasks);
    res.json({ ok: true, event_id });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ===== Start =====
app.listen(PORT, () => {
  console.log("BioLink Multi-Pixel v4.6 running on http://localhost:" + PORT);
});
