import express from "express";
import fs from "fs";
import path from "path";
import bodyParser from "body-parser";

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const DB_PATH = path.join(process.cwd(), "db.json");

/* ---------------- DB ---------------- */
function defaultDB() {
  return {
    tenants: {
      default: {
        pixels: [],
        customBundles: [],
        bgImage: "",
      },
    },
  };
}

function migrateDB(db) {
  Object.values(db.tenants || {}).forEach((t) => {
    if (typeof t.customBundle === "string" && t.customBundle.trim()) {
      t.customBundles = Array.isArray(t.customBundles) ? t.customBundles : [];
      t.customBundles.push(t.customBundle);
      delete t.customBundle;
    }
    if (!Array.isArray(t.customBundles)) t.customBundles = [];
  });
  return db;
}

function readDB() {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify(defaultDB(), null, 2));
  }
  const db = JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  const migrated = migrateDB(db);
  if (JSON.stringify(migrated) !== JSON.stringify(db)) {
    fs.writeFileSync(DB_PATH, JSON.stringify(migrated, null, 2));
  }
  return migrated;
}

function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function getTenantConfig(tenant) {
  const db = readDB();
  return db.tenants[tenant] || {};
}

function saveTenantConfig(tenant, cfg) {
  const db = readDB();
  db.tenants[tenant] = cfg;
  saveDB(db);
}

/* ---------------- Middleware ---------------- */
function requireAdmin(req, res, next) {
  // demo: ไม่เช็ค login
  next();
}

function sanitize(str) {
  return (str || "").toString();
}

/* ---------------- Admin UI ---------------- */
app.get("/admin/:tenant", requireAdmin, (req, res) => {
  const t = req.params.tenant;
  const cfg = getTenantConfig(t);
  const esc = (s) =>
    (s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  res.type("html").send(`<!doctype html><meta charset=utf-8>
<title>Admin ${t}</title>
<style>
body{font-family:sans-serif;background:#0b1220;color:#fff}
.wrap{max-width:900px;margin:24px auto;padding:0 16px}
textarea{width:100%;min-height:200px;background:#111;color:#eee;border:1px solid #333;border-radius:8px;padding:8px}
input,button{padding:6px 10px;border-radius:6px;border:none}
button{cursor:pointer}
.bg{background:#111;padding:12px;border-radius:8px;margin:12px 0}
</style>
<div class=wrap>
  <h1>Admin — ${t}</h1>

  <div class=bg>
    <h2>Background Image</h2>
    <form method=post action="/admin/${t}/bg">
      <input name=bg value="${esc(cfg.bgImage)}" style="width:100%" placeholder="https://example.com/bg.jpg">
      <button>บันทึก</button>
    </form>
  </div>

  <div class=bg>
    <h2>Custom Code Bundles (HTML + CSS + JS)</h2>
    <form method=post action="/admin/${t}/custom-bundles/add">
      <textarea name=bundle placeholder="<!-- custom code -->"></textarea>
      <button>เพิ่มก้อนโค้ด</button>
    </form>
    ${(cfg.customBundles || [])
      .map(
        (c, i) => `
      <div class=bg>
        <div>Bundle #${i + 1}</div>
        <form method=post action="/admin/${t}/custom-bundles/update">
          <input type=hidden name=idx value="${i}">
          <textarea name=bundle>${esc(c)}</textarea>
          <button>บันทึก</button>
        </form>
        <form method=post action="/admin/${t}/custom-bundles/delete" onsubmit="return confirm('ลบก้อนนี้?')">
          <input type=hidden name=idx value="${i}">
          <button>ลบ</button>
        </form>
      </div>
    `
      )
      .join("")}
    <p><a href="/admin/${t}/code-studio" style="color:cyan">เปิด Code Studio</a></p>
  </div>
</div>`);
});

/* ---------------- Admin Post ---------------- */
app.post("/admin/:tenant/bg", requireAdmin, (req, res) => {
  const t = req.params.tenant;
  const cfg = getTenantConfig(t);
  cfg.bgImage = req.body.bg || "";
  saveTenantConfig(t, cfg);
  res.redirect("/admin/" + t);
});

app.post("/admin/:tenant/custom-bundles/add", requireAdmin, (req, res) => {
  const t = req.params.tenant;
  const cfg = getTenantConfig(t);
  cfg.customBundles = cfg.customBundles || [];
  cfg.customBundles.push(sanitize(req.body.bundle));
  saveTenantConfig(t, cfg);
  res.redirect("/admin/" + t);
});

app.post("/admin/:tenant/custom-bundles/update", requireAdmin, (req, res) => {
  const t = req.params.tenant;
  const cfg = getTenantConfig(t);
  const i = parseInt(req.body.idx, 10);
  if (cfg.customBundles && cfg.customBundles[i] !== undefined) {
    cfg.customBundles[i] = sanitize(req.body.bundle);
    saveTenantConfig(t, cfg);
  }
  res.redirect("/admin/" + t);
});

app.post("/admin/:tenant/custom-bundles/delete", requireAdmin, (req, res) => {
  const t = req.params.tenant;
  const cfg = getTenantConfig(t);
  const i = parseInt(req.body.idx, 10);
  if (cfg.customBundles && cfg.customBundles[i] !== undefined) {
    cfg.customBundles.splice(i, 1);
    saveTenantConfig(t, cfg);
  }
  res.redirect("/admin/" + t);
});

/* ---------------- Code Studio ---------------- */
app.get("/admin/:tenant/code-studio", requireAdmin, (req, res) => {
  const t = req.params.tenant;
  const cfg = getTenantConfig(t);
  const esc = (s) =>
    (s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  res.type("html").send(`<!doctype html><meta charset=utf-8>
<title>Code Studio — ${t}</title>
<style>
body{background:#0f172a;color:#eee;font-family:monospace;padding:20px}
.ta{width:100%;min-height:300px;background:#111;color:#eee;border:1px solid #333;border-radius:8px;padding:10px}
.card{background:#1e293b;padding:16px;border-radius:8px;margin:16px 0}
button{background:#2563eb;color:#fff;border:none;border-radius:6px;padding:8px 14px;cursor:pointer}
.danger{background:#dc2626}
</style>
<h1>Code Studio — ${t}</h1>
<form method=post action="/admin/${t}/custom-bundles/add" class=card>
  <h3>เพิ่มก้อนใหม่</h3>
  <textarea class=ta name=bundle></textarea>
  <button>เพิ่ม</button>
</form>
${(cfg.customBundles||[]).map((c,i)=>`
  <div class=card>
    <h3>Bundle #${i+1}</h3>
    <form method=post action="/admin/${t}/custom-bundles/update">
      <input type=hidden name=idx value="${i}">
      <textarea class=ta name=bundle>${esc(c)}</textarea>
      <button>บันทึก</button>
    </form>
    <form method=post action="/admin/${t}/custom-bundles/delete" onsubmit="return confirm('ลบ?')">
      <input type=hidden name=idx value="${i}">
      <button class=danger>ลบ</button>
    </form>
  </div>`).join("")}
<p><a href="/admin/${t}" style="color:cyan">← กลับ Admin</a></p>`);
});

/* ---------------- Client ---------------- */
app.get("/:tenant", (req, res) => {
  const t = req.params.tenant;
  const cfg = getTenantConfig(t);
  res.type("html").send(`<!doctype html><meta charset=utf-8>
<title>${t}</title>
<style>
body{margin:0;min-height:100vh;background:${cfg.bgImage?`url('${cfg.bgImage}') center/cover no-repeat`:"#111"};color:#fff;display:flex;align-items:center;justify-content:center;font-family:sans-serif}
</style>
<h1>Hello from ${t}</h1>
${(cfg.customBundles||[]).join("\n")}
`);
});

/* ---------------- Start ---------------- */
// ให้ Express เชื่อ proxy เพื่อให้ req.protocol เป็น https เวลาอยู่หลัง CDN/Proxy
app.set('trust proxy', true);

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const HOST = process.env.HOST || '0.0.0.0';

// เดา URL สาธารณะจาก env ของแต่ละแพลตฟอร์ม (ถ้าไม่มีก็แสดง localhost)
const PUBLIC_URL =
  process.env.RENDER_EXTERNAL_URL ||                                  // Render
  (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : '') || // Vercel
  process.env.DEPLOY_URL || process.env.URL ||                        // Netlify
  `http://localhost:${PORT}`;

app.listen(PORT, HOST, () => {
  console.log(`BioLink Multi-Pixel v4.x running on ${PUBLIC_URL}`);
});
