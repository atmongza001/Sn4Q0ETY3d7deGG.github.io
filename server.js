// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname; // ← เสิร์ฟจากรากโฟลเดอร์ (ตรงกับรูปของคุณ)

app.use(express.json());

// เสิร์ฟไฟล์ static ทั้งหมดจากราก (index.html, gamesList.json)
app.use(express.static(ROOT, { index: 'index.html' }));

// Health check สำหรับ Render
app.get('/healthz', (_req, res) => res.status(200).send('ok'));

// ปุ่ม “เล่น” — เดโม่: ถ้ามี play.html จะเด้งไป play.html, ถ้าไม่มีตอบ ok
app.post('/api/launch', (req, res) => {
  const { gameId, playerId = 'demoUser' } = req.body || {};
  if (!gameId) return res.status(400).json({ error: 'missing params' });
  const sid = Date.now();

  const play = path.join(ROOT, 'play.html');
  if (fs.existsSync(play)) {
    return res.json({
      launchUrl: `/play.html?gameId=${encodeURIComponent(gameId)}&sid=${sid}&user=${encodeURIComponent(playerId)}`
    });
  }
  // ไม่มี play.html ก็ส่งแค่นี้ (ปุ่มฝั่งหน้าเว็บจะไม่ redirect)
  return res.json({ ok: true, gameId, playerId, sid });
});

// Fallback: เสิร์ฟ index.html ให้ทุกเส้นทาง GET
app.get('/*', (_req, res) => res.sendFile(path.join(ROOT, 'index.html')));

app.listen(PORT, '0.0.0.0', () => console.log('running on :' + PORT));
