// server.js
const express = require('express');
const path = require('path');
const app = express();

const PORT = process.env.PORT || 3000;          // ✅ ใช้พอร์ตจาก Render
const PUB  = path.join(__dirname, 'public');

app.use(express.json());
app.use(express.static(PUB, { index: 'index.html' }));

// ปุ่ม "เล่น" → ลิงก์ไปหน้าเดโม่ภายในเว็บ
app.post('/api/launch', (req, res) => {
  const { gameId, playerId = 'demoUser' } = req.body || {};
  if (!gameId) return res.status(400).json({ error: 'missing params' });
  const sid = Date.now();
  res.json({ launchUrl: `/play.html?gameId=${encodeURIComponent(gameId)}&sid=${sid}&user=${encodeURIComponent(playerId)}` });
});

// Health check สำหรับ Render
app.get('/healthz', (_req, res) => res.status(200).send('ok'));

// Fallback (Express 5): จับทุกเส้นทางให้เสิร์ฟ index.html
app.use((req, res) => res.sendFile(path.join(PUB, 'index.html')));

app.listen(PORT, '0.0.0.0', () => console.log('running on :' + PORT));
