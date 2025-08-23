// server.js
const express = require('express');
const path = require('path');
const app = express();
app.use(express.json());
app.use('/data', express.static(path.join(__dirname, 'public/data')));
app.use('/', express.static(path.join(__dirname, 'public')));

// TODO: ภายหลังแก้ให้เรียก API ของผู้ให้บริการจริง และสร้างลายเซ็น HMAC ตามเอกสารของค่าย
app.post('/api/launch', async (req, res) => {
  const { gameId, playerId } = req.body || {};
  if(!gameId || !playerId) return res.status(400).json({ error:'missing params' });

  // ตัวอย่างลิงก์จำลอง (ของจริงจะได้มาจาก provider หลังตรวจลายเซ็น/สิทธิ์)
  const launchUrl = `https://example.provider/launch?gameId=${encodeURIComponent(gameId)}&sid=${Date.now()}&user=${encodeURIComponent(playerId)}`;
  res.json({ launchUrl });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log('running on http://localhost:'+PORT));
