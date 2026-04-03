const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const db = new Database('game.db');
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- DB Setup ---
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    btc REAL DEFAULT 0,
    gpu INTEGER DEFAULT 0,
    asic INTEGER DEFAULT 0,
    farm INTEGER DEFAULT 0,
    last_seen INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
`);

// --- Auth Middleware ---
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Routes ---

// Register
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username must be 3-20 chars' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be 6+ chars' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username: letters, numbers, _ only' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
    const result = stmt.run(username, hash);
    const token = jwt.sign({ id: result.lastInsertRowid, username }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, username });
  } catch (e) {
    res.status(400).json({ error: 'Username already taken' });
  }
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Wrong username or password' });
  }
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username, btc: user.btc, gpu: user.gpu, asic: user.asic, farm: user.farm });
});

// Save game
app.post('/api/save', auth, (req, res) => {
  const { btc, gpu, asic, farm } = req.body;
  const now = Math.floor(Date.now() / 1000);
  db.prepare('UPDATE users SET btc=?, gpu=?, asic=?, farm=?, last_seen=? WHERE id=?')
    .run(btc, gpu, asic, farm, now, req.user.id);
  res.json({ ok: true });
});

// Leaderboard (top 20)
app.get('/api/leaderboard', (req, res) => {
  const rows = db.prepare('SELECT username, btc FROM users ORDER BY btc DESC LIMIT 20').all();
  res.json(rows);
});

// Online players (seen in last 5 minutes)
app.get('/api/online', (req, res) => {
  const cutoff = Math.floor(Date.now() / 1000) - 300;
  const rows = db.prepare('SELECT username, btc FROM users WHERE last_seen > ? ORDER BY last_seen DESC').all(cutoff);
  res.json(rows);
});

// Heartbeat (keep online status alive)
app.post('/api/heartbeat', auth, (req, res) => {
  const now = Math.floor(Date.now() / 1000);
  db.prepare('UPDATE users SET last_seen=? WHERE id=?').run(now, req.user.id);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
