const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

try { process.loadEnvFile(path.join(__dirname, 'config.txt')); }
catch (e) { console.error('Could not read config.txt:', e.message); process.exit(1); }

const { DB_HOST = 'localhost', DB_USER = 'root', DB_PASSWORD = '', DB_NAME = 'lostfound', JWT_SECRET, PORT = 3000 } = process.env;
if (!JWT_SECRET) { console.error('config.txt needs a JWT_SECRET line'); process.exit(1); }
if (DB_PASSWORD === 'PUT_YOUR_MYSQL_PASSWORD_HERE') { console.error('Open config.txt and replace PUT_YOUR_MYSQL_PASSWORD_HERE with your MySQL password'); process.exit(1); }

const pool = mysql.createPool({ host: DB_HOST, user: DB_USER, password: DB_PASSWORD, database: DB_NAME, connectionLimit: 5, dateStrings: true });

const app = express();
app.use(express.json({ limit: '20kb' }));

const upDir = path.join(__dirname, 'uploads');
fs.mkdirSync(upDir, { recursive: true });
app.use('/uploads', express.static(upDir));
app.use(express.static(path.join(__dirname, 'public')));

const EXT = { 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp', 'image/gif': '.gif' };
const upload = multer({
  storage: multer.diskStorage({
    destination: upDir,
    filename: (req, f, cb) => cb(null, crypto.randomBytes(12).toString('hex') + EXT[f.mimetype])
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, f, cb) => EXT[f.mimetype] ? cb(null, true) : cb(new Error('Only JPG, PNG, WEBP or GIF images are allowed'))
});

const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
function auth(req, res, next) {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET); next(); }
  catch (e) { res.status(401).json({ error: 'Please log in first' }); }
}
function session(id, name) {
  return { token: jwt.sign({ id, name }, JWT_SECRET, { expiresIn: '30d' }), user: { id, name } };
}

// ---------- accounts ----------
app.post('/api/signup', wrap(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  const email = String(req.body.email || '').trim().toLowerCase();
  const pw = String(req.body.password || '');
  if (!name || email.length > 120 || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter your name and a valid email' });
  if (pw.length < 6 || pw.length > 100) return res.status(400).json({ error: 'Password must be 6 to 100 characters' });
  const hash = await bcrypt.hash(pw, 10);
  try {
    const [r] = await pool.execute('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', [name, email, hash]);
    res.json(session(r.insertId, name));
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'That email is already registered. Try logging in.' });
    throw e;
  }
}));

app.post('/api/login', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const [rows] = await pool.execute('SELECT id, name, password_hash FROM users WHERE email = ?', [email]);
  const u = rows[0];
  if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.password_hash))) return res.status(401).json({ error: 'Wrong email or password' });
  res.json(session(u.id, u.name));
}));

// ---------- items ----------
app.get('/api/items', wrap(async (req, res) => {
  const [rows] = await pool.query(
    `SELECT i.id, i.user_id, u.name AS poster, i.kind, i.title, i.category, i.place, i.item_date,
            i.description, i.image_file, i.resolved, i.created_at
     FROM items i JOIN users u ON u.id = i.user_id
     ORDER BY i.resolved, i.created_at DESC LIMIT 200`);
  res.json(rows);
}));

app.post('/api/items', auth, upload.single('image'), wrap(async (req, res) => {
  const b = req.body;
  const title = String(b.title || '').trim().slice(0, 80);
  if (!['lost', 'found'].includes(b.kind) || !title) {
    if (req.file) fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: 'Choose lost or found, and enter what the item is' });
  }
  const date = /^\d{4}-\d{2}-\d{2}$/.test(b.date || '') ? b.date : null;
  await pool.execute(
    'INSERT INTO items (user_id, kind, title, category, place, item_date, description, image_file) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [req.user.id, b.kind, title, String(b.category || '').slice(0, 40), String(b.place || '').trim().slice(0, 80), date,
     String(b.description || '').trim().slice(0, 400), req.file ? req.file.filename : null]);
  res.json({ ok: true });
}));

app.post('/api/items/:id/resolve', auth, wrap(async (req, res) => {
  const [r] = await pool.execute('UPDATE items SET resolved = NOT resolved WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!r.affectedRows) return res.status(403).json({ error: 'Only the person who posted this can do that' });
  res.json({ ok: true });
}));

app.delete('/api/items/:id', auth, wrap(async (req, res) => {
  const [rows] = await pool.execute('SELECT image_file FROM items WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!rows[0]) return res.status(403).json({ error: 'Only the person who posted this can delete it' });
  await pool.execute('DELETE FROM items WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (rows[0].image_file) fs.unlink(path.join(upDir, path.basename(rows[0].image_file)), () => {});
  res.json({ ok: true });
}));

// ---------- private messages (only the two people involved can read them) ----------
app.get('/api/items/:id/messages', auth, wrap(async (req, res) => {
  const [irows] = await pool.execute('SELECT user_id FROM items WHERE id = ?', [req.params.id]);
  if (!irows[0]) return res.status(404).json({ error: 'Post not found' });
  const [rows] = await pool.execute(
    `SELECT m.id, m.sender_id, m.receiver_id, m.body, m.created_at, s.name AS sender_name, r.name AS receiver_name
     FROM messages m JOIN users s ON s.id = m.sender_id JOIN users r ON r.id = m.receiver_id
     WHERE m.item_id = ? AND (m.sender_id = ? OR m.receiver_id = ?) ORDER BY m.id`,
    [req.params.id, req.user.id, req.user.id]);
  res.json({ owner_id: irows[0].user_id, messages: rows });
}));

app.post('/api/items/:id/messages', auth, wrap(async (req, res) => {
  const body = String(req.body.body || '').trim().slice(0, 300);
  if (!body) return res.status(400).json({ error: 'Type a message first' });
  const [irows] = await pool.execute('SELECT user_id FROM items WHERE id = ?', [req.params.id]);
  if (!irows[0]) return res.status(404).json({ error: 'Post not found' });
  const me = req.user.id;
  let to;
  if (irows[0].user_id === me) {
    // the poster can only reply to someone who already wrote to them about this item
    to = parseInt(req.body.to, 10);
    const [chk] = await pool.execute('SELECT 1 FROM messages WHERE item_id = ? AND sender_id = ? AND receiver_id = ? LIMIT 1', [req.params.id, to, me]);
    if (!to || !chk[0]) return res.status(400).json({ error: 'Choose who you are replying to' });
  } else {
    to = irows[0].user_id;
  }
  await pool.execute('INSERT INTO messages (item_id, sender_id, receiver_id, body) VALUES (?, ?, ?, ?)', [req.params.id, me, to, body]);
  res.json({ ok: true });
}));

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Photo is too big (max 5 MB)' : err.message });
  if (err.message && err.message.startsWith('Only JPG')) return res.status(400).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on the server' });
});

app.listen(PORT, '0.0.0.0', () => console.log('Lost & Found is running: open http://localhost:' + PORT));
