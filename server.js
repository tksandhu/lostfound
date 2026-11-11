const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

// Local use: settings come from config.txt. On Vercel: settings come from Environment Variables.
try { process.loadEnvFile(path.join(__dirname, 'config.txt')); } catch (e) { /* no config.txt: use environment variables */ }

const { DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT = 3306, DB_SSL, JWT_SECRET, PORT = 3000 } = process.env;
const missing = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'JWT_SECRET'].filter(k => !process.env[k]);
if (missing.length) console.error('Missing settings: ' + missing.join(', '));
if (DB_PASSWORD === 'PUT_YOUR_MYSQL_PASSWORD_HERE') missing.push('DB_PASSWORD (still the placeholder in config.txt)');

const pool = mysql.createPool({
  host: DB_HOST, port: Number(DB_PORT), user: DB_USER, password: DB_PASSWORD, database: DB_NAME,
  connectionLimit: 3, enableKeepAlive: true, dateStrings: true,
  ssl: DB_SSL === 'true' ? { minVersion: 'TLSv1.2', rejectUnauthorized: true } : undefined
});

const app = express();
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public'))); // used locally; Vercel serves /public itself

app.use('/api', (req, res, next) =>
  missing.length ? res.status(500).json({ error: 'Server is missing settings: ' + missing.join(', ') }) : next());

// Photos are kept in memory briefly, then stored inside MySQL (no folders needed).
const TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (req, f, cb) => TYPES.includes(f.mimetype) ? cb(null, true) : cb(new Error('Only JPG, PNG, WEBP or GIF images are allowed'))
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
            i.description, (i.image_data IS NOT NULL) AS has_image, i.resolved, i.created_at
     FROM items i JOIN users u ON u.id = i.user_id
     ORDER BY i.resolved, i.created_at DESC LIMIT 200`);
  res.json(rows);
}));

app.get('/api/items/:id/image', wrap(async (req, res) => {
  const [rows] = await pool.execute('SELECT image_data, image_type FROM items WHERE id = ?', [req.params.id]);
  if (!rows[0] || !rows[0].image_data) return res.status(404).end();
  res.set('Content-Type', rows[0].image_type || 'image/jpeg');
  res.set('Cache-Control', 'public, max-age=86400');
  res.send(rows[0].image_data);
}));

app.post('/api/items', auth, upload.single('image'), wrap(async (req, res) => {
  const b = req.body;
  const title = String(b.title || '').trim().slice(0, 80);
  if (!['lost', 'found'].includes(b.kind) || !title) return res.status(400).json({ error: 'Choose lost or found, and enter what the item is' });
  const date = /^\d{4}-\d{2}-\d{2}$/.test(b.date || '') ? b.date : null;
  await pool.execute(
    'INSERT INTO items (user_id, kind, title, category, place, item_date, description, image_data, image_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [req.user.id, b.kind, title, String(b.category || '').slice(0, 40), String(b.place || '').trim().slice(0, 80), date,
     String(b.description || '').trim().slice(0, 400), req.file ? req.file.buffer : null, req.file ? req.file.mimetype : null]);
  res.json({ ok: true });
}));

app.post('/api/items/:id/resolve', auth, wrap(async (req, res) => {
  const [r] = await pool.execute('UPDATE items SET resolved = NOT resolved WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!r.affectedRows) return res.status(403).json({ error: 'Only the person who posted this can do that' });
  res.json({ ok: true });
}));

app.delete('/api/items/:id', auth, wrap(async (req, res) => {
  const [rows] = await pool.execute('SELECT id FROM items WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!rows[0]) return res.status(403).json({ error: 'Only the person who posted this can delete it' });
  await pool.execute('DELETE FROM messages WHERE item_id = ?', [req.params.id]);
  await pool.execute('DELETE FROM items WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
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
  if (err instanceof multer.MulterError) return res.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'Photo is too big' : err.message });
  if (err.message && err.message.startsWith('Only JPG')) return res.status(400).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on the server' });
});

module.exports = app;
if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => console.log('Lost & Found is running: open http://localhost:' + PORT));
}
