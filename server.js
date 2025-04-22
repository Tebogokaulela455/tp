const express    = require('express');
const bodyParser = require('body-parser');
const sqlite3    = require('sqlite3').verbose();
const bcrypt     = require('bcrypt');
const cors       = require('cors');
const app        = express();
const port       = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(cors());

// --- Initialize SQLite DB ---
const db = new sqlite3.Database('./database.db', err => {
  if (err) console.error('DB error', err);
});
db.serialize(() => {
  // Users table with subscription columns
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    subscriptionExpiry TEXT,
    hasPaid INTEGER DEFAULT 0
  )`);
  // Other tables unchanged
  db.run(`CREATE TABLE IF NOT EXISTS members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    idNumber TEXT UNIQUE NOT NULL,
    address TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    memberId INTEGER NOT NULL,
    planType TEXT,
    coverLevel REAL,
    premium REAL,
    startDate TEXT,
    status TEXT,
    FOREIGN KEY(memberId) REFERENCES members(id)
  )`);
});

// Utility: add 30‑day trial expiry to a user
function addTrialToUser(userId) {
  const expiry = new Date(Date.now() + 30*24*60*60*1000).toISOString();
  db.run(
    'UPDATE users SET subscriptionExpiry = ? WHERE id = ?',
    [expiry, userId],
    err => { if (err) console.error('Failed to set trial expiry', err); }
  );
}

// --- Auth Routes ---

// Register: creates user + 30‑day trial
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO users (name, email, password) VALUES (?,?,?)',
      [name, email, hash],
      function(err) {
        if (err) {
          if (err.code === 'SQLITE_CONSTRAINT') {
            return res.status(400).json({ error: 'Email already in use' });
          }
          return res.status(500).json({ error: 'DB error' });
        }
        // Give the new user a 30‑day free trial
        addTrialToUser(this.lastID);
        res.json({
          message: 'Registered. Free trial active for 30 days.',
          trialEnds: new Date(Date.now()+30*24*60*60*1000).toISOString()
        });
      }
    );
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login: blocks if trial expired
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'All fields required' });
  }
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    const now = new Date();
    const expiry = user.subscriptionExpiry ? new Date(user.subscriptionExpiry) : null;
    if (!expiry || expiry < now) {
      return res.status(403).json({
        error: 'Your free trial has expired. Please pay R300 to continue.',
        trialExpired: true,
        expiryDate: user.subscriptionExpiry
      });
    }

    // Success – in a real app you’d issue a JWT/session here
    res.json({ message: 'Login successful' });
  });
});

// --- Subscription Payment ---

// Renew subscription (extend by 30 days) after payment
app.post('/api/subscription/pay', (req, res) => {
  const { userId, reference } = req.body;
  if (!userId || !reference) {
    return res.status(400).json({ error: 'User ID and payment reference required' });
  }
  // In production you’d verify the reference against your bank
  const newExpiry = new Date(Date.now() + 30*24*60*60*1000).toISOString();
  db.run(
    'UPDATE users SET hasPaid = 1, subscriptionExpiry = ? WHERE id = ?',
    [newExpiry, userId],
    err => {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json({
        message: 'Payment received. Subscription renewed for 30 days.',
        newExpiry
      });
    }
  );
});

// --- Members CRUD (unchanged) ---
app.get('/api/members', (req, res) => {
  db.all('SELECT * FROM members', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});
app.get('/api/members/:id', (req, res) => {
  db.get('SELECT * FROM members WHERE id=?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(row);
  });
});
app.post('/api/members', (req, res) => {
  const { name, idNumber, address } = req.body;
  db.run('INSERT INTO members (name,idNumber,address) VALUES (?,?,?)',
    [name, idNumber, address], function(err) {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json({ id: this.lastID });
    }
  );
});
app.put('/api/members/:id', (req, res) => {
  const { name, idNumber, address } = req.body;
  db.run('UPDATE members SET name=?,idNumber=?,address=? WHERE id=?',
    [name, idNumber, address, req.params.id],
    err => err ? res.status(500).json({ error: 'DB error' }) : res.sendStatus(200)
  );
});
app.delete('/api/members/:id', (req, res) => {
  db.run('DELETE FROM members WHERE id=?', [req.params.id],
    err => err ? res.status(500).json({ error: 'DB error' }) : res.sendStatus(200)
  );
});

// --- Policies CRUD (unchanged) ---
app.get('/api/policies', (req, res) => {
  db.all('SELECT * FROM policies', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});
app.get('/api/policies/:id', (req, res) => {
  db.get('SELECT * FROM policies WHERE id=?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(row);
  });
});
app.post('/api/policies', (req, res) => {
  const { memberId, planType, coverLevel, premium, startDate, status } = req.body;
  db.run(
    'INSERT INTO policies (memberId,planType,coverLevel,premium,startDate,status) VALUES (?,?,?,?,?,?)',
    [memberId, planType, coverLevel, premium, startDate, status],
    function(err) {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json({ id: this.lastID });
    }
  );
});
app.put('/api/policies/:id', (req, res) => {
  const { planType, coverLevel, premium, startDate, status } = req.body;
  db.run(
    'UPDATE policies SET planType=?,coverLevel=?,premium=?,startDate=?,status=? WHERE id=?',
    [planType, coverLevel, premium, startDate, status, req.params.id],
    err => err ? res.status(500).json({ error: 'DB error' }) : res.sendStatus(200)
  );
});
app.delete('/api/policies/:id', (req, res) => {
  db.run('DELETE FROM policies WHERE id=?', [req.params.id],
    err => err ? res.status(500).json({ error: 'DB error' }) : res.sendStatus(200)
  );
});

// --- Start Server ---
app.listen(port, () => console.log(`Server running on port ${port}`));
