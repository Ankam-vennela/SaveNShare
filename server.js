const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
 
const app = express();
app.use(cors()); // Allow all origins for local dev
app.use(bodyParser.json());
// Serve static files from the "public" folder where HTML lives
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
 
const upload = multer({ dest: path.join(__dirname, 'uploads') });
const db = new sqlite3.Database(path.join(__dirname, 'database.db'));
const JWT_SECRET = 'savenShareSecret2026';
 
// Email transporter (configure with your Gmail app password)
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'yourapp@gmail.com',
    pass: process.env.EMAIL_PASS || 'your-app-password'
  }
});
 
// Lightweight schema migration: ensure review columns exist on donations
db.serialize(() => {
  db.run(
    'ALTER TABLE donations ADD COLUMN reviewRating INTEGER',
    (err) => {
      if (err && !/duplicate column name/i.test(err.message)) {
        console.error('Migration error (reviewRating):', err.message);
      }
    }
  );
  db.run(
    'ALTER TABLE donations ADD COLUMN reviewComment TEXT',
    (err) => {
      if (err && !/duplicate column name/i.test(err.message)) {
        console.error('Migration error (reviewComment):', err.message);
      }
    }
  );
  db.run(
    'ALTER TABLE donations ADD COLUMN reviewedAt DATETIME',
    (err) => {
      if (err && !/duplicate column name/i.test(err.message)) {
        console.error('Migration error (reviewedAt):', err.message);
      }
    }
  );
});

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};
 
// Update stats helper
const updateStats = (type) => {
  if (type === 'donation') db.run('UPDATE stats SET totalDonations = totalDonations + 1 WHERE id=1');
  if (type === 'helped') db.run('UPDATE stats SET totalHelped = totalHelped + 1 WHERE id=1');
};

function computeExpiryInfo(donation) {
  const best = donation && donation.bestBeforeHours != null ? parseInt(donation.bestBeforeHours, 10) : null;
  if (!best || best <= 0 || !donation.createdAt) {
    return { expiresAt: null, isExpired: false };
  }
  const createdMs = new Date(donation.createdAt).getTime();
  if (Number.isNaN(createdMs)) return { expiresAt: null, isExpired: false };
  const expiresMs = createdMs + best * 60 * 60 * 1000;
  return { expiresAt: new Date(expiresMs).toISOString(), isExpired: Date.now() > expiresMs };
}

function annotateDonation(d) {
  const { expiresAt, isExpired } = computeExpiryInfo(d);
  return { ...d, expiresAt, isExpired };
}
 
// ── AUTH ROUTES ──────────────────────────────────────────────────────────────
 
app.post('/api/donor/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (email, password, role) VALUES (?, ?, "donor")', [email, hashedPassword],
      function (err) {
        if (err) return res.status(400).json({ error: 'Email already registered' });
        const token = jwt.sign({ id: this.lastID, role: 'donor' }, JWT_SECRET);
        res.json({ token, message: 'Registered successfully' });
      });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});
 
app.post('/api/donor/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  db.get('SELECT * FROM users WHERE email = ? AND role = "donor"', [email], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
    res.json({ token });
  });
});
 
app.post('/api/recipient/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (email, password, role) VALUES (?, ?, "recipient")', [email, hashedPassword],
      function (err) {
        if (err) return res.status(400).json({ error: 'Email already registered' });
        const token = jwt.sign({ id: this.lastID, role: 'recipient' }, JWT_SECRET);
        res.json({ token, message: 'Registered successfully' });
      });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});
 
app.post('/api/recipient/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  db.get('SELECT * FROM users WHERE email = ? AND role = "recipient"', [email], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
    res.json({ token });
  });
});
 
// ── DONATION ROUTES ──────────────────────────────────────────────────────────
 
// Post donation
app.post('/api/donations', authenticateToken, upload.single('image'), (req, res) => {
  if (req.user.role !== 'donor') {
    return res.status(403).json({ error: 'Donors only' });
  }
  const { foodType, quantity, bestBeforeHours, address, phone, details } = req.body;
  if (!address) return res.status(400).json({ error: 'Pickup address is required' });
 
  const imagePath = req.file ? `/uploads/${req.file.filename}` : null;
 
  db.run(
    `INSERT INTO donations
      (donorId, image, foodType, quantity, bestBeforeHours, phone, details, address, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'posted')`,
    [
      req.user.id, imagePath,
      foodType || null, quantity || null,
      bestBeforeHours ? parseInt(bestBeforeHours) : null,
      phone || null, details || '', address
    ],
    function (err) {
      if (err) { console.error('INSERT donation error:', err); return res.status(500).json({ error: 'Failed to post donation' }); }
      updateStats('donation');
      res.json({ id: this.lastID, message: 'Donation posted!' });
    }
  );
});
 
// Get donations
// Donors: own donations (all statuses) + requester email
// Recipients: available (posted) donations only
app.get('/api/donations', authenticateToken, (req, res) => {
  if (req.user.role === 'donor') {
    db.all(
      `SELECT d.*, 
        (SELECT email FROM users WHERE id = d.requesterId) AS requesterEmail
       FROM donations d
       WHERE d.donorId = ?
       ORDER BY d.createdAt DESC`,
      [req.user.id],
      (err, rows) => {
        if (err) return res.status(500).json({ error: 'Error fetching donations' });
        const annotated = (rows || []).map(r => {
          const info = annotateDonation(r);
          // Auto-mark expired in DB for posted/requested items (keeps accepted intact)
          if (info.isExpired && (info.status === 'posted' || info.status === 'requested')) {
            info.status = 'expired';
            db.run('UPDATE donations SET status = "expired" WHERE id = ? AND status IN ("posted","requested")', [info.id]);
          }
          return info;
        });
        res.json(annotated);
      }
    );
  } else {
    db.all(
      `SELECT d.*, u.email AS donorEmail
       FROM donations d
       JOIN users u ON u.id = d.donorId
       WHERE d.status = 'posted'
         AND (d.bestBeforeHours IS NULL OR datetime(d.createdAt, '+' || d.bestBeforeHours || ' hours') > CURRENT_TIMESTAMP)
       ORDER BY d.createdAt DESC`,
      [],
      (err, rows) => {
        if (err) return res.status(500).json({ error: 'Error fetching donations' });
        res.json((rows || []).map(annotateDonation));
      }
    );
  }
});
 
// NEW: Recipient's own requests
app.get('/api/my-requests', authenticateToken, (req, res) => {
  if (req.user.role !== 'recipient') return res.status(403).json({ error: 'Recipients only' });
  db.all(
    `SELECT d.*, u.email AS donorEmail
     FROM donations d
     JOIN users u ON u.id = d.donorId
     WHERE d.requesterId = ?
     ORDER BY d.createdAt DESC`,
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Error fetching requests' });
      const annotated = (rows || []).map(r => {
        const info = annotateDonation(r);
        if (info.isExpired && info.status === 'requested') {
          info.status = 'expired';
          db.run('UPDATE donations SET status = "expired" WHERE id = ? AND status = "requested"', [info.id]);
        }
        return info;
      });
      res.json(annotated);
    }
  );
});
 
// Recipient requests a donation
app.post('/api/donations/:id/request', authenticateToken, (req, res) => {
  if (req.user.role !== 'recipient') return res.status(403).json({ error: 'Recipients only' });
  db.get(
    'SELECT * FROM donations WHERE id = ? AND status = "posted" AND (bestBeforeHours IS NULL OR datetime(createdAt, \'+\' || bestBeforeHours || \' hours\') > CURRENT_TIMESTAMP)',
    [req.params.id],
    (err, donation) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!donation) return res.status(400).json({ error: 'Donation is not available' });
    db.run(
      'UPDATE donations SET status = "requested", requesterId = ? WHERE id = ?',
      [req.user.id, req.params.id],
      function (err2) {
        if (err2) return res.status(500).json({ error: 'Could not request donation' });
        res.json({ message: 'Request sent to donor!' });
      }
    );
    });
});
 
// Donor accepts a request
app.post('/api/donations/:id/accept', authenticateToken, (req, res) => {
  if (req.user.role !== 'donor') return res.status(403).json({ error: 'Donors only' });
  db.get('SELECT * FROM donations WHERE id = ? AND donorId = ?', [req.params.id, req.user.id], (err, donation) => {
    if (!donation || donation.status !== 'requested') {
      return res.status(400).json({ error: 'Cannot accept: donation not in requested state' });
    }
    db.run('UPDATE donations SET status = "accepted" WHERE id = ?', [req.params.id], (err2) => {
      if (err2) return res.status(500).json({ error: 'Could not accept donation' });
      updateStats('helped');
      db.get('SELECT email FROM users WHERE id = ?', [donation.requesterId], (err3, recipient) => {
        if (recipient) {
          transporter.sendMail({
            to: recipient.email,
            subject: 'SaveNShare: Your Request Was Accepted! 🎉',
            text: `Your request for "${donation.foodType || 'food'}" was accepted!\n\nPickup: ${donation.address}\nContact: ${donation.phone || 'N/A'}\n\nPlease pick it up soon!`
          }).catch(e => console.log('Email error:', e.message));
        }
      });
      res.json({ message: 'Accepted! Recipient notified.' });
    });
  });
});
 
// Donor rejects/cancels a request (returns to posted)
app.post('/api/donations/:id/reject', authenticateToken, (req, res) => {
  if (req.user.role !== 'donor') return res.status(403).json({ error: 'Donors only' });
  db.get('SELECT * FROM donations WHERE id = ? AND donorId = ?', [req.params.id, req.user.id], (err, donation) => {
    if (!donation || donation.status !== 'requested') {
      return res.status(400).json({ error: 'Cannot reject: not in requested state' });
    }
    db.run('UPDATE donations SET status = "posted", requesterId = NULL WHERE id = ?', [req.params.id], (err2) => {
      if (err2) return res.status(500).json({ error: 'Could not reject' });
      res.json({ message: 'Request rejected. Donation is available again.' });
    });
  });
});
 
// Track donation
app.get('/api/donations/:id/track', authenticateToken, (req, res) => {
  const sql = req.user.role === 'donor'
    ? 'SELECT * FROM donations WHERE id = ? AND donorId = ?'
    : 'SELECT * FROM donations WHERE id = ? AND (donorId = ? OR requesterId = ?)';
  const params = req.user.role === 'donor'
    ? [req.params.id, req.user.id]
    : [req.params.id, req.user.id, req.user.id];
  db.get(sql, params, (err, donation) => {
    if (!donation) return res.status(404).json({ error: 'Not found' });
    const info = annotateDonation(donation);
    if (info.isExpired && (info.status === 'posted' || info.status === 'requested')) {
      info.status = 'expired';
      db.run('UPDATE donations SET status = "expired" WHERE id = ? AND status IN ("posted","requested")', [info.id]);
    }
    res.json(info);
  });
});

// Recipient leaves a review after receiving donation
app.post('/api/donations/:id/review', authenticateToken, (req, res) => {
  if (req.user.role !== 'recipient') {
    return res.status(403).json({ error: 'Recipients only' });
  }

  const { rating, comment } = req.body;
  const numericRating = parseInt(rating, 10);
  if (!numericRating || numericRating < 1 || numericRating > 5) {
    return res.status(400).json({ error: 'Rating must be between 1 and 5' });
  }

  // Ensure this recipient requested AND the donation was accepted
  db.get(
    'SELECT * FROM donations WHERE id = ? AND requesterId = ? AND status = "accepted"',
    [req.params.id, req.user.id],
    (err, donation) => {
      if (err) return res.status(500).json({ error: 'Server error' });
      if (!donation) {
        return res.status(400).json({ error: 'You can only review accepted donations you received' });
      }

      db.run(
        'UPDATE donations SET reviewRating = ?, reviewComment = ?, reviewedAt = CURRENT_TIMESTAMP WHERE id = ?',
        [numericRating, comment || null, req.params.id],
        (err2) => {
          if (err2) return res.status(500).json({ error: 'Could not save review' });
          res.json({ message: 'Thank you for your feedback!' });
        }
      );
    }
  );
});
 
// ── PASSWORD RESET ────────────────────────────────────────────────────────────
 
app.post('/api/auth/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!user) return res.json({ message: 'If this email exists, a reset link was sent.' });
 
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
 
    db.run('DELETE FROM password_resets WHERE userId = ?', [user.id], () => {
      db.run(
        'INSERT INTO password_resets (userId, token, expiresAt) VALUES (?, ?, ?)',
        [user.id, token, expiresAt],
        (err2) => {
          if (err2) return res.status(500).json({ error: 'Could not create reset token' });
          const resetLink = `http://localhost:3000/reset-password.html?token=${token}`;
          console.log('Password reset link (for testing):', resetLink);
          transporter.sendMail({
            to: user.email,
            subject: 'SaveNShare - Reset your password',
            text: `Click this link to reset your password:\n\n${resetLink}\n\nValid for 1 hour.`
          }, (mailErr) => {
            if (mailErr) console.log('Email error:', mailErr.message);
          });
          // Also return the reset link in the API response so it can be shown in the UI during local testing
          res.json({
            message: 'If this email exists, a reset link was sent.',
            resetLink
          });
        }
      );
    });
  });
});
 
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
 
  db.get('SELECT * FROM password_resets WHERE token = ?', [token], async (err, pr) => {
    if (err) return res.status(500).json({ error: 'Server error' });
    if (!pr) return res.status(400).json({ error: 'Invalid or expired link' });
    if (new Date(pr.expiresAt).getTime() < Date.now()) {
      db.run('DELETE FROM password_resets WHERE id = ?', [pr.id]);
      return res.status(400).json({ error: 'Link expired. Please request a new one.' });
    }
    const hashed = await bcrypt.hash(password, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, pr.userId], (err2) => {
      if (err2) return res.status(500).json({ error: 'Could not update password' });
      db.run('DELETE FROM password_resets WHERE id = ?', [pr.id]);
      res.json({ message: 'Password reset successfully. You can now login.' });
    });
  });
});
 
// ── STATS ────────────────────────────────────────────────────────────────────
 
app.get('/api/stats', (req, res) => {
  db.get('SELECT totalDonations, totalHelped FROM stats WHERE id=1', (err, stats) => {
    res.json(stats || { totalDonations: 0, totalHelped: 0 });
  });
});
 
// ── START ─────────────────────────────────────────────────────────────────────
 
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n✅ SaveNShare running at http://localhost:${PORT}`);
  console.log('📌 Run "node init-db.js" first if this is a fresh install.');
  console.log('📧 Set EMAIL_USER and EMAIL_PASS env vars for email features.\n');
});