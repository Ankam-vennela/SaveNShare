const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('database.db');

db.serialize(() => {
  // USERS TABLE
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT CHECK(role IN ('donor', 'recipient')) NOT NULL
  )`);

  // DONATIONS TABLE
  db.run(`CREATE TABLE IF NOT EXISTS donations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    donorId INTEGER NOT NULL,
    image TEXT,
    foodType TEXT,
    quantity TEXT,
    bestBeforeHours INTEGER,
    phone TEXT,
    details TEXT NOT NULL,
    address TEXT NOT NULL,
    status TEXT DEFAULT 'posted',
    requesterId INTEGER,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (donorId) REFERENCES users(id),
    FOREIGN KEY (requesterId) REFERENCES users(id)
  )`);

  // STATS TABLE
  db.run(`CREATE TABLE IF NOT EXISTS stats (
    id INTEGER PRIMARY KEY,
    totalDonations INTEGER DEFAULT 0,
    totalHelped INTEGER DEFAULT 0
  )`);

  // PASSWORD RESET TOKENS TABLE
  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    token TEXT NOT NULL,
    expiresAt DATETIME NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id)
  )`);

  // ENSURE ONE ROW IN STATS
  db.run(
    'INSERT OR IGNORE INTO stats (id, totalDonations, totalHelped) VALUES (1, 0, 0)'
  );
});

db.close();
console.log('Database initialized!');
