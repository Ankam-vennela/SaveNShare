function initDatabase(db, callback) {
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT CHECK(role IN ('donor', 'recipient')) NOT NULL
    )`);

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

    db.run(`CREATE TABLE IF NOT EXISTS stats (
      id INTEGER PRIMARY KEY,
      totalDonations INTEGER DEFAULT 0,
      totalHelped INTEGER DEFAULT 0
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      token TEXT NOT NULL,
      expiresAt DATETIME NOT NULL,
      FOREIGN KEY (userId) REFERENCES users(id)
    )`);

    db.run(
      'INSERT OR IGNORE INTO stats (id, totalDonations, totalHelped) VALUES (1, 0, 0)',
      callback
    );
  });
}

module.exports = { initDatabase };
