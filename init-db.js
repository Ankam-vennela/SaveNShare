const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { initDatabase } = require('./db-init');

const db = new sqlite3.Database(path.join(__dirname, 'database.db'));
initDatabase(db, () => {
  db.close();
  console.log('Database initialized!');
});
