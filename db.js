const Database = require('better-sqlite3');
const db = new Database('keys.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    id TEXT PRIMARY KEY,
    key TEXT UNIQUE,
    type TEXT,
    hwid TEXT,
    expires_at INTEGER,
    created_at INTEGER,
    banned INTEGER DEFAULT 0
  );
`);

// Migrate existing table if it lacks the banned column
try {
  db.exec("ALTER TABLE keys ADD COLUMN banned INTEGER DEFAULT 0");
} catch (e) {
  // Column already exists
}

module.exports = db;
