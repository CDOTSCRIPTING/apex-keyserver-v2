const Database = require('better-sqlite3');
const db = new Database('keys.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    id TEXT PRIMARY KEY,
    key TEXT UNIQUE,
    type TEXT,
    hwid TEXT,
    expires_at INTEGER,
    created_at INTEGER
  );
`);

module.exports = db;
