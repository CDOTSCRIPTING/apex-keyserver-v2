const Database = require('better-sqlite3');
const db = new Database('keys.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    id TEXT PRIMARY KEY,
    key TEXT UNIQUE,
    type TEXT,
    hwid TEXT,
    username TEXT,
    expires_at INTEGER,
    created_at INTEGER,
    banned INTEGER DEFAULT 0
  );
`);

// Migrate existing table
try { db.exec("ALTER TABLE keys ADD COLUMN banned INTEGER DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE keys ADD COLUMN username TEXT"); } catch (e) {}

module.exports = db;
