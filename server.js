const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const db = require('./db');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());
app.use(cors());

const API_SECRET = "YourSecureSecret123!";

// 1. VALIDATION ENDPOINT
app.post('/validate', (req, res) => {
    const { key, hwid } = req.body;
    if (!key || !hwid) return res.status(400).json({ valid: false, error: "Missing parameters" });

    const row = db.prepare('SELECT * FROM keys WHERE key = ?').get(key);
    
    if (!row) return res.json({ valid: false, error: "Invalid key" });
    if (row.expires_at && Date.now() > row.expires_at) return res.json({ valid: false, error: "Key expired" });
    
    // HWID Locking
    if (!row.hwid) {
        db.prepare('UPDATE keys SET hwid = ? WHERE id = ?').run(hwid, row.id);
        return res.json({ valid: true, type: row.type, message: "HWID locked to this device" });
    } else if (row.hwid !== hwid) {
        return res.json({ valid: false, error: "Key locked to another device" });
    }

    return res.json({ valid: true, type: row.type });
});

// 2. WEBHOOK ENDPOINT
app.post('/webhook', (req, res) => {
    const { secret, product_type } = req.body; 
    if (secret !== API_SECRET) return res.status(401).send("Unauthorized");

    const newKey = `APEX-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const id = uuidv4();
    
    let expires_at = null;
    if (product_type === "weekly") {
        expires_at = Date.now() + (7 * 24 * 60 * 60 * 1000); 
    }

    db.prepare('INSERT INTO keys (id, key, type, expires_at, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(id, newKey, product_type, expires_at, Date.now());

    console.log(`Generated Key: ${newKey} (${product_type})`);
    res.status(200).json({ key: newKey });
});

// 3. ADMIN GENERATE ENDPOINT
app.post('/admin/generate', (req, res) => {
    const { auth, type } = req.body;
    if (auth !== API_SECRET) return res.status(401).send("Unauthorized");

    const newKey = `APEX-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const id = uuidv4();
    let expires_at = type === "weekly" ? Date.now() + (7 * 24 * 60 * 60 * 1000) : null;

    db.prepare('INSERT INTO keys (id, key, type, expires_at, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(id, newKey, type, expires_at, Date.now());

    res.json({ key: newKey, type, expires_at });
});

// 4. WEB ADMIN PANEL UI
app.get('/admin', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Apex Key Admin</title>
        <style>
            body { font-family: Arial; background: #0a0a0a; color: #f5f5f5; padding: 20px; }
            input, select, button { padding: 8px; margin: 4px; background: #1c1c1c; color: #fff; border: 1px solid #333; }
            button { background: #c81919; cursor: pointer; font-weight: bold; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #333; padding: 8px; text-align: left; }
            th { background: #1c1c1c; }
        </style>
    </head>
    <body>
        <h2>APEX KEY ADMIN</h2>
        <div>
            <input id="auth" placeholder="Admin Secret" type="password">
            <select id="type">
                <option value="weekly">Weekly</option>
                <option value="lifetime">Lifetime</option>
            </select>
            <button onclick="genKey()">Generate Key</button>
            <button onclick="loadKeys()">Refresh List</button>
        </div>
        <p id="status" style="color: #ff3232;"></p>
        <table id="keyTable">
            <tr><th>Key</th><th>Type</th><th>HWID</th><th>Expires</th></tr>
        </table>
        <script>
            async function genKey() {
                const auth = document.getElementById('auth').value;
                const type = document.getElementById('type').value;
                const res = await fetch('/admin/generate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({auth, type})
                });
                const data = await res.json();
                document.getElementById('status').innerText = data.key ? 'Generated: ' + data.key : 'Error: ' + data.error;
                loadKeys();
            }
            async function loadKeys() {
                const auth = document.getElementById('auth').value;
                const res = await fetch('/admin/keys?auth=' + encodeURIComponent(auth));
                const data = await res.json();
                const table = document.getElementById('keyTable');
                table.innerHTML = '<tr><th>Key</th><th>Type</th><th>HWID</th><th>Expires</th></tr>';
                (data.keys || []).forEach(k => {
                    const row = table.insertRow();
                    row.insertCell(0).innerText = k.key;
                    row.insertCell(1).innerText = k.type;
                    row.insertCell(2).innerText = k.hwid || '—';
                    row.insertCell(3).innerText = k.expires_at ? new Date(k.expires_at).toLocaleDateString() : 'Never';
                });
            }
        </script>
    </body>
    </html>
    `);
});

// 5. ADMIN LIST ENDPOINT
app.get('/admin/keys', (req, res) => {
    const { auth } = req.query;
    if (auth !== API_SECRET) return res.status(401).json({ error: "Unauthorized" });
    const rows = db.prepare('SELECT key, type, hwid, expires_at FROM keys').all();
    res.json({ keys: rows });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));
