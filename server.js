const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const db = require('./db');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());
app.use(cors());

const API_SECRET = "Summer98$";

app.post('/validate', (req, res) => {
    const { key, hwid, username } = req.body;
    if (!key || !hwid) return res.status(400).json({ valid: false, error: "Missing parameters" });

    const row = db.prepare('SELECT * FROM keys WHERE key = ?').get(key);
    
    if (!row) return res.json({ valid: false, error: "Invalid key" });
    if (row.banned) return res.json({ valid: false, error: "Key is banned" });
    if (row.expires_at && Date.now() > row.expires_at) return res.json({ valid: false, error: "Key expired" });
    
    const userStr = username || "Unknown";

    if (!row.hwid) {
        db.prepare('UPDATE keys SET hwid = ?, username = ? WHERE id = ?').run(hwid, userStr, row.id);
        return res.json({ valid: true, type: row.type, message: "HWID locked to this device" });
    } else if (row.hwid !== hwid) {
        return res.json({ valid: false, error: "Key locked to another device" });
    } else {
        // Update username if it changed
        if (row.username !== userStr) {
            db.prepare('UPDATE keys SET username = ? WHERE id = ?').run(userStr, row.id);
        }
    }

    return res.json({ valid: true, type: row.type });
});

app.post('/webhook', (req, res) => {
    const { secret, product_type } = req.body; 
    if (secret !== API_SECRET) return res.status(401).send("Unauthorized");

    const newKey = `APEX-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const id = uuidv4();
    let expires_at = product_type === "weekly" ? Date.now() + (7 * 24 * 60 * 60 * 1000) : null;

    db.prepare('INSERT INTO keys (id, key, type, expires_at, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(id, newKey, product_type, expires_at, Date.now());

    res.status(200).json({ key: newKey });
});

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

app.put('/admin/keys/:key/ban', (req, res) => {
    const { auth } = req.body;
    if (auth !== API_SECRET) return res.status(401).json({ error: "Unauthorized" });
    db.prepare('UPDATE keys SET banned = 1 WHERE key = ?').run(req.params.key);
    res.json({ success: true });
});

app.delete('/admin/keys/:key', (req, res) => {
    const { auth } = req.body;
    if (auth !== API_SECRET) return res.status(401).json({ error: "Unauthorized" });
    db.prepare('DELETE FROM keys WHERE key = ?').run(req.params.key);
    res.json({ success: true });
});

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
            button.ban-btn { background: #ffaa00; color: #000; }
            button.del-btn { background: #ff0000; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #333; padding: 8px; text-align: left; }
            th { background: #1c1c1c; }
        </style>
    </head>
    <body>
        <h2>APEX KEY ADMIN</h2>
        <div>
            <input id="auth" placeholder="Admin Secret" type="password" style="width: 200px;">
            <select id="type">
                <option value="weekly">Weekly</option>
                <option value="lifetime">Lifetime</option>
            </select>
            <button onclick="genKey()">Generate Key</button>
            <button onclick="loadKeys()" style="background: #444;">Refresh List</button>
        </div>
        <p id="status" style="color: #ff3232;"></p>
        <table id="keyTable">
            <tr><th>Key</th><th>Type</th><th>User</th><th>HWID</th><th>Expires</th><th>Status</th><th>Actions</th></tr>
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
                table.innerHTML = '<tr><th>Key</th><th>Type</th><th>User</th><th>HWID</th><th>Expires</th><th>Status</th><th>Actions</th></tr>';
                (data.keys || []).forEach(k => {
                    const row = table.insertRow();
                    row.insertCell(0).innerText = k.key;
                    row.insertCell(1).innerText = k.type;
                    row.insertCell(2).innerText = k.username || '—';
                    row.insertCell(3).innerText = k.hwid || '—';
                    row.insertCell(4).innerText = k.expires_at ? new Date(k.expires_at).toLocaleDateString() : 'Never';
                    row.insertCell(5).innerText = k.banned ? 'BANNED' : 'Active';
                    row.insertCell(5).style.color = k.banned ? '#ff3232' : '#32cd32';
                    
                    const actionsCell = row.insertCell(6);
                    
                    if (!k.banned) {
                        const banBtn = document.createElement('button');
                        banBtn.className = 'ban-btn';
                        banBtn.innerText = 'Ban';
                        banBtn.onclick = () => banKey(k.key);
                        actionsCell.appendChild(banBtn);
                    }
                    
                    const delBtn = document.createElement('button');
                    delBtn.className = 'del-btn';
                    delBtn.innerText = 'Delete';
                    delBtn.onclick = () => deleteKey(k.key);
                    actionsCell.appendChild(delBtn);
                });
            }
            async function banKey(key) {
                const auth = document.getElementById('auth').value;
                await fetch('/admin/keys/' + key + '/ban', {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({auth})
                });
                loadKeys();
            }
            async function deleteKey(key) {
                const auth = document.getElementById('auth').value;
                await fetch('/admin/keys/' + key, {
                    method: 'DELETE',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({auth})
                });
                loadKeys();
            }
        </script>
    </body>
    </html>
    `);
});

app.get('/admin/keys', (req, res) => {
    const { auth } = req.query;
    if (auth !== API_SECRET) return res.status(401).json({ error: "Unauthorized" });
    const rows = db.prepare('SELECT key, type, username, hwid, expires_at, banned FROM keys').all();
    res.json({ keys: rows });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));
