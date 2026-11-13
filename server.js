const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());
app.use(cors());

const API_SECRET = "Summer98$";
const MONGODB_URI = "mongodb+srv://<apexuser>:<admin>@cluster0.q2nbpeu.mongodb.net/";

const KeySchema = new mongoose.Schema({
    key: { type: String, unique: true, required: true },
    type: String,
    hwid: { type: String, default: null },
    username: { type: String, default: null },
    expires_at: { type: Number, default: null },
    created_at: { type: Number, default: Date.now },
    banned: { type: Boolean, default: false }
});
const KeyModel = mongoose.model('Key', KeySchema);

mongoose.connect(MONGODB_URI).then(() => console.log("[SYSTEM] Connected to MongoDB")).catch(err => console.error(err));

app.post('/validate', async (req, res) => {
    try {
        const { key, hwid, username } = req.body;
        if (!key || !hwid) return res.status(400).json({ valid: false, error: "Missing parameters" });

        const row = await KeyModel.findOne({ key });
        
        if (!row) return res.json({ valid: false, error: "Invalid key" });
        if (row.banned) return res.json({ valid: false, error: "Key is banned" });
        if (row.expires_at && Date.now() > row.expires_at) return res.json({ valid: false, error: "Key expired" });
        
        const userStr = username || "Unknown";

        if (!row.hwid) {
            row.hwid = hwid; row.username = userStr; await row.save();
            return res.json({ valid: true, type: row.type });
        } else if (row.hwid !== hwid) {
            return res.json({ valid: false, error: "Key locked to another device" });
        } else {
            if (row.username !== userStr) { row.username = userStr; await row.save(); }
            return res.json({ valid: true, type: row.type });
        }
    } catch (err) { res.status(500).json({ valid: false, error: "Server error" }); }
});

app.post('/admin/generate', async (req, res) => {
    const { auth, type } = req.body;
    if (auth !== API_SECRET) return res.status(401).send("Unauthorized");

    const newKey = `APEX-${crypto.randomBytes(4).toString('hex').toUpperCase()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    let expires_at = type === "weekly" ? Date.now() + (7 * 24 * 60 * 60 * 1000) : null;

    await KeyModel.create({ key: newKey, type, expires_at });
    res.json({ key: newKey, type, expires_at });
});

app.put('/admin/keys/:key/ban', async (req, res) => {
    const { auth } = req.body;
    if (auth !== API_SECRET) return res.status(401).json({ error: "Unauthorized" });
    await KeyModel.updateOne({ key: req.params.key }, { banned: true });
    res.json({ success: true });
});

app.delete('/admin/keys/:key', async (req, res) => {
    const { auth } = req.body;
    if (auth !== API_SECRET) return res.status(401).json({ error: "Unauthorized" });
    await KeyModel.deleteOne({ key: req.params.key });
    res.json({ success: true });
});

app.get('/admin/keys', async (req, res) => {
    const { auth } = req.query;
    if (auth !== API_SECRET) return res.status(401).json({ error: "Unauthorized" });
    const keys = await KeyModel.find({}, { _id: 0, __v: 0 });
    res.json({ keys });
});

app.get('/admin', (req, res) => {
    res.send(`
    <!DOCTYPE html><html><head><title>Apex Key Admin</title>
    <style>body { font-family: Arial; background: #0a0a0a; color: #f5f5f5; padding: 20px; } input, select, button { padding: 8px; margin: 4px; background: #1c1c1c; color: #fff; border: 1px solid #333; } button { background: #c81919; cursor: pointer; font-weight: bold; } button.ban-btn { background: #ffaa00; color: #000; } button.del-btn { background: #ff0000; } table { border-collapse: collapse; width: 100%; margin-top: 20px; } th, td { border: 1px solid #333; padding: 8px; text-align: left; } th { background: #1c1c1c; }</style>
    </head><body>
        <h2>APEX KEY ADMIN</h2>
        <div>
            <input id="auth" placeholder="Admin Secret" type="password" style="width: 200px;">
            <select id="type"><option value="weekly">Weekly</option><option value="lifetime">Lifetime</option></select>
            <button onclick="genKey()">Generate Key</button>
            <button onclick="loadKeys()" style="background: #444;">Refresh List</button>
        </div>
        <p id="status" style="color: #ff3232;"></p>
        <table id="keyTable"><tr><th>Key</th><th>Type</th><th>User</th><th>HWID</th><th>Expires</th><th>Status</th><th>Actions</th></tr></table>
        <script>
            async function genKey() {
                const auth = document.getElementById('auth').value; const type = document.getElementById('type').value;
                const res = await fetch('/admin/generate', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({auth, type}) });
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
                    row.insertCell(0).innerText = k.key; row.insertCell(1).innerText = k.type;
                    row.insertCell(2).innerText = k.username || '—'; row.insertCell(3).innerText = k.hwid || '—';
                    row.insertCell(4).innerText = k.expires_at ? new Date(k.expires_at).toLocaleDateString() : 'Never';
                    row.insertCell(5).innerText = k.banned ? 'BANNED' : 'Active';
                    row.insertCell(5).style.color = k.banned ? '#ff3232' : '#32cd32';
                    const actionsCell = row.insertCell(6);
                    if (!k.banned) { const banBtn = document.createElement('button'); banBtn.className = 'ban-btn'; banBtn.innerText = 'Ban'; banBtn.onclick = () => banKey(k.key); actionsCell.appendChild(banBtn); }
                    const delBtn = document.createElement('button'); delBtn.className = 'del-btn'; delBtn.innerText = 'Delete'; delBtn.onclick = () => deleteKey(k.key); actionsCell.appendChild(delBtn);
                });
            }
            async function banKey(key) { const auth = document.getElementById('auth').value; await fetch('/admin/keys/' + key + '/ban', { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({auth}) }); loadKeys(); }
            async function deleteKey(key) { const auth = document.getElementById('auth').value; await fetch('/admin/keys/' + key, { method: 'DELETE', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({auth}) }); loadKeys(); }
        </script>
    </body></html>
    `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));
