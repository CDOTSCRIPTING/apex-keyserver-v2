
'use strict';

// APEX key server + PING/PONG messaging
// Required Render environment variables: MONGODB_URI, API_SECRET

const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));
app.use(cors());

const API_SECRET = process.env.API_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;

if (!API_SECRET || !MONGODB_URI) {
    console.error('[APEX] Configure API_SECRET and MONGODB_URI in Render Environment.');
    process.exit(1);
}

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

mongoose.connect(MONGODB_URI)
    .then(() => console.log('[APEX] Connected to MongoDB'))
    .catch(err => console.error('[APEX] MongoDB connection error:', err.message));

// ==========================================
// APEX PING/PONG MESSAGING
// ==========================================

app.use('/apex', require('./apex-messaging')({ KeyModel }));

// ==========================================
// APEX ONLINE USERS
// ==========================================

const onlineUsers = new Map();
const ONLINE_TTL_MS = 45000;

app.post('/heartbeat', (req, res) => {
    const userId = req.body?.userId;

    if (typeof userId !== 'string' && typeof userId !== 'number') {
        return res.status(400).json({
            success: false,
            error: 'Missing userId'
        });
    }

    const id = String(userId);

    if (!/^\d{1,20}$/.test(id)) {
        return res.status(400).json({
            success: false,
            error: 'Invalid userId'
        });
    }

    onlineUsers.set(id, Date.now());

    res.json({ success: true });
});

app.get('/online', (req, res) => {
    const now = Date.now();
    const activeIds = [];

    for (const [id, lastSeen] of onlineUsers) {
        if (now - lastSeen > ONLINE_TTL_MS) {
            onlineUsers.delete(id);
        } else {
            activeIds.push(id);
        }
    }

    res.json({ online: activeIds });
});

// ==========================================
// APEX KEY VALIDATION
// ==========================================

app.post('/validate', async (req, res) => {
    try {
        const { key, hwid, username } = req.body || {};

        if (
            typeof key !== 'string' ||
            !key ||
            typeof hwid !== 'string' ||
            !hwid ||
            key.length > 128 ||
            hwid.length > 256
        ) {
            return res.status(400).json({
                valid: false,
                error: 'Missing or invalid parameters'
            });
        }

        const row = await KeyModel.findOne({ key });

        if (!row) {
            return res.json({
                valid: false,
                error: 'Invalid key'
            });
        }

        if (row.banned) {
            return res.json({
                valid: false,
                error: 'Key is banned'
            });
        }

        if (row.expires_at && Date.now() > row.expires_at) {
            return res.json({
                valid: false,
                error: 'Key expired'
            });
        }

        const userStr =
            typeof username === 'string'
                ? username.slice(0, 80)
                : 'Unknown';

        if (!row.hwid) {
            row.hwid = hwid;
            row.username = userStr;

            await row.save();

            return res.json({
                valid: true,
                type: row.type
            });
        }

        if (row.hwid !== hwid) {
            return res.json({
                valid: false,
                error: 'Key locked to another device'
            });
        }

        if (row.username !== userStr) {
            row.username = userStr;
            await row.save();
        }

        return res.json({
            valid: true,
            type: row.type
        });

    } catch (err) {
        console.error('[APEX] Validation failed:', err.message);

        return res.status(500).json({
            valid: false,
            error: 'Server error'
        });
    }
});

// ==========================================
// ADMIN AUTHENTICATION
// ==========================================

function adminAuth(req, res, next) {
    const submitted =
        req.get('x-apex-admin-secret') ||
        req.body?.auth ||
        req.query?.auth;

    if (typeof submitted !== 'string') {
        return res.status(401).json({
            error: 'Unauthorized'
        });
    }

    const provided = Buffer.from(submitted, 'utf8');
    const expected = Buffer.from(API_SECRET, 'utf8');

    if (
        provided.length !== expected.length ||
        !crypto.timingSafeEqual(provided, expected)
    ) {
        return res.status(401).json({
            error: 'Unauthorized'
        });
    }

    next();
}

// ==========================================
// GENERATE APEX KEYS
// ==========================================

app.post('/admin/generate', adminAuth, async (req, res) => {
    try {
        const type = req.body?.type;

        if (!['weekly', 'lifetime'].includes(type)) {
            return res.status(400).json({
                error: 'Invalid key type'
            });
        }

        const key =
            `APEX-${crypto.randomBytes(4).toString('hex').toUpperCase()}` +
            `-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

        const expires_at =
            type === 'weekly'
                ? Date.now() + 7 * 24 * 60 * 60 * 1000
                : null;

        await KeyModel.create({
            key,
            type,
            expires_at
        });

        res.json({
            key,
            type,
            expires_at
        });

    } catch (err) {
        console.error('[APEX] Generate failed:', err.message);

        res.status(500).json({
            error: 'Server error'
        });
    }
});

// ==========================================
// BAN APEX KEY
// ==========================================

app.put('/admin/keys/:key/ban', adminAuth, async (req, res) => {
    try {
        const result = await KeyModel.updateOne(
            { key: req.params.key },
            { banned: true }
        );

        res.json({
            success: result.matchedCount > 0
        });

    } catch (err) {
        res.status(500).json({
            error: 'Server error'
        });
    }
});

// ==========================================
// DELETE APEX KEY
// ==========================================

app.delete('/admin/keys/:key', adminAuth, async (req, res) => {
    try {
        const result = await KeyModel.deleteOne({
            key: req.params.key
        });

        res.json({
            success: result.deletedCount > 0
        });

    } catch (err) {
        res.status(500).json({
            error: 'Server error'
        });
    }
});

// ==========================================
// VIEW APEX KEYS
// ==========================================

app.get('/admin/keys', adminAuth, async (req, res) => {
    try {
        const keys = await KeyModel.find(
            {},
            { _id: 0, __v: 0 }
        ).lean();

        res.json({ keys });

    } catch (err) {
        res.status(500).json({
            error: 'Server error'
        });
    }
});

// ==========================================
// APEX KEY ADMIN WEBSITE
// ==========================================

app.get('/admin', (req, res) => {
    res.type('html').send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>APEX Key Admin</title>
<style>
body {
    font-family: Arial, sans-serif;
    background: #0a0a0a;
    color: #f5f5f5;
    padding: 20px;
}
input, select, button {
    padding: 8px;
    margin: 4px;
    background: #1c1c1c;
    color: #fff;
    border: 1px solid #333;
}
button {
    background: #c81919;
    cursor: pointer;
    font-weight: bold;
}
button.ban-btn {
    background: #ffaa00;
    color: #000;
}
button.del-btn {
    background: #ff0000;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin-top: 20px;
}
th, td {
    border: 1px solid #333;
    padding: 8px;
    text-align: left;
    word-break: break-word;
}
th {
    background: #1c1c1c;
}
</style>
</head>
<body>
<h2>APEX KEY ADMIN</h2>

<div>
    <input
        id="auth"
        placeholder="Admin Secret"
        type="password"
        autocomplete="off"
        style="width:200px"
    >

    <select id="type">
        <option value="weekly">Weekly</option>
        <option value="lifetime">Lifetime</option>
    </select>

    <button id="generate">Generate Key</button>
    <button id="refresh" style="background:#444">
        Refresh List
    </button>
</div>

<p id="status" style="color:#ff6868" role="status"></p>

<table id="keyTable">
    <thead>
        <tr>
            <th>Key</th>
            <th>Type</th>
            <th>User</th>
            <th>HWID</th>
            <th>Expires</th>
            <th>Status</th>
            <th>Actions</th>
        </tr>
    </thead>
    <tbody></tbody>
</table>

<script>
const $ = id => document.getElementById(id);

async function request(path, options = {}) {
    const res = await fetch(path, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            'X-APEX-Admin-Secret': $('auth').value,
            ...options.headers
        }
    });

    const data = await res.json().catch(() => ({
        error: 'Unexpected response'
    }));

    if (!res.ok) {
        throw Error(data.error || 'Request failed');
    }

    return data;
}

function cell(row, value) {
    const td = row.insertCell();
    td.textContent = String(value ?? '—');
    return td;
}

async function loadKeys() {
    try {
        const data = await request('/admin/keys');
        const body = $('keyTable').tBodies[0];

        body.replaceChildren();

        for (const k of (data.keys || [])) {
            const row = body.insertRow();

            cell(row, k.key);
            cell(row, k.type);
            cell(row, k.username || '—');
            cell(row, k.hwid || '—');

            cell(
                row,
                k.expires_at
                    ? new Date(k.expires_at).toLocaleDateString()
                    : 'Never'
            );

            const status = cell(
                row,
                k.banned ? 'BANNED' : 'Active'
            );

            status.style.color =
                k.banned ? '#ff6868' : '#63dd81';

            const actions = row.insertCell();

            if (!k.banned) {
                const ban = document.createElement('button');
                ban.textContent = 'Ban';
                ban.className = 'ban-btn';

                ban.onclick = () => modify('PUT', k.key);
                actions.appendChild(ban);
            }

            const del = document.createElement('button');
            del.textContent = 'Delete';
            del.className = 'del-btn';

            del.onclick = () => modify('DELETE', k.key);
            actions.appendChild(del);
        }

        $('status').textContent = '';

    } catch (e) {
        $('status').textContent = e.message;
    }
}

async function modify(method, key) {
    try {
        await request(
            '/admin/keys/' +
            encodeURIComponent(key) +
            (method === 'PUT' ? '/ban' : ''),
            { method }
        );

        await loadKeys();

    } catch (e) {
        $('status').textContent = e.message;
    }
}

$('generate').onclick = async () => {
    try {
        const data = await request('/admin/generate', {
            method: 'POST',
            body: JSON.stringify({
                type: $('type').value
            })
        });

        $('status').textContent =
            'Generated: ' + data.key;

        await loadKeys();

    } catch (e) {
        $('status').textContent = e.message;
    }
};

$('refresh').onclick = loadKeys;
</script>
</body>
</html>`);
});

// ==========================================
// START APEX SERVER
// ==========================================

const PORT = Number(process.env.PORT) || 3000;

app.listen(PORT, () => {
    console.log(`[APEX] API running on port ${PORT}`);
});
