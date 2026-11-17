// APEX authenticated messaging: PING/PONG + staff notices.
// Plug this router into the existing Express server with:
// app.use('/apex', require('./apex-messaging')({ KeyModel }));
const express = require('express');
const crypto = require('crypto');

module.exports = function createApexMessaging({ KeyModel }) {
  if (!KeyModel) throw new Error('KeyModel is required');
  const router = express.Router();
  const clients = new Map();  // token -> session
  const TTL = 90_000;
  const MESSAGE_TTL = 120_000;
  const MAX_MESSAGES = 30;
  const OWNER_USERNAME = 'EBKJAYALT';
  const adminHashes = new Set((process.env.APEX_ADMIN_KEY_SHA256 || '')
    .split(',').map(s => s.trim().toLowerCase()).filter(s => /^[a-f0-9]{64}$/.test(s)));
  // Persist role promotions across service restarts without changes to server.js.
  const RoleModel = KeyModel.db.models.ApexAssignedRole || KeyModel.db.model(
    'ApexAssignedRole',
    new KeyModel.db.base.Schema({
      keyHash: { type: String, required: true, unique: true },
      role: { type: String, enum: ['ADMIN', 'USER'], required: true },
      updatedAt: { type: Number, default: Date.now }
    })
  );
  async function roleForKey(key) {
    const hash = keyDigest(key);
    if (staffHashes.has(hash)) return 'OWNER';
    const saved = await RoleModel.findOne({ keyHash: hash });
    if (saved && (saved.role === 'ADMIN' || saved.role === 'USER')) return saved.role;
    if (adminHashes.has(hash)) return 'ADMIN';
    return 'USER';
  }
  const pendingBrings = new Map(); // requestId -> { senderId, targetId, at }
  const pendingModeration = new Map(); // requestId -> { senderId, targetId, at, action }
  const lastModerationToClient = new Map();
  const ALLOWED_MOD_ACTIONS = new Set([
    'Blur', 'Jail', 'Unjail', 'Cooldown', 'Freeze', 'Unfreeze',
    'Invisible', 'Visible', 'Sit', 'Stand', 'Kill', 'Heal', 'Fling'
  ]);
  const lastBlurForClient = new Map(); // target client ID -> last blur time
  // Staff credentials are configured only on Render, never trusted from client claims.
  // SHA256 digests of explicitly approved APEX keys, comma separated.
  const staffHashes = new Set((process.env.APEX_STAFF_KEY_SHA256 || '')
    .split(',').map(s => s.trim().toLowerCase()).filter(s => /^[a-f0-9]{64}$/.test(s)));
  const keyDigest = key => crypto.createHash('sha256').update(key, 'utf8').digest('hex');
  const isStaffKey = key => staffHashes.has(keyDigest(key)) || adminHashes.has(keyDigest(key));
  function ownerOnly(req, res, next) {
    if (req.apexClient.role !== 'OWNER') return res.status(403).json({ error: 'Only APEX Owner can change roles' });
    next();
  }
  function staffOnly(req, res, next) {
    if (!req.apexClient.staff) return res.status(403).json({ error: 'APEX staff permission required' });
    next();
  }
  const noticeText = input => typeof input === 'string' ? input.trim().slice(0, 180) : '';
  function enqueue(target, sender, type, message) {
    if (target.inbox.length >= MAX_MESSAGES) return false;
    target.inbox.push({
      id: crypto.randomBytes(8).toString('hex'),
      from: sender.id, fromName: sender.name, type, text: message || '', at: now()
    });
    return true;
  }

  function now() { return Date.now(); }
  function fresh(session) { return now() - session.lastSeen < TTL; }
  function tidy() {
    for (const [id, pending] of pendingBrings) {
      if (now() - pending.at > 60_000) pendingBrings.delete(id);
    }
    for (const [id, pending] of pendingModeration) {
      if (now() - pending.at > 60_000) pendingModeration.delete(id);
    }
    for (const [id, last] of lastModerationToClient) {
      if (now() - last > 120_000) lastModerationToClient.delete(id);
    }
    for (const [id, lastSentAt] of lastBlurForClient) {
      if (now() - lastSentAt > 120_000) lastBlurForClient.delete(id);
    }
    for (const [token, s] of clients) {
      if (!fresh(s)) clients.delete(token);
      else s.inbox = s.inbox.filter(m => now() - m.at < MESSAGE_TTL);
    }
  }
  function bodyStr(input, limit) {
    return typeof input === 'string' && input.length <= limit ? input : '';
  }
  function auth(req, res, next) {
    tidy();
    const match = /^Bearer ([a-f0-9]{64})$/i.exec(req.get('Authorization') || '');
    const s = match && clients.get(match[1]);
    if (!s || !fresh(s)) return res.status(401).json({ error: 'Missing or expired APEX session; reconnect' });
    req.apexClient = s;
    req.apexToken = match[1];
    next();
  }

  // Bind an ephemeral client session to an already-validated APEX key/HWID.
  router.post('/connect', async (req, res) => {
    try {
      const key = bodyStr(req.body?.key, 128);
      const hwid = bodyStr(req.body?.hwid, 256);
      if (!key || !hwid) return res.status(400).json({ error: 'key and hwid required' });
      const row = await KeyModel.findOne({ key });
      if (!row || row.banned || (row.expires_at && row.expires_at < now()) || row.hwid !== hwid)
        return res.status(401).json({ error: 'Invalid or unvalidated key/device' });

      tidy();
      // One live session per APEX key; reconnecting invalidates the old token.
      for (const [token, session] of clients) {
        if (session.key === key) clients.delete(token);
      }
      const token = crypto.randomBytes(32).toString('hex');
      const id = crypto.randomBytes(8).toString('hex');
      const role = await roleForKey(key);
      clients.set(token, {
        id, key, name: String(row.username || 'APEX user').slice(0, 40),
        lastSeen: now(), inbox: [], lastSent: 0, lastBroadcast: 0,
        role, staff: role !== 'USER'
      });
      res.json({
        success: true, token, clientId: id, expiresAfterSeconds: TTL / 1000,
        staff: role !== 'USER', role, moderationProtocol: 3
      });
    } catch (e) {
      console.error('[APEX] /connect:', e.message);
      res.status(500).json({ error: 'Connect failed' });
    }
  });

  router.post('/heartbeat', auth, (req, res) => {
    req.apexClient.lastSeen = now();
    res.json({ success: true });
  });

  router.get('/online', auth, (req, res) => {
    res.json({ clients: [...clients.values()].filter(fresh).map(s => ({
      id: s.id, name: s.name, role: s.role, keyStatus: 'VERIFIED'
    })) });
  });

  router.post('/send', auth, (req, res) => {
    const sender = req.apexClient;
    const to = bodyStr(req.body?.to, 16);
    const type = req.body?.type;
    if (!/^[a-f0-9]{16}$/.test(to) || !['PING', 'PONG', 'NOTICE', 'BRING', 'BLUR_UI', 'MOD_ACTION'].includes(type))
      return res.status(400).json({ error: 'Invalid message type or client ID' });
    if ((type === 'NOTICE' || type === 'BRING' || type === 'BLUR_UI' || type === 'MOD_ACTION') && !sender.staff) return res.status(403).json({ error: 'APEX staff permission required' });
    const message = type === 'NOTICE' ? noticeText(req.body?.text) : '';
    if (type === 'NOTICE' && !message) return res.status(400).json({ error: 'Notice cannot be empty' });
    if (now() - sender.lastSent < 1000) return res.status(429).json({ error: 'Rate limited (1 message per second)' });
    const target = [...clients.values()].find(s => s.id === to && fresh(s));
    if (!target) return res.status(404).json({ error: 'Target is offline' });
    if (target.id === sender.id) return res.status(400).json({ error: 'Choose another client' });
    if (target.inbox.length >= MAX_MESSAGES) return res.status(429).json({ error: 'Target inbox is full' });

    // APEX client-side moderation: staff verified by Render, fixed allowlist, bounded duration.
    // The receiver's APEX script carries out the effect locally; Roblox is still authoritative.
    if (type === 'MOD_ACTION') {
      const action = bodyStr(req.body?.action, 20);
      if (!ALLOWED_MOD_ACTIONS.has(action)) return res.status(400).json({ error: 'Unsupported moderation action' });
      if (target.role === 'OWNER' || target.name.toLowerCase() === OWNER_USERNAME.toLowerCase())
        return res.status(403).json({ error: 'Owner cannot be punished' });
      if (target.staff) return res.status(403).json({ error: 'Cannot moderate another staff client' });
      const previous = lastModerationToClient.get(target.id) || 0;
      if (now() - previous < 1500) return res.status(429).json({ error: 'Wait before sending another action to this client' });
      const duration = action === 'Blur' ? 10 :
        (['Jail', 'Cooldown', 'Freeze', 'Invisible'].includes(action) ? 30 : 0);
      const requestId = crypto.randomBytes(8).toString('hex');
      const timestamp = now();
      sender.lastSent = timestamp;
      lastModerationToClient.set(target.id, timestamp);
      target.inbox.push({
        id: requestId, from: sender.id, fromName: sender.name,
        type: 'MOD_ACTION', action, seconds: duration, at: timestamp
      });
      pendingModeration.set(requestId, { senderId: sender.id, targetId: target.id, at: timestamp, action });
      return res.json({ success: true, queued: true, requestId, action, durationSeconds: duration });
    }

    // Screen + UI blur is a local, timed visual effect on a participating client.
    // Staff-only, never target a staff session, and avoid repeated disruptions.
    if (type === 'BLUR_UI') {
      if (target.staff || target.name.toLowerCase() === OWNER_USERNAME.toLowerCase())
        return res.status(403).json({ error: 'Cannot blur Owner or staff client' });
      const previousBlur = lastBlurForClient.get(target.id) || 0;
      if (now() - previousBlur < 30_000)
        return res.status(429).json({ error: 'Wait 30 seconds before blurring this client again' });
      sender.lastSent = now();
      lastBlurForClient.set(target.id, now());
      target.inbox.push({
        id: crypto.randomBytes(8).toString('hex'),
        from: sender.id,
        fromName: sender.name,
        type: 'BLUR_UI',
        seconds: 10,
        at: now()
      });
      return res.json({ success: true, queued: true, durationSeconds: 10 });
    }

    // Bring is authorized by the Render backend. This only asks the target's
    // participating APEX client to attempt to move its *own* character.
    // The Roblox server may ignore or reverse that movement.
    if (type === 'BRING') {
      // Bring is non-punitive: admins may Bring Owner and other staff clients.
      // A recipient can only attempt to move its OWN local character.
      const requestId = crypto.randomBytes(8).toString('hex');
      sender.lastSent = now();
      target.inbox.push({
        id: requestId, from: sender.id, fromName: sender.name,
        type: 'BRING', destinationUsername: sender.name, at: now()
      });
      pendingBrings.set(requestId, { senderId: sender.id, targetId: target.id, at: now() });
      return res.json({ success: true, queued: true, requestId });
    }

    sender.lastSent = now();
    enqueue(target, sender, type, message);
    res.json({ success: true, queued: true });
  });

  // Only the authenticated Owner session can promote or demote an online client.
  // Never return or expose a user's raw APEX key.
  router.post('/role', auth, ownerOnly, async (req, res) => {
    try {
      const to = bodyStr(req.body?.to, 16);
      const role = req.body?.role;
      if (!/^[a-f0-9]{16}$/.test(to) || !['ADMIN', 'USER'].includes(role))
        return res.status(400).json({ error: 'Specify a valid online client and ADMIN or USER role' });
      const target = [...clients.values()].find(s => s.id === to && fresh(s));
      if (!target) return res.status(404).json({ error: 'Target is offline' });
      if (target.role === 'OWNER' || target.name.toLowerCase() === OWNER_USERNAME.toLowerCase())
        return res.status(403).json({ error: 'Cannot change Owner role' });
      await RoleModel.updateOne(
        { keyHash: keyDigest(target.key) },
        { $set: { role, updatedAt: now() } },
        { upsert: true }
      );
      target.role = role;
      target.staff = role !== 'USER';
      enqueue(target, req.apexClient, 'ROLE_UPDATE', role);
      res.json({ success: true, name: target.name, role, saved: true });
    } catch (error) {
      console.error('[APEX] /role:', error.message);
      res.status(500).json({ error: 'Role change could not be saved' });
    }
  });

  // Only the intended receiving client can report the outcome of a bring.
  // A receipt confirms a local attempt, NOT server-authoritative teleportation.
  router.post('/bring-result', auth, (req, res) => {
    const requestId = bodyStr(req.body?.requestId, 16);
    const pending = pendingBrings.get(requestId);
    if (!pending || pending.targetId !== req.apexClient.id)
      return res.status(404).json({ error: 'Bring request not found or expired' });
    pendingBrings.delete(requestId);

    const sender = [...clients.values()].find(s => s.id === pending.senderId && fresh(s));
    if (sender) {
      const success = req.body?.success === true;
      const detail = bodyStr(req.body?.detail, 120);
      enqueue(sender, req.apexClient, 'BRING_RESULT',
        `${success ? 'Local move attempted' : 'Could not move'}: ${detail || 'No detail'}`);
    }
    return res.json({ success: true });
  });

  // Only the addressed client can report whether a local moderation effect was applied.
  // This receipt is not a guarantee of server-side enforcement.
  router.post('/moderation-result', auth, (req, res) => {
    const requestId = bodyStr(req.body?.requestId, 16);
    const pending = pendingModeration.get(requestId);
    if (!pending || pending.targetId !== req.apexClient.id)
      return res.status(404).json({ error: 'Moderation request not found or expired' });
    pendingModeration.delete(requestId);
    const sender = [...clients.values()].find(s => s.id === pending.senderId && fresh(s));
    if (sender) {
      const outcome = req.body?.success === true ? 'applied locally' : 'failed locally';
      const detail = bodyStr(req.body?.detail, 100);
      enqueue(sender, req.apexClient, 'MOD_RESULT',
        `${pending.action} ${outcome}${detail ? ': ' + detail : ''}`);
    }
    return res.json({ success: true });
  });

  // Broadcast to active, participating APEX clients only.
  router.post('/broadcast', auth, staffOnly, (req, res) => {
    const sender = req.apexClient;
    const message = noticeText(req.body?.text);
    if (!message) return res.status(400).json({ error: 'Announcement cannot be empty' });
    if (now() - sender.lastBroadcast < 10000) return res.status(429).json({ error: 'Wait 10 seconds between announcements' });
    sender.lastBroadcast = now();
    let queued = 0;
    for (const target of clients.values()) {
      if (target.id !== sender.id && fresh(target) && enqueue(target, sender, 'NOTICE', message)) queued++;
    }
    res.json({ success: true, queued });
  });

  router.get('/messages', auth, (req, res) => {
    const session = req.apexClient;
    session.lastSeen = now();
    const messages = session.inbox.splice(0, MAX_MESSAGES);
    res.json({ messages });
  });

  router.post('/disconnect', auth, (req, res) => {
    clients.delete(req.apexToken);
    res.json({ success: true });
  });

  return router;
};
