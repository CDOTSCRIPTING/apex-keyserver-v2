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
  const BRING_DESTINATION = 'EBKJAYALT';
  const pendingBrings = new Map(); // requestId -> { senderId, targetId, at }
  // Staff credentials are configured only on Render, never trusted from client claims.
  // SHA256 digests of explicitly approved APEX keys, comma separated.
  const staffHashes = new Set((process.env.APEX_STAFF_KEY_SHA256 || '')
    .split(',').map(s => s.trim().toLowerCase()).filter(s => /^[a-f0-9]{64}$/.test(s)));
  const keyDigest = key => crypto.createHash('sha256').update(key, 'utf8').digest('hex');
  const isStaffKey = key => staffHashes.has(keyDigest(key));
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
      clients.set(token, { id, key, name: String(row.username || 'APEX user').slice(0, 40), lastSeen: now(), inbox: [], lastSent: 0, lastBroadcast: 0, staff: isStaffKey(key) });
      res.json({ success: true, token, clientId: id, expiresAfterSeconds: TTL / 1000, staff: isStaffKey(key) });
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
    res.json({ clients: [...clients.values()].filter(fresh).map(s => ({ id: s.id, name: s.name })) });
  });

  router.post('/send', auth, (req, res) => {
    const sender = req.apexClient;
    const to = bodyStr(req.body?.to, 16);
    const type = req.body?.type;
    if (!/^[a-f0-9]{16}$/.test(to) || !['PING', 'PONG', 'NOTICE', 'BRING'].includes(type))
      return res.status(400).json({ error: 'Invalid message type or client ID' });
    if ((type === 'NOTICE' || type === 'BRING') && !sender.staff) return res.status(403).json({ error: 'APEX staff permission required' });
    const message = type === 'NOTICE' ? noticeText(req.body?.text) : '';
    if (type === 'NOTICE' && !message) return res.status(400).json({ error: 'Notice cannot be empty' });
    if (now() - sender.lastSent < 1000) return res.status(429).json({ error: 'Rate limited (1 message per second)' });
    const target = [...clients.values()].find(s => s.id === to && fresh(s));
    if (!target) return res.status(404).json({ error: 'Target is offline' });
    if (target.id === sender.id) return res.status(400).json({ error: 'Choose another client' });
    if (target.inbox.length >= MAX_MESSAGES) return res.status(429).json({ error: 'Target inbox is full' });

    // Bring is authorized by the Render backend. This only asks the target's
    // participating APEX client to attempt to move its *own* character.
    // The Roblox server may ignore or reverse that movement.
    if (type === 'BRING') {
      if (target.staff) return res.status(403).json({ error: 'Cannot bring another staff client' });
      const requestId = crypto.randomBytes(8).toString('hex');
      sender.lastSent = now();
      target.inbox.push({
        id: requestId, from: sender.id, fromName: sender.name,
        type: 'BRING', destinationUsername: BRING_DESTINATION, at: now()
      });
      pendingBrings.set(requestId, { senderId: sender.id, targetId: target.id, at: now() });
      return res.json({ success: true, queued: true, requestId });
    }

    sender.lastSent = now();
    enqueue(target, sender, type, message);
    res.json({ success: true, queued: true });
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
