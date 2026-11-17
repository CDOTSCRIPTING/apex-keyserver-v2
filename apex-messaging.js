const express = require('express');
const crypto = require('crypto');

module.exports = function createApexMessaging({ KeyModel }) {
  if (!KeyModel) throw new Error('KeyModel is required');

  const router = express.Router();
  const clients = new Map();

  const TTL = 90000;
  const MESSAGE_TTL = 120000;
  const MAX_MESSAGES = 30;

  // Approved staff key hashes, configured in Render.
  const staffHashes = new Set(
    (process.env.APEX_STAFF_KEY_SHA256 || '')
      .split(',')
      .map(s => s.trim().toLowerCase())
      .filter(s => /^[a-f0-9]{64}$/.test(s))
  );

  function keyDigest(key) {
    return crypto.createHash('sha256')
      .update(key, 'utf8')
      .digest('hex');
  }

  function isStaffKey(key) {
    return staffHashes.has(keyDigest(key));
  }

  function now() {
    return Date.now();
  }

  function fresh(session) {
    return now() - session.lastSeen < TTL;
  }

  function tidy() {
    for (const [token, session] of clients) {
      if (!fresh(session)) {
        clients.delete(token);
      } else {
        session.inbox = session.inbox.filter(
          m => now() - m.at < MESSAGE_TTL
        );
      }
    }
  }

  function bodyStr(input, limit) {
    return typeof input === 'string' && input.length <= limit
      ? input
      : '';
  }

  function noticeText(input) {
    return typeof input === 'string'
      ? input.trim().slice(0, 180)
      : '';
  }

  function auth(req, res, next) {
    tidy();

    const match = /^Bearer ([a-f0-9]{64})$/i.exec(
      req.get('Authorization') || ''
    );

    const session = match && clients.get(match[1]);

    if (!session || !fresh(session)) {
      return res.status(401).json({
        error: 'Missing or expired APEX session; reconnect'
      });
    }

    req.apexClient = session;
    req.apexToken = match[1];

    next();
  }

  function staffOnly(req, res, next) {
    if (!req.apexClient.staff) {
      return res.status(403).json({
        error: 'APEX staff permission required'
      });
    }

    next();
  }

  function enqueue(target, sender, type, message) {
    if (target.inbox.length >= MAX_MESSAGES) {
      return false;
    }

    target.inbox.push({
      id: crypto.randomBytes(8).toString('hex'),
      from: sender.id,
      fromName: sender.name,
      type,
      text: message || '',
      at: now()
    });

    return true;
  }

  // Connect an authenticated APEX user.
  router.post('/connect', async (req, res) => {
    try {
      const key = bodyStr(req.body?.key, 128);
      const hwid = bodyStr(req.body?.hwid, 256);

      if (!key || !hwid) {
        return res.status(400).json({
          error: 'key and hwid required'
        });
      }

      const row = await KeyModel.findOne({ key });

      if (
        !row ||
        row.banned ||
        (row.expires_at && row.expires_at < now()) ||
        row.hwid !== hwid
      ) {
        return res.status(401).json({
          error: 'Invalid or unvalidated key/device'
        });
      }

      tidy();

      // Only one active session per key.
      for (const [token, session] of clients) {
        if (session.key === key) {
          clients.delete(token);
        }
      }

      const token = crypto.randomBytes(32).toString('hex');
      const id = crypto.randomBytes(8).toString('hex');
      const staff = isStaffKey(key);

      clients.set(token, {
        id,
        key,
        name: String(row.username || 'APEX user').slice(0, 40),
        lastSeen: now(),
        inbox: [],
        lastSent: 0,
        lastBroadcast: 0,
        staff
      });

      return res.json({
        success: true,
        token,
        clientId: id,
        expiresAfterSeconds: TTL / 1000,
        staff
      });

    } catch (error) {
      console.error('[APEX] /connect:', error.message);

      return res.status(500).json({
        error: 'Connect failed'
      });
    }
  });

  // Keep client online.
  router.post('/heartbeat', auth, (req, res) => {
    req.apexClient.lastSeen = now();

    return res.json({
      success: true
    });
  });

  // List online APEX users.
  router.get('/online', auth, (req, res) => {
    return res.json({
      clients: [...clients.values()]
        .filter(fresh)
        .map(session => ({
          id: session.id,
          name: session.name
        }))
    });
  });

  // Send PING, PONG, or staff notifications.
  router.post('/send', auth, (req, res) => {
    const sender = req.apexClient;
    const to = bodyStr(req.body?.to, 16);
    const type = req.body?.type;

    if (
      !/^[a-f0-9]{16}$/.test(to) ||
      !['PING', 'PONG', 'NOTICE'].includes(type)
    ) {
      return res.status(400).json({
        error: 'Invalid message type or client ID'
      });
    }

    if (type === 'NOTICE' && !sender.staff) {
      return res.status(403).json({
        error: 'APEX staff permission required'
      });
    }

    const message = type === 'NOTICE'
      ? noticeText(req.body?.text)
      : '';

    if (type === 'NOTICE' && !message) {
      return res.status(400).json({
        error: 'Notice cannot be empty'
      });
    }

    if (now() - sender.lastSent < 1000) {
      return res.status(429).json({
        error: 'Rate limited (1 message per second)'
      });
    }

    const target = [...clients.values()].find(
      session => session.id === to && fresh(session)
    );

    if (!target) {
      return res.status(404).json({
        error: 'Target is offline'
      });
    }

    if (target.id === sender.id) {
      return res.status(400).json({
        error: 'Choose another client'
      });
    }

    if (target.inbox.length >= MAX_MESSAGES) {
      return res.status(429).json({
        error: 'Target inbox is full'
      });
    }

    sender.lastSent = now();

    enqueue(target, sender, type, message);

    return res.json({
      success: true,
      queued: true
    });
  });

  // Broadcast an announcement to connected APEX clients.
  router.post('/broadcast', auth, staffOnly, (req, res) => {
    const sender = req.apexClient;
    const message = noticeText(req.body?.text);

    if (!message) {
      return res.status(400).json({
        error: 'Announcement cannot be empty'
      });
    }

    if (now() - sender.lastBroadcast < 10000) {
      return res.status(429).json({
        error: 'Wait 10 seconds between announcements'
      });
    }

    sender.lastBroadcast = now();

    let queued = 0;

    for (const target of clients.values()) {
      if (
        target.id !== sender.id &&
        fresh(target) &&
        enqueue(target, sender, 'NOTICE', message)
      ) {
        queued++;
      }
    }

    return res.json({
      success: true,
      queued
    });
  });

  // Receive queued messages.
  router.get('/messages', auth, (req, res) => {
    const session = req.apexClient;

    session.lastSeen = now();

    const messages = session.inbox.splice(
      0,
      MAX_MESSAGES
    );

    return res.json({
      messages
    });
  });

  // Disconnect.
  router.post('/disconnect', auth, (req, res) => {
    clients.delete(req.apexToken);

    return res.json({
      success: true
    });
  });

  return router;
};
