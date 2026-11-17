
```javascript
// APEX client-to-client connectivity test (PING/PONG only).
// Plug this router into the existing Express server with:
// app.use('/apex', require('./apex-messaging')({ KeyModel }));

const express = require('express');
const crypto = require('crypto');

module.exports = function createApexMessaging({ KeyModel }) {
  if (!KeyModel) throw new Error('KeyModel is required');

  const router = express.Router();
  const clients = new Map();

  const TTL = 90_000;
  const MESSAGE_TTL = 120_000;
  const MAX_MESSAGES = 30;

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
          message => now() - message.at < MESSAGE_TTL
        );
      }
    }
  }

  function bodyStr(input, limit) {
    return typeof input === 'string' && input.length <= limit
      ? input
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

      // Reconnecting invalidates the previous session.
      for (const [token, session] of clients) {
        if (session.key === key) {
          clients.delete(token);
        }
      }

      const token = crypto.randomBytes(32).toString('hex');
      const id = crypto.randomBytes(8).toString('hex');

      clients.set(token, {
        id,
        key,
        name: String(row.username || 'APEX user').slice(0, 40),
        lastSeen: now(),
        inbox: [],
        lastSent: 0
      });

      res.json({
        success: true,
        token,
        clientId: id,
        expiresAfterSeconds: TTL / 1000
      });

    } catch (error) {
      console.error('[APEX] /connect:', error.message);

      res.status(500).json({
        error: 'Connect failed'
      });
    }
  });

  router.post('/heartbeat', auth, (req, res) => {
    req.apexClient.lastSeen = now();

    res.json({ success: true });
  });

  router.get('/online', auth, (req, res) => {
    res.json({
      clients: [...clients.values()]
        .filter(fresh)
        .map(session => ({
          id: session.id,
          name: session.name
        }))
    });
  });

  router.post('/send', auth, (req, res) => {
    const sender = req.apexClient;
    const to = bodyStr(req.body?.to, 16);
    const type = req.body?.type;

    if (
      !/^[a-f0-9]{16}$/.test(to) ||
      !['PING', 'PONG'].includes(type)
    ) {
      return res.status(400).json({
        error: 'Only PING/PONG with a valid client ID is supported'
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

    target.inbox.push({
      id: crypto.randomBytes(8).toString('hex'),
      from: sender.id,
      fromName: sender.name,
      type,
      at: now()
    });

    res.json({
      success: true,
      queued: true
    });
  });

  router.get('/messages', auth, (req, res) => {
    const session = req.apexClient;

    session.lastSeen = now();

    const messages = session.inbox.splice(
      0,
      MAX_MESSAGES
    );

    res.json({ messages });
  });

  router.post('/disconnect', auth, (req, res) => {
    clients.delete(req.apexToken);

    res.json({ success: true });
  });

  return router;
};
```
