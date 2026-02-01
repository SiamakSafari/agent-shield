// Continuous Monitoring API routes
const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const { requireFeature } = require('../middleware/auth');

// Tier limits
const TIER_LIMITS = {
  free:       { maxMonitors: 1,  maxSkills: 5,   scanIntervalLabel: 'daily' },
  pro:        { maxMonitors: 10, maxSkills: 100,  scanIntervalLabel: '6-hour' },
  enterprise: { maxMonitors: -1, maxSkills: -1,   scanIntervalLabel: 'hourly' }
};

function tierLimits(plan) {
  return TIER_LIMITS[plan] || TIER_LIMITS.free;
}

// ─── POST / — Create a new monitor ──────────────────────────────────────────
router.post('/', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { name, skills } = req.body;
    if (!skills || !Array.isArray(skills) || skills.length === 0) {
      return res.status(400).json({
        error: 'Invalid input',
        message: 'Provide an array of skill URLs in "skills"',
        example: { name: 'My Agent Stack', skills: ['https://example.com/SKILL.md'] }
      });
    }

    // Validate URLs
    for (const url of skills) {
      try {
        const u = new URL(url);
        if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
      } catch {
        return res.status(400).json({ error: 'Invalid URL', message: `"${url}" is not a valid HTTP(S) URL` });
      }
    }

    const db = req.db;
    const plan = req.user.plan || 'free';
    const limits = tierLimits(plan);

    // Check monitor count
    const existing = await db.get(
      'SELECT COUNT(*) as cnt FROM monitors WHERE user_id = ? AND is_active = 1',
      [req.user.id]
    );
    if (limits.maxMonitors > 0 && (existing?.cnt || 0) >= limits.maxMonitors) {
      return res.status(403).json({
        error: 'Monitor limit reached',
        message: `Your ${plan} plan allows ${limits.maxMonitors} monitor(s). Upgrade for more.`,
        currentPlan: plan
      });
    }

    // Check skill count
    if (limits.maxSkills > 0 && skills.length > limits.maxSkills) {
      return res.status(403).json({
        error: 'Skill limit exceeded',
        message: `Your ${plan} plan allows ${limits.maxSkills} skills per monitor.`,
        currentPlan: plan
      });
    }

    const monitorId = crypto.randomUUID();
    const now = new Date().toISOString();

    await db.run(
      `INSERT INTO monitors (id, user_id, name, plan, is_active, created_at, updated_at)
       VALUES (?, ?, ?, ?, 1, ?, ?)`,
      [monitorId, req.user.id, name || 'Unnamed Monitor', plan, now, now]
    );

    // Insert skills
    for (const url of skills) {
      await db.run(
        `INSERT INTO monitor_skills (id, monitor_id, url, content_hash, created_at)
         VALUES (?, ?, ?, NULL, ?)`,
        [crypto.randomUUID(), monitorId, url, now]
      );
    }

    // Create initial alert
    await db.run(
      `INSERT INTO alerts (id, monitor_id, type, severity, message, skill_url, created_at)
       VALUES (?, ?, 'monitor_created', 'info', ?, NULL, ?)`,
      [crypto.randomUUID(), monitorId, `Monitor "${name || 'Unnamed Monitor'}" created with ${skills.length} skill(s)`, now]
    );

    res.status(201).json({
      id: monitorId,
      name: name || 'Unnamed Monitor',
      skills: skills,
      plan,
      scanInterval: limits.scanIntervalLabel,
      createdAt: now,
      message: 'Monitor created. First scan will begin shortly.'
    });

  } catch (error) {
    console.error('Create monitor error:', error);
    res.status(500).json({ error: 'Failed to create monitor', message: error.message });
  }
});

// ─── GET / — List all monitors for this API key ─────────────────────────────
router.get('/', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const monitors = await req.db.all(
      `SELECT m.id, m.name, m.plan, m.is_active, m.created_at, m.updated_at,
              (SELECT COUNT(*) FROM monitor_skills WHERE monitor_id = m.id) as skill_count,
              (SELECT COUNT(*) FROM alerts WHERE monitor_id = m.id AND acknowledged = 0) as unread_alerts,
              (SELECT MAX(scanned_at) FROM scan_history WHERE monitor_id = m.id) as last_scan_at
       FROM monitors m
       WHERE m.user_id = ? AND m.is_active = 1
       ORDER BY m.created_at DESC`,
      [req.user.id]
    );

    const limits = tierLimits(req.user.plan || 'free');

    res.json({
      monitors: monitors.map(m => ({
        id: m.id,
        name: m.name,
        skillCount: m.skill_count,
        unreadAlerts: m.unread_alerts,
        lastScanAt: m.last_scan_at,
        isActive: !!m.is_active,
        createdAt: m.created_at,
        updatedAt: m.updated_at
      })),
      limits: {
        maxMonitors: limits.maxMonitors === -1 ? 'unlimited' : limits.maxMonitors,
        maxSkills: limits.maxSkills === -1 ? 'unlimited' : limits.maxSkills,
        scanInterval: limits.scanIntervalLabel
      }
    });

  } catch (error) {
    console.error('List monitors error:', error);
    res.status(500).json({ error: 'Failed to list monitors', message: error.message });
  }
});

// ─── GET /:id — Get monitor details ─────────────────────────────────────────
router.get('/:id', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const db = req.db;
    const monitor = await db.get(
      'SELECT * FROM monitors WHERE id = ? AND user_id = ? AND is_active = 1',
      [req.params.id, req.user.id]
    );

    if (!monitor) {
      return res.status(404).json({ error: 'Monitor not found' });
    }

    const skills = await db.all(
      'SELECT id, url, content_hash, last_trust_score, last_scanned_at, created_at FROM monitor_skills WHERE monitor_id = ?',
      [monitor.id]
    );

    const recentScans = await db.all(
      `SELECT id, skill_url, trust_score, threat_level, content_hash, scan_id, scanned_at
       FROM scan_history
       WHERE monitor_id = ?
       ORDER BY scanned_at DESC
       LIMIT 50`,
      [monitor.id]
    );

    const unreadAlerts = await db.get(
      'SELECT COUNT(*) as cnt FROM alerts WHERE monitor_id = ? AND acknowledged = 0',
      [monitor.id]
    );

    res.json({
      id: monitor.id,
      name: monitor.name,
      plan: monitor.plan,
      isActive: !!monitor.is_active,
      createdAt: monitor.created_at,
      updatedAt: monitor.updated_at,
      skills: skills.map(s => ({
        id: s.id,
        url: s.url,
        contentHash: s.content_hash,
        lastTrustScore: s.last_trust_score,
        lastScannedAt: s.last_scanned_at
      })),
      recentScans,
      unreadAlerts: unreadAlerts?.cnt || 0
    });

  } catch (error) {
    console.error('Get monitor error:', error);
    res.status(500).json({ error: 'Failed to get monitor', message: error.message });
  }
});

// ─── DELETE /:id — Remove a monitor ──────────────────────────────────────────
router.delete('/:id', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const result = await req.db.run(
      'UPDATE monitors SET is_active = 0, updated_at = ? WHERE id = ? AND user_id = ?',
      [new Date().toISOString(), req.params.id, req.user.id]
    );

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Monitor not found' });
    }

    res.json({ message: 'Monitor deleted', id: req.params.id });

  } catch (error) {
    console.error('Delete monitor error:', error);
    res.status(500).json({ error: 'Failed to delete monitor', message: error.message });
  }
});

// ─── POST /:id/scan — Trigger manual re-scan ────────────────────────────────
router.post('/:id/scan', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const db = req.db;
    const monitor = await db.get(
      'SELECT * FROM monitors WHERE id = ? AND user_id = ? AND is_active = 1',
      [req.params.id, req.user.id]
    );

    if (!monitor) {
      return res.status(404).json({ error: 'Monitor not found' });
    }

    // Import scanner and run scan
    const { scanMonitor } = require('../monitoring/scheduler');
    const results = await scanMonitor(db, monitor.id);

    res.json({
      monitorId: monitor.id,
      message: 'Scan complete',
      results
    });

  } catch (error) {
    console.error('Manual scan error:', error);
    res.status(500).json({ error: 'Scan failed', message: error.message });
  }
});

// ─── GET /:id/alerts — Get alerts for a monitor ─────────────────────────────
router.get('/:id/alerts', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const db = req.db;
    const monitor = await db.get(
      'SELECT id FROM monitors WHERE id = ? AND user_id = ? AND is_active = 1',
      [req.params.id, req.user.id]
    );

    if (!monitor) {
      return res.status(404).json({ error: 'Monitor not found' });
    }

    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const offset = parseInt(req.query.offset) || 0;

    const alerts = await db.all(
      `SELECT id, type, severity, message, skill_url, old_score, new_score, acknowledged, created_at
       FROM alerts
       WHERE monitor_id = ?
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [monitor.id, limit, offset]
    );

    const totalCount = await db.get(
      'SELECT COUNT(*) as cnt FROM alerts WHERE monitor_id = ?',
      [monitor.id]
    );

    res.json({
      monitorId: monitor.id,
      alerts,
      total: totalCount?.cnt || 0,
      limit,
      offset
    });

  } catch (error) {
    console.error('Get alerts error:', error);
    res.status(500).json({ error: 'Failed to get alerts', message: error.message });
  }
});

// ─── POST /:id/alerts/acknowledge — Acknowledge alerts ──────────────────────
router.post('/:id/alerts/acknowledge', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const db = req.db;
    const monitor = await db.get(
      'SELECT id FROM monitors WHERE id = ? AND user_id = ? AND is_active = 1',
      [req.params.id, req.user.id]
    );

    if (!monitor) {
      return res.status(404).json({ error: 'Monitor not found' });
    }

    const { alertIds } = req.body;
    if (alertIds && Array.isArray(alertIds)) {
      for (const aid of alertIds) {
        await db.run(
          'UPDATE alerts SET acknowledged = 1 WHERE id = ? AND monitor_id = ?',
          [aid, monitor.id]
        );
      }
    } else {
      // Acknowledge all
      await db.run(
        'UPDATE alerts SET acknowledged = 1 WHERE monitor_id = ? AND acknowledged = 0',
        [monitor.id]
      );
    }

    res.json({ message: 'Alerts acknowledged' });

  } catch (error) {
    console.error('Acknowledge alerts error:', error);
    res.status(500).json({ error: 'Failed to acknowledge alerts', message: error.message });
  }
});

// ─── POST /:id/webhook — Register a webhook URL ─────────────────────────────
router.post('/:id/webhook', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Webhooks require enterprise plan
    const plan = req.user.plan || 'free';
    if (plan !== 'enterprise') {
      return res.status(403).json({
        error: 'Enterprise feature',
        message: 'Webhook notifications require an Enterprise plan.',
        currentPlan: plan
      });
    }

    const { url, secret } = req.body;
    if (!url) {
      return res.status(400).json({ error: 'Missing webhook URL' });
    }

    try {
      const u = new URL(url);
      if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
    } catch {
      return res.status(400).json({ error: 'Invalid webhook URL' });
    }

    const db = req.db;
    const monitor = await db.get(
      'SELECT id FROM monitors WHERE id = ? AND user_id = ? AND is_active = 1',
      [req.params.id, req.user.id]
    );

    if (!monitor) {
      return res.status(404).json({ error: 'Monitor not found' });
    }

    const webhookId = crypto.randomUUID();
    const webhookSecret = secret || crypto.randomBytes(32).toString('hex');

    await db.run(
      `INSERT INTO webhooks (id, monitor_id, url, secret, is_active, created_at)
       VALUES (?, ?, ?, ?, 1, ?)`,
      [webhookId, monitor.id, url, webhookSecret, new Date().toISOString()]
    );

    res.status(201).json({
      id: webhookId,
      url,
      secret: webhookSecret,
      message: 'Webhook registered. Alert payloads will be POSTed to this URL.',
      note: 'Payloads include X-AgentShield-Signature header (HMAC-SHA256 of body using your secret).'
    });

  } catch (error) {
    console.error('Register webhook error:', error);
    res.status(500).json({ error: 'Failed to register webhook', message: error.message });
  }
});

// ─── GET /:id/webhook — List webhooks ────────────────────────────────────────
router.get('/:id/webhook', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const db = req.db;
    const monitor = await db.get(
      'SELECT id FROM monitors WHERE id = ? AND user_id = ? AND is_active = 1',
      [req.params.id, req.user.id]
    );

    if (!monitor) {
      return res.status(404).json({ error: 'Monitor not found' });
    }

    const webhooks = await db.all(
      'SELECT id, url, is_active, created_at FROM webhooks WHERE monitor_id = ? AND is_active = 1',
      [monitor.id]
    );

    res.json({ monitorId: monitor.id, webhooks });

  } catch (error) {
    console.error('List webhooks error:', error);
    res.status(500).json({ error: 'Failed to list webhooks', message: error.message });
  }
});

// ─── DELETE /:id/webhook/:webhookId — Remove a webhook ───────────────────────
router.delete('/:id/webhook/:webhookId', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const db = req.db;
    const monitor = await db.get(
      'SELECT id FROM monitors WHERE id = ? AND user_id = ? AND is_active = 1',
      [req.params.id, req.user.id]
    );

    if (!monitor) {
      return res.status(404).json({ error: 'Monitor not found' });
    }

    const result = await db.run(
      'UPDATE webhooks SET is_active = 0 WHERE id = ? AND monitor_id = ?',
      [req.params.webhookId, monitor.id]
    );

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Webhook not found' });
    }

    res.json({ message: 'Webhook removed', id: req.params.webhookId });

  } catch (error) {
    console.error('Delete webhook error:', error);
    res.status(500).json({ error: 'Failed to delete webhook', message: error.message });
  }
});

module.exports = router;
