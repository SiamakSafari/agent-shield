// Registration and API key management routes
const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const { createAPIKey, revokeAPIKey, listAPIKeys, hashAPIKey, API_PLANS } = require('../middleware/auth');

// POST / — Register new account + get free API key
router.post('/', async (req, res) => {
  try {
    const { email, name } = req.body;

    if (!email || !name) {
      return res.status(400).json({
        error: 'Missing required fields',
        message: 'Both "email" and "name" are required',
        example: { email: 'dev@example.com', name: 'Jane Developer' }
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        error: 'Invalid email',
        message: 'Please provide a valid email address'
      });
    }

    const db = req.db;

    // Ensure users table exists
    await db.run(`
      CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        plan TEXT DEFAULT 'free',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Check if email already registered
    const existing = await db.get('SELECT user_id, email, name, plan FROM users WHERE email = ?', [email]);
    if (existing) {
      return res.status(409).json({
        error: 'Email already registered',
        message: 'An account with this email already exists. Use your existing API key or generate a new one.',
        userId: existing.user_id
      });
    }

    // Create user
    const userId = crypto.randomUUID();
    await db.run(
      'INSERT INTO users (user_id, email, name, plan) VALUES (?, ?, ?, ?)',
      [userId, email, name, 'free']
    );

    // Create free API key
    const keyResult = await createAPIKey(db, userId, 'free');

    res.status(201).json({
      message: 'Account created successfully',
      user: {
        id: userId,
        email,
        name,
        plan: 'free'
      },
      apiKey: keyResult.apiKey,
      keyId: keyResult.keyId,
      limits: keyResult.limits,
      usage: {
        header: 'X-API-Key',
        example: `curl -H "X-API-Key: ${keyResult.apiKey}" -X POST https://agent-shield-production.up.railway.app/scan -H "Content-Type: application/json" -d '{"content":"# test skill"}'`
      },
      important: '⚠️ Save your API key now — it cannot be retrieved later!'
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      error: 'Registration failed',
      message: error.message
    });
  }
});

// GET /keys — List all API keys for authenticated user
router.get('/keys', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Provide your API key in X-API-Key header to manage keys'
      });
    }

    const keys = await listAPIKeys(req.db, req.user.id);
    res.json({
      userId: req.user.id,
      plan: req.user.plan,
      keys: keys.map(k => ({
        keyId: k.key_id,
        plan: k.plan,
        dailyLimit: k.daily_limit,
        monthlyLimit: k.monthly_limit,
        isActive: !!k.is_active,
        createdAt: k.created_at,
        lastUsedAt: k.last_used_at
      }))
    });
  } catch (error) {
    console.error('List keys error:', error);
    res.status(500).json({ error: 'Failed to list keys', message: error.message });
  }
});

// POST /key — Generate additional API key (authenticated)
router.post('/key', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Provide your API key in X-API-Key header to generate a new key'
      });
    }

    // Check how many active keys user has (limit to 5)
    const activeKeys = await req.db.all(
      'SELECT key_id FROM api_keys WHERE user_id = ? AND is_active = TRUE',
      [req.user.id]
    );

    if (activeKeys.length >= 5) {
      return res.status(400).json({
        error: 'Key limit reached',
        message: 'Maximum 5 active API keys per account. Revoke an existing key first.',
        activeKeys: activeKeys.length
      });
    }

    const keyResult = await createAPIKey(req.db, req.user.id, req.user.plan);

    res.status(201).json({
      message: 'New API key created',
      apiKey: keyResult.apiKey,
      keyId: keyResult.keyId,
      limits: keyResult.limits,
      important: '⚠️ Save your API key now — it cannot be retrieved later!'
    });
  } catch (error) {
    console.error('Create key error:', error);
    res.status(500).json({ error: 'Failed to create key', message: error.message });
  }
});

// DELETE /key/:keyId — Revoke an API key (authenticated)
router.delete('/key/:keyId', async (req, res) => {
  try {
    if (!req.user || !req.user.isAuthenticated) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Provide your API key in X-API-Key header to revoke keys'
      });
    }

    const { keyId } = req.params;
    const revoked = await revokeAPIKey(req.db, keyId, req.user.id);

    if (!revoked) {
      return res.status(404).json({
        error: 'Key not found',
        message: 'API key not found or does not belong to your account'
      });
    }

    res.json({
      message: 'API key revoked successfully',
      keyId,
      warning: 'This key can no longer be used for authentication'
    });
  } catch (error) {
    console.error('Revoke key error:', error);
    res.status(500).json({ error: 'Failed to revoke key', message: error.message });
  }
});

// GET /plans — Show available plans
router.get('/plans', async (req, res) => {
  res.json({
    plans: Object.entries(API_PLANS).map(([key, plan]) => ({
      id: key,
      name: plan.name,
      dailyLimit: plan.dailyLimit === -1 ? 'unlimited' : plan.dailyLimit,
      monthlyLimit: plan.monthlyLimit === -1 ? 'unlimited' : plan.monthlyLimit,
      features: plan.features
    }))
  });
});

module.exports = router;
