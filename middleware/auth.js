// API key authentication middleware
const crypto = require('crypto');

const API_PLANS = {
  free: {
    dailyLimit: 10,
    monthlyLimit: 300,
    features: ['basic-scan', 'basic-report'],
    name: 'Free'
  },
  pro: {
    dailyLimit: 1000,
    monthlyLimit: 30000,
    features: ['basic-scan', 'detailed-report', 'badges', 'api-access', 'batch-scan'],
    name: 'Pro ($19.99/mo)'
  },
  enterprise: {
    dailyLimit: -1, // unlimited
    monthlyLimit: -1,
    features: ['basic-scan', 'detailed-report', 'badges', 'api-access', 'batch-scan', 'webhook-alerts', 'compliance-reports', 'priority-support'],
    name: 'Enterprise ($99.99/mo)'
  }
};

// Generate API key
function generateAPIKey() {
  const prefix = 'ash_'; // AgentShield prefix
  const randomBytes = crypto.randomBytes(32).toString('hex');
  return prefix + randomBytes;
}

// Hash API key for storage
function hashAPIKey(apiKey) {
  return crypto.createHash('sha256').update(apiKey).digest('hex');
}

// Validate API key format
function isValidAPIKeyFormat(apiKey) {
  return typeof apiKey === 'string' && 
         apiKey.startsWith('ash_') && 
         apiKey.length === 68; // 4 (prefix) + 64 (hex)
}

// Authentication middleware
function authenticateAPI(db) {
  return async (req, res, next) => {
    const apiKey = req.headers['x-api-key'] || req.query.api_key;
    
    // Allow certain endpoints without authentication
    const publicEndpoints = ['/', '/health', '/stats', '/discovery'];
    const isPublicEndpoint = publicEndpoints.includes(req.path);
    
    // Allow registration endpoints without auth (POST /register creates accounts)
    const isRegisterPost = (req.path === '/register' || req.path === '/api/register' ||
                            req.path === '/register/' || req.path === '/api/register/') && req.method === 'POST';
    const isRegisterPlans = (req.path === '/register/plans' || req.path === '/api/register/plans') && req.method === 'GET';
    
    // Allow Stripe webhook without auth (Stripe signs these requests itself)
    const isBillingWebhook = (req.path === '/billing/webhook' || req.path === '/api/billing/webhook') && req.method === 'POST';
    
    // Allow scan endpoints without auth (free tier, IP rate-limited)
    const publicScanPaths = ['/scan', '/scan/', '/scan/url', '/scan/validate', '/scan/stats', '/scan/health',
                             '/api/scan', '/api/scan/', '/api/scan/url', '/api/scan/validate', '/api/scan/stats', '/api/scan/health'];
    const isPublicScan = publicScanPaths.includes(req.path);
    
    // For public endpoints and unauthenticated scans, set anonymous user and continue
    if (isPublicEndpoint || isRegisterPost || isRegisterPlans || isBillingWebhook || (isPublicScan && !apiKey)) {
      req.user = {
        id: 'anonymous',
        plan: 'free',
        features: API_PLANS.free.features,
        isAuthenticated: false
      };
      return next();
    }

    // If no API key and not a public/scan endpoint, require auth
    if (!apiKey) {
      return res.status(401).json({
        error: 'API key required',
        message: 'Please provide an API key in the X-API-Key header or api_key query parameter. Note: POST /scan is free and does not require authentication.',
        documentation: 'https://github.com/SiamakSafari/agent-shield#authentication',
        freeEndpoints: ['POST /scan', 'POST /scan/url', 'POST /scan/validate', 'GET /scan/stats', 'GET /scan/health']
      });
    }

    // Validate API key format
    if (!isValidAPIKeyFormat(apiKey)) {
      return res.status(401).json({
        error: 'Invalid API key format',
        message: 'API key must start with "ash_" and be 68 characters long'
      });
    }

    try {
      // Hash the provided key to look up in database
      const keyHash = hashAPIKey(apiKey);
      
      // Look up API key in database
      const apiKeyRecord = await db.get(
        `SELECT key_id, user_id, plan, daily_limit, monthly_limit, is_active, last_used_at
         FROM api_keys
         WHERE key_hash = ? AND is_active = TRUE`,
        [keyHash]
      );

      if (!apiKeyRecord) {
        return res.status(401).json({
          error: 'Invalid API key',
          message: 'The provided API key is not valid or has been deactivated'
        });
      }

      // Update last used timestamp
      await db.run(
        'UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_id = ?',
        [apiKeyRecord.key_id]
      );

      // Check usage limits
      const usageCheck = await checkUsageLimits(db, apiKeyRecord);
      if (!usageCheck.allowed) {
        return res.status(429).json({
          error: 'Usage limit exceeded',
          message: usageCheck.message,
          limits: {
            daily: apiKeyRecord.daily_limit,
            monthly: apiKeyRecord.monthly_limit,
            current: usageCheck.current
          },
          resetTime: usageCheck.resetTime
        });
      }

      // Set user context
      const plan = API_PLANS[apiKeyRecord.plan] || API_PLANS.free;
      req.user = {
        id: apiKeyRecord.user_id,
        keyId: apiKeyRecord.key_id,
        plan: apiKeyRecord.plan,
        planName: plan.name,
        features: plan.features,
        limits: {
          daily: apiKeyRecord.daily_limit,
          monthly: apiKeyRecord.monthly_limit
        },
        isAuthenticated: true
      };

      next();

    } catch (error) {
      console.error('Authentication error:', error);
      res.status(500).json({
        error: 'Authentication failed',
        message: 'Internal server error during authentication'
      });
    }
  };
}

// Check if user has specific feature access
function requireFeature(feature) {
  return (req, res, next) => {
    if (!req.user || !req.user.features.includes(feature)) {
      const planSuggestion = getPlanSuggestion(feature);
      
      return res.status(403).json({
        error: 'Feature not available',
        message: `This feature requires ${planSuggestion.name} plan or higher`,
        feature: feature,
        currentPlan: req.user?.plan || 'none',
        upgradeOptions: planSuggestion.plans
      });
    }
    next();
  };
}

// Check usage limits for API key
async function checkUsageLimits(db, apiKeyRecord) {
  const now = new Date();
  const today = now.toISOString().split('T')[0];
  const thisMonth = now.toISOString().substring(0, 7); // YYYY-MM

  // Get today's usage
  const dailyUsage = await db.get(
    `SELECT COUNT(*) as count
     FROM api_usage
     WHERE api_key = ? AND DATE(timestamp) = ?`,
    [apiKeyRecord.key_id, today]
  );

  // Get this month's usage
  const monthlyUsage = await db.get(
    `SELECT COUNT(*) as count
     FROM api_usage
     WHERE api_key = ? AND strftime('%Y-%m', timestamp) = ?`,
    [apiKeyRecord.key_id, thisMonth]
  );

  // Check daily limit
  if (apiKeyRecord.daily_limit > 0 && dailyUsage.count >= apiKeyRecord.daily_limit) {
    return {
      allowed: false,
      message: `Daily limit of ${apiKeyRecord.daily_limit} requests exceeded`,
      current: { daily: dailyUsage.count, monthly: monthlyUsage.count },
      resetTime: new Date(now.getTime() + 24 * 60 * 60 * 1000) // Tomorrow
    };
  }

  // Check monthly limit
  if (apiKeyRecord.monthly_limit > 0 && monthlyUsage.count >= apiKeyRecord.monthly_limit) {
    const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1);
    return {
      allowed: false,
      message: `Monthly limit of ${apiKeyRecord.monthly_limit} requests exceeded`,
      current: { daily: dailyUsage.count, monthly: monthlyUsage.count },
      resetTime: nextMonth
    };
  }

  return {
    allowed: true,
    current: { daily: dailyUsage.count, monthly: monthlyUsage.count }
  };
}

// Get plan suggestion for a feature
function getPlanSuggestion(feature) {
  const plans = [];
  
  Object.entries(API_PLANS).forEach(([planKey, planData]) => {
    if (planData.features.includes(feature)) {
      plans.push({
        plan: planKey,
        name: planData.name,
        features: planData.features
      });
    }
  });

  return {
    name: plans.length > 0 ? plans[0].name : 'Pro',
    plans: plans
  };
}

// Create new API key
async function createAPIKey(db, userId, plan = 'free') {
  const apiKey = generateAPIKey();
  const keyHash = hashAPIKey(apiKey);
  const keyId = crypto.randomUUID();
  
  const planConfig = API_PLANS[plan] || API_PLANS.free;
  
  await db.run(
    `INSERT INTO api_keys (key_id, key_hash, user_id, plan, daily_limit, monthly_limit)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [keyId, keyHash, userId, plan, planConfig.dailyLimit, planConfig.monthlyLimit]
  );

  return {
    apiKey: apiKey, // Return the actual key only once
    keyId: keyId,
    plan: plan,
    limits: {
      daily: planConfig.dailyLimit,
      monthly: planConfig.monthlyLimit
    }
  };
}

// Revoke API key
async function revokeAPIKey(db, keyId, userId) {
  const result = await db.run(
    `UPDATE api_keys
     SET is_active = FALSE
     WHERE key_id = ? AND user_id = ?`,
    [keyId, userId]
  );
  return result.changes > 0;
}

// List API keys for user
async function listAPIKeys(db, userId) {
  return await db.all(
    `SELECT key_id, plan, daily_limit, monthly_limit, created_at, last_used_at, is_active
     FROM api_keys
     WHERE user_id = ?
     ORDER BY created_at DESC`,
    [userId]
  );
}

module.exports = {
  generateAPIKey,
  hashAPIKey,
  isValidAPIKeyFormat,
  authenticateAPI,
  requireFeature,
  createAPIKey,
  revokeAPIKey,
  listAPIKeys,
  checkUsageLimits,
  API_PLANS
};
