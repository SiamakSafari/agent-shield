// Rate limiting middleware for AgentShield API
const rateLimit = require('express-rate-limit');

// Create rate limiter based on plan
function createRateLimiter(db) {
  return rateLimit({
    windowMs: 60 * 1000, // 1 minute window
    handler: (req, res) => {
      const retryAfter = Math.round(req.rateLimit.resetTime / 1000);
      
      res.status(429).json({
        error: 'Rate limit exceeded',
        message: 'Too many requests in a short period',
        limit: req.rateLimit.limit,
        remaining: req.rateLimit.remaining,
        resetTime: new Date(req.rateLimit.resetTime).toISOString(),
        retryAfter: retryAfter
      });
    },
    keyGenerator: (req) => {
      // Use API key if available, otherwise IP address
      return req.user?.keyId || req.ip;
    },
    limit: (req) => {
      // Different limits based on plan
      if (!req.user || !req.user.isAuthenticated) {
        return 5; // Anonymous users: 5 requests per minute
      }
      
      switch (req.user.plan) {
        case 'enterprise':
          return 1000; // Enterprise: 1000 requests per minute
        case 'pro':
          return 100; // Pro: 100 requests per minute
        case 'free':
        default:
          return 10; // Free: 10 requests per minute
      }
    },
    skip: (req) => {
      // Skip rate limiting for health checks and static assets
      return req.path === '/health' || req.path === '/';
    },
    standardHeaders: true,
    legacyHeaders: false,
  });
}

// Endpoint-specific rate limiters
function createEndpointLimiter(endpoint, limits) {
  return rateLimit({
    windowMs: limits.windowMs || 60 * 1000,
    max: limits.max || 10,
    message: {
      error: 'Rate limit exceeded',
      message: `Too many ${endpoint} requests`,
      limit: limits.max || 10,
      windowMs: limits.windowMs || 60000
    },
    standardHeaders: true,
    legacyHeaders: false,
  });
}

// Scanning endpoint rate limiter - more restrictive since it's resource intensive
const scanRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  handler: (req, res) => {
    res.status(429).json({
      error: 'Scan rate limit exceeded',
      message: 'Scanning is resource-intensive. Please wait before submitting another scan.',
      suggestion: 'Consider upgrading to Pro plan for higher limits',
      retryAfter: 60
    });
  },
  keyGenerator: (req) => req.user?.keyId || req.ip,
  max: (req) => {
    if (!req.user || !req.user.isAuthenticated) {
      return 2; // Anonymous: 2 scans per minute
    }
    
    switch (req.user.plan) {
      case 'enterprise':
        return 50; // Enterprise: 50 scans per minute
      case 'pro':
        return 20; // Pro: 20 scans per minute
      case 'free':
      default:
        return 5; // Free: 5 scans per minute
    }
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Batch scanning rate limiter - even more restrictive
const batchScanRateLimit = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: (req) => {
    if (!req.user || !req.user.isAuthenticated) {
      return 0; // Anonymous: no batch scanning
    }
    
    switch (req.user.plan) {
      case 'enterprise':
        return 10; // Enterprise: 10 batch scans per 5 minutes
      case 'pro':
        return 3; // Pro: 3 batch scans per 5 minutes
      case 'free':
      default:
        return 0; // Free: no batch scanning
    }
  },
  handler: (req, res) => {
    res.status(429).json({
      error: 'Batch scan rate limit exceeded',
      message: 'Batch scanning is limited to prevent abuse',
      currentPlan: req.user?.plan || 'none',
      suggestion: req.user?.plan === 'free' ? 
        'Upgrade to Pro plan to access batch scanning' :
        'Please wait before submitting another batch scan'
    });
  },
  keyGenerator: (req) => req.user?.keyId || req.ip,
  standardHeaders: true,
  legacyHeaders: false,
});

// Badge generation rate limiter
const badgeRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: (req) => {
    // Badges are lighter weight, allow more requests
    if (!req.user || !req.user.isAuthenticated) {
      return 10; // Anonymous: 10 badge requests per minute
    }
    
    switch (req.user.plan) {
      case 'enterprise':
        return 200; // Enterprise: 200 badge requests per minute
      case 'pro':
        return 100; // Pro: 100 badge requests per minute
      case 'free':
      default:
        return 30; // Free: 30 badge requests per minute
    }
  },
  keyGenerator: (req) => req.user?.keyId || req.ip,
  standardHeaders: true,
  legacyHeaders: false,
});

// IP-based rate limiter for unauthenticated requests
const ipRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per IP per 15 minutes
  message: {
    error: 'IP rate limit exceeded',
    message: 'Too many requests from this IP address',
    suggestion: 'Please obtain an API key for higher limits'
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip
});

// Daily quota middleware
function dailyQuotaCheck(db) {
  return async (req, res, next) => {
    // Skip for non-authenticated users on public endpoints
    if (!req.user || !req.user.isAuthenticated) {
      return next();
    }

    // Skip for unlimited plans
    if (req.user.limits.daily === -1) {
      return next();
    }

    try {
      const today = new Date().toISOString().split('T')[0];
      
      const dailyUsage = db.db.prepare(`
        SELECT COUNT(*) as count 
        FROM api_usage 
        WHERE api_key = ? AND DATE(timestamp) = ?
      `).get(req.user.keyId, today);

      if (dailyUsage.count >= req.user.limits.daily) {
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);
        tomorrow.setHours(0, 0, 0, 0);

        return res.status(429).json({
          error: 'Daily quota exceeded',
          message: `You have exceeded your daily limit of ${req.user.limits.daily} requests`,
          usage: {
            current: dailyUsage.count,
            limit: req.user.limits.daily
          },
          resetTime: tomorrow.toISOString(),
          plan: req.user.plan,
          upgradeUrl: 'https://agentshield.dev/pricing'
        });
      }

      // Add usage info to request for logging
      req.usage = {
        daily: dailyUsage.count,
        dailyLimit: req.user.limits.daily
      };

      next();
    } catch (error) {
      console.error('Daily quota check error:', error);
      next(); // Don't block on errors
    }
  };
}

// Abuse detection middleware
function abuseDetection(db) {
  return async (req, res, next) => {
    try {
      const identifier = req.user?.keyId || req.ip;
      const last5Minutes = new Date(Date.now() - 5 * 60 * 1000).toISOString();
      
      // Check for excessive failed requests
      const failedRequests = db.db.prepare(`
        SELECT COUNT(*) as count 
        FROM api_usage 
        WHERE (api_key = ? OR ip_address = ?) 
          AND timestamp > ? 
          AND status_code >= 400
      `).get(identifier, req.ip, last5Minutes);

      if (failedRequests.count > 20) {
        return res.status(429).json({
          error: 'Potential abuse detected',
          message: 'Too many failed requests detected. Please check your integration.',
          suggestion: 'Review API documentation and ensure proper error handling'
        });
      }

      // Check for suspicious patterns (same payload repeated many times)
      if (req.method === 'POST' && req.body) {
        const bodyHash = require('crypto')
          .createHash('sha256')
          .update(JSON.stringify(req.body))
          .digest('hex');

        const recentSimilar = db.db.prepare(`
          SELECT COUNT(*) as count 
          FROM api_usage 
          WHERE (api_key = ? OR ip_address = ?) 
            AND timestamp > ?
            AND error_message LIKE ?
        `).get(identifier, req.ip, last5Minutes, `%${bodyHash.substring(0, 8)}%`);

        if (recentSimilar.count > 10) {
          return res.status(429).json({
            error: 'Repetitive requests detected',
            message: 'Multiple identical requests detected. Please vary your test data.',
            suggestion: 'Use different content for testing or implement proper caching'
          });
        }
      }

      next();
    } catch (error) {
      console.error('Abuse detection error:', error);
      next(); // Don't block on errors
    }
  };
}

module.exports = {
  createRateLimiter,
  createEndpointLimiter,
  scanRateLimit,
  batchScanRateLimit,
  badgeRateLimit,
  ipRateLimit,
  dailyQuotaCheck,
  abuseDetection
};