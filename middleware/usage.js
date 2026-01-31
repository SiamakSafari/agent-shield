// Usage tracking and analytics middleware for AgentShield
const crypto = require('crypto');

// Main usage tracking middleware
function trackUsage(db) {
  return (req, res, next) => {
    const startTime = Date.now();
    
    // Capture original end function
    const originalEnd = res.end;
    
    // Override end function to log after response
    res.end = function(chunk, encoding) {
      // Call original end function
      originalEnd.call(this, chunk, encoding);
      
      // Log usage after response is sent (non-blocking, async fire-and-forget)
      setImmediate(() => {
        logRequest(db, req, res, startTime).catch(err => {
          console.error('Error logging request:', err);
        });
      });
    };
    
    next();
  };
}

// Log individual request (async)
async function logRequest(db, req, res, startTime) {
  const responseTime = Date.now() - startTime;
  const endpoint = normalizeEndpoint(req.path);
  
  await db.logAPIUsage(
    req.user?.keyId || null,
    endpoint,
    req.method,
    getClientIP(req),
    req.get('User-Agent') || '',
    responseTime,
    res.statusCode,
    res.statusCode >= 400 ? getErrorMessage(res) : null
  );
}

// Normalize endpoints for analytics (group similar endpoints)
function normalizeEndpoint(path) {
  // Replace UUIDs, IDs, and other dynamic parts with placeholders
  return path
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:id') // UUIDs
    .replace(/\/[0-9]+/g, '/:id') // Numeric IDs
    .replace(/\/[a-zA-Z0-9_-]{20,}/g, '/:token') // Long tokens/keys
    .toLowerCase();
}

// Get client IP address (handle proxies)
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
         req.headers['x-real-ip'] ||
         req.connection?.remoteAddress ||
         req.socket?.remoteAddress ||
         req.ip;
}

// Extract error message from response
function getErrorMessage(res) {
  if (res.statusCode >= 500) {
    return 'Internal server error';
  } else if (res.statusCode === 429) {
    return 'Rate limit exceeded';
  } else if (res.statusCode === 401) {
    return 'Unauthorized';
  } else if (res.statusCode === 403) {
    return 'Forbidden';
  } else if (res.statusCode === 400) {
    return 'Bad request';
  } else if (res.statusCode === 404) {
    return 'Not found';
  }
  return null;
}

// Analytics middleware for generating usage reports
function analyticsMiddleware(db) {
  return (req, res, next) => {
    // Add analytics helper functions to request object (all async)
    req.analytics = {
      getUserStats: (userId, days = 30) => getUserStats(db, userId, days),
      getEndpointStats: (endpoint, days = 30) => getEndpointStats(db, endpoint, days),
      getSystemStats: (days = 30) => getSystemStats(db, days),
      getErrorAnalysis: (days = 7) => getErrorAnalysis(db, days)
    };
    
    next();
  };
}

// Get user-specific usage statistics
async function getUserStats(db, userId, days = 30) {
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  
  const stats = await db.get(
    `SELECT 
      COUNT(*) as total_requests,
      AVG(response_time_ms) as avg_response_time,
      COUNT(CASE WHEN status_code < 400 THEN 1 END) as successful_requests,
      COUNT(CASE WHEN status_code >= 400 THEN 1 END) as failed_requests,
      COUNT(DISTINCT endpoint) as unique_endpoints,
      COUNT(DISTINCT DATE(timestamp)) as active_days
    FROM api_usage 
    WHERE api_key IN (
      SELECT key_id FROM api_keys WHERE user_id = ?
    ) AND timestamp > ?`,
    [userId, since]
  );

  const dailyUsage = await db.all(
    `SELECT 
      DATE(timestamp) as date,
      COUNT(*) as requests,
      AVG(response_time_ms) as avg_response_time
    FROM api_usage 
    WHERE api_key IN (
      SELECT key_id FROM api_keys WHERE user_id = ?
    ) AND timestamp > ?
    GROUP BY DATE(timestamp)
    ORDER BY date DESC`,
    [userId, since]
  );

  const endpointBreakdown = await db.all(
    `SELECT 
      endpoint,
      COUNT(*) as requests,
      AVG(response_time_ms) as avg_response_time
    FROM api_usage 
    WHERE api_key IN (
      SELECT key_id FROM api_keys WHERE user_id = ?
    ) AND timestamp > ?
    GROUP BY endpoint
    ORDER BY requests DESC
    LIMIT 10`,
    [userId, since]
  );

  return {
    summary: stats,
    dailyUsage: dailyUsage,
    topEndpoints: endpointBreakdown
  };
}

// Get endpoint-specific statistics
async function getEndpointStats(db, endpoint, days = 30) {
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  
  const stats = await db.get(
    `SELECT 
      COUNT(*) as total_requests,
      AVG(response_time_ms) as avg_response_time,
      MIN(response_time_ms) as min_response_time,
      MAX(response_time_ms) as max_response_time,
      COUNT(CASE WHEN status_code < 400 THEN 1 END) as successful_requests,
      COUNT(CASE WHEN status_code >= 400 THEN 1 END) as failed_requests,
      COUNT(DISTINCT api_key) as unique_users
    FROM api_usage 
    WHERE endpoint = ? AND timestamp > ?`,
    [endpoint, since]
  );

  const hourlyPattern = await db.all(
    `SELECT 
      strftime('%H', timestamp) as hour,
      COUNT(*) as requests,
      AVG(response_time_ms) as avg_response_time
    FROM api_usage 
    WHERE endpoint = ? AND timestamp > ?
    GROUP BY strftime('%H', timestamp)
    ORDER BY hour`,
    [endpoint, since]
  );

  return {
    summary: stats,
    hourlyPattern: hourlyPattern
  };
}

// Get system-wide statistics
async function getSystemStats(db, days = 30) {
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  
  const overview = await db.get(
    `SELECT 
      COUNT(*) as total_requests,
      COUNT(DISTINCT api_key) as active_users,
      COUNT(DISTINCT ip_address) as unique_ips,
      AVG(response_time_ms) as avg_response_time,
      COUNT(CASE WHEN status_code < 400 THEN 1 END) as successful_requests,
      COUNT(CASE WHEN status_code >= 400 THEN 1 END) as failed_requests
    FROM api_usage 
    WHERE timestamp > ?`,
    [since]
  );

  const dailyTrends = await db.all(
    `SELECT 
      DATE(timestamp) as date,
      COUNT(*) as total_requests,
      COUNT(DISTINCT api_key) as active_users,
      AVG(response_time_ms) as avg_response_time,
      COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_rate
    FROM api_usage 
    WHERE timestamp > ?
    GROUP BY DATE(timestamp)
    ORDER BY date DESC`,
    [since]
  );

  const topEndpoints = await db.all(
    `SELECT 
      endpoint,
      COUNT(*) as requests,
      AVG(response_time_ms) as avg_response_time,
      COUNT(CASE WHEN status_code >= 400 THEN 1 END) as errors
    FROM api_usage 
    WHERE timestamp > ?
    GROUP BY endpoint
    ORDER BY requests DESC
    LIMIT 20`,
    [since]
  );

  const planUsage = await db.all(
    `SELECT 
      ak.plan,
      COUNT(*) as requests,
      COUNT(DISTINCT ak.key_id) as active_keys,
      AVG(au.response_time_ms) as avg_response_time
    FROM api_usage au
    JOIN api_keys ak ON au.api_key = ak.key_id
    WHERE au.timestamp > ?
    GROUP BY ak.plan
    ORDER BY requests DESC`,
    [since]
  );

  return {
    overview: overview,
    dailyTrends: dailyTrends,
    topEndpoints: topEndpoints,
    planUsage: planUsage
  };
}

// Get error analysis
async function getErrorAnalysis(db, days = 7) {
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
  
  const errorBreakdown = await db.all(
    `SELECT 
      status_code,
      error_message,
      COUNT(*) as count,
      COUNT(DISTINCT api_key) as affected_users,
      COUNT(DISTINCT ip_address) as affected_ips
    FROM api_usage 
    WHERE status_code >= 400 AND timestamp > ?
    GROUP BY status_code, error_message
    ORDER BY count DESC
    LIMIT 50`,
    [since]
  );

  const errorTrends = await db.all(
    `SELECT 
      DATE(timestamp) as date,
      status_code,
      COUNT(*) as count
    FROM api_usage 
    WHERE status_code >= 400 AND timestamp > ?
    GROUP BY DATE(timestamp), status_code
    ORDER BY date DESC, count DESC`,
    [since]
  );

  const slowQueries = await db.all(
    `SELECT 
      endpoint,
      method,
      AVG(response_time_ms) as avg_response_time,
      MAX(response_time_ms) as max_response_time,
      COUNT(*) as request_count
    FROM api_usage 
    WHERE timestamp > ? AND response_time_ms > 1000
    GROUP BY endpoint, method
    ORDER BY avg_response_time DESC
    LIMIT 20`,
    [since]
  );

  return {
    errorBreakdown: errorBreakdown,
    errorTrends: errorTrends,
    slowQueries: slowQueries
  };
}

// Security monitoring middleware
function securityMonitoring(db) {
  return (req, res, next) => {
    // Track suspicious patterns
    const patterns = detectSuspiciousPatterns(req);
    
    if (patterns.length > 0) {
      // Log security events (could also send alerts)
      console.warn('Suspicious patterns detected:', {
        ip: getClientIP(req),
        userAgent: req.get('User-Agent'),
        patterns: patterns,
        endpoint: req.path,
        apiKey: req.user?.keyId
      });
    }
    
    next();
  };
}

// Detect suspicious request patterns
function detectSuspiciousPatterns(req) {
  const patterns = [];
  
  // Check for SQL injection attempts
  const sqlInjectionPatterns = [
    /(\%27)|(\')|(\-\-)|(\%23)|(#)/i,
    /((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i,
    /\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i
  ];
  
  const queryString = req.url;
  for (const pattern of sqlInjectionPatterns) {
    if (pattern.test(queryString)) {
      patterns.push('sql_injection_attempt');
      break;
    }
  }
  
  // Check for XSS attempts
  const xssPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi
  ];
  
  const bodyStr = JSON.stringify(req.body || {});
  for (const pattern of xssPatterns) {
    if (pattern.test(bodyStr) || pattern.test(queryString)) {
      patterns.push('xss_attempt');
      break;
    }
  }
  
  // Check for suspiciously long payloads
  if (bodyStr.length > 100000) { // 100KB
    patterns.push('large_payload');
  }
  
  // Check for suspicious user agents
  const userAgent = req.get('User-Agent') || '';
  const suspiciousUAs = ['sqlmap', 'nikto', 'nmap', 'masscan', 'nessus'];
  if (suspiciousUAs.some(ua => userAgent.toLowerCase().includes(ua))) {
    patterns.push('suspicious_user_agent');
  }
  
  return patterns;
}

module.exports = {
  trackUsage,
  analyticsMiddleware,
  securityMonitoring,
  getUserStats,
  getEndpointStats,
  getSystemStats,
  getErrorAnalysis,
  normalizeEndpoint,
  getClientIP
};
