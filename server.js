// AgentShield - Production-ready AI Agent Security Scanner
// Main Express server application

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const path = require('path');
require('dotenv').config();

// Import local modules
const { AgentShieldDB } = require('./db');
const { authenticateAPI } = require('./middleware/auth');
const { createRateLimiter, ipRateLimit, dailyQuotaCheck, abuseDetection } = require('./middleware/rateLimit');
const { trackUsage, analyticsMiddleware, securityMonitoring } = require('./middleware/usage');

// Import routes
const scanRoutes = require('./routes/scan');
const reportRoutes = require('./routes/reports');
const badgeRoutes = require('./routes/badges');
const registerRoutes = require('./routes/register');
const billingRoutes = require('./routes/billing');
const monitorRoutes = require('./routes/monitors');
const shieldScoreRoutes = require('./routes/shield-score');
const reputationRoutes = require('./routes/reputation');
const { startScheduler } = require('./monitoring/scheduler');

async function startServer() {
  // Initialize Express app
  const app = express();
  const PORT = process.env.PORT || 3000;
  const NODE_ENV = process.env.NODE_ENV || 'development';

  // Initialize database (async)
  const db = new AgentShieldDB({ dbPath: process.env.DATABASE_PATH || './agent-shield.db' });
  await db.init();

  // Security middleware
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https:"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
        scriptSrcAttr: ["'unsafe-inline'"],
        connectSrc: ["'self'"]
      }
    },
    crossOriginEmbedderPolicy: false
  }));

  // CORS configuration
  const corsOptions = {
    origin: process.env.ALLOWED_ORIGINS ? 
      process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) : 
      true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
    credentials: true,
    maxAge: 86400 // 24 hours
  };

  app.use(cors(corsOptions));

  // Compression
  app.use(compression());

  // Stripe webhook needs raw body — mount BEFORE json parser
  // The webhook route handler uses express.raw() internally
  app.use('/billing/webhook', express.raw({ type: 'application/json' }));
  app.use('/api/billing/webhook', express.raw({ type: 'application/json' }));

  // Body parsing middleware (for all other routes)
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Trust proxy for rate limiting behind reverse proxy
  app.set('trust proxy', 1);

  // Attach database to request object
  app.use((req, res, next) => {
    req.db = db;
    next();
  });

  // Usage tracking and analytics
  app.use(trackUsage(db));
  app.use(analyticsMiddleware(db));

  // Security monitoring
  app.use(securityMonitoring(db));

  // Serve static files (before auth — public content)
  app.use(express.static(path.join(__dirname, 'public')));

  // Blog routes - serve static HTML articles (before auth — public content)
  app.get('/blog', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'blog', 'index.html'));
  });
  app.get('/blog/:slug', (req, res) => {
    const slug = req.params.slug.replace(/[^a-z0-9-]/gi, '');
    const filePath = path.join(__dirname, 'public', 'blog', slug + '.html');
    res.sendFile(filePath, (err) => {
      if (err) {
        res.status(404).json({ error: 'Article not found' });
      }
    });
  });

  // IP-based rate limiting for unauthenticated requests
  app.use(ipRateLimit);

  // Authentication middleware
  app.use(authenticateAPI(db));

  // API rate limiting based on plan
  app.use(createRateLimiter(db));

  // Daily quota checking
  app.use(dailyQuotaCheck(db));

  // Abuse detection
  app.use(abuseDetection(db));

  // API Routes (both /scan and /api/scan work — we link /api/scan in marketing)
  app.use('/scan', scanRoutes);
  app.use('/api/scan', scanRoutes);
  app.use('/report', reportRoutes);
  app.use('/api/report', reportRoutes);
  app.use('/badges', badgeRoutes);
  app.use('/api/badges', badgeRoutes);
  app.use('/register', registerRoutes);
  app.use('/api/register', registerRoutes);
  app.use('/billing', billingRoutes);
  app.use('/api/billing', billingRoutes);
  app.use('/monitors', monitorRoutes);
  app.use('/api/monitors', monitorRoutes);
  app.use('/shield-score', shieldScoreRoutes);
  app.use('/api/shield-score', shieldScoreRoutes);
  app.use('/reputation', reputationRoutes);
  app.use('/api/reputation', reputationRoutes);

  // Root endpoint - Landing page
  app.get('/', async (req, res) => {
    try {
      const stats = await db.getStats();
      
      // If requesting JSON, return stats
      if (req.headers.accept?.includes('application/json')) {
        return res.json({
          name: 'AgentShield',
          version: '1.0.0',
          description: 'Production-ready security scanner for AI agent skills and plugins',
          status: 'operational',
          stats: stats.allTime,
          endpoints: {
            scan: '/scan',
            reports: '/report/:scanId',
            badges: '/badges/:scanId',
            health: '/health',
            discovery: '/discovery'
          }
        });
      }

      // Serve HTML landing page
      res.sendFile(path.join(__dirname, 'public', 'index.html'));
    } catch (error) {
      console.error('Root endpoint error:', error);
      res.status(500).json({
        error: 'Server error',
        message: 'Failed to load landing page'
      });
    }
  });

  // Health check endpoint
  app.get('/health', async (req, res) => {
    try {
      const stats = await db.getStats();
      const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        environment: NODE_ENV,
        database: {
          connected: !!db.db,
          stats: stats
        }
      };

      res.json(health);
    } catch (error) {
      console.error('Health check error:', error);
      res.status(503).json({
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: error.message
      });
    }
  });

  // Platform statistics endpoint
  app.get('/stats', async (req, res) => {
    try {
      const stats = await db.getStats();
      
      res.json({
        totalScans: stats.allTime.total_scans || 0,
        threatsDetected: stats.allTime.threats_detected || 0,
        cleanSkills: stats.allTime.clean_skills || 0,
        cleanPercentage: stats.allTime.total_scans > 0 ? 
          Math.round((stats.allTime.clean_skills / stats.allTime.total_scans) * 100) : 0,
        avgTrustScore: Math.round(stats.allTime.avg_trust_score || 0),
        avgScanTime: Math.round(stats.allTime.avg_scan_duration_ms || 0),
        today: stats.today,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      console.error('Stats endpoint error:', error);
      res.status(500).json({
        error: 'Failed to retrieve statistics',
        message: error.message
      });
    }
  });

  // x402 discovery endpoint for AI agent marketplaces
  app.get('/discovery', (req, res) => {
    try {
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      
      res.json({
        name: 'AgentShield Security Scanner',
        description: 'Comprehensive security scanning for AI agent skills and plugins',
        version: '1.0.0',
        provider: 'AgentShield',
        capabilities: [
          'skill-scanning',
          'vulnerability-detection',
          'security-reporting',
          'badge-generation',
          'batch-processing'
        ],
        endpoints: {
          scan: {
            url: `${baseUrl}/scan`,
            methods: ['POST'],
            description: 'Scan individual skills for security vulnerabilities',
            pricing: {
              free: { price: 0, limit: '10/day' },
              pro: { price: 0.05, limit: '1000/day' },
              enterprise: { price: 'contact', limit: 'unlimited' }
            }
          },
          batchScan: {
            url: `${baseUrl}/scan/batch`,
            methods: ['POST'],
            description: 'Scan multiple skills in a single request',
            pricing: {
              pro: { price: 0.04, limit: '25/batch' },
              enterprise: { price: 'contact', limit: '100/batch' }
            }
          },
          badges: {
            url: `${baseUrl}/badges/:scanId`,
            methods: ['GET'],
            description: 'Generate embeddable security badges',
            pricing: { free: { price: 0, limit: '30/min' } }
          }
        },
        authentication: {
          type: 'api-key',
          header: 'X-API-Key',
          registration: `${baseUrl}#pricing`
        },
        documentation: `${baseUrl}#documentation`,
        support: 'https://github.com/SiamakSafari/agent-shield/issues'
      });
    } catch (error) {
      console.error('Discovery endpoint error:', error);
      res.status(500).json({
        error: 'Discovery failed',
        message: error.message
      });
    }
  });

  // Verification endpoint (placeholder for future manual verification)
  app.post('/verify', (req, res) => {
    res.json({
      message: 'Manual verification feature coming soon',
      description: 'Submit skills for manual security review by our experts',
      status: 'not_implemented',
      estimatedLaunch: '2024-Q2',
      notification: 'Sign up for updates at https://agentshield.dev'
    });
  });

  // Global error handler
  app.use((error, req, res, next) => {
    console.error('Global error handler:', error);
    
    // Don't leak error details in production
    const isDevelopment = NODE_ENV === 'development';
    
    res.status(error.status || 500).json({
      error: 'Internal server error',
      message: isDevelopment ? error.message : 'Something went wrong',
      timestamp: new Date().toISOString(),
      ...(isDevelopment && { stack: error.stack })
    });
  });

  // 404 handler
  app.use((req, res) => {
    res.status(404).json({
      error: 'Not found',
      message: `Endpoint ${req.method} ${req.path} does not exist`,
      availableEndpoints: [
        'POST /scan',
        'POST /scan/batch', 
        'GET /report/:scanId',
        'GET /badges/:scanId',
        'POST /register',
        'GET /register/plans',
        'POST /billing/checkout',
        'GET /billing/status',
        'GET /billing/portal',
        'POST /api/monitors',
        'GET /api/monitors',
        'GET /api/monitors/:id',
        'DELETE /api/monitors/:id',
        'POST /api/monitors/:id/scan',
        'GET /api/monitors/:id/alerts',
        'POST /api/monitors/:id/webhook',
        'GET /api/shield-score?skills=url1,url2',
        'GET /api/shield-score/badge/:score',
        'GET /api/shield-score/leaderboard',
        'GET /api/reputation?agent_id=OWNER/REPO',
        'GET /health',
        'GET /stats',
        'GET /discovery'
      ]
    });
  });

  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    if (db) db.close();
    process.exit(0);
  });

  process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully');
    if (db) db.close();
    process.exit(0);
  });

  // Start server
  app.listen(PORT, () => {
    console.log(`🛡️  AgentShield Server running on port ${PORT}`);
    console.log(`📊 Environment: ${NODE_ENV}`);
    console.log(`🔗 API Base URL: http://localhost:${PORT}`);
    console.log(`📋 Health Check: http://localhost:${PORT}/health`);
    console.log(`📈 Statistics: http://localhost:${PORT}/stats`);
    
    if (NODE_ENV === 'development') {
      console.log(`🏠 Landing Page: http://localhost:${PORT}`);
      console.log(`🔍 Discovery: http://localhost:${PORT}/discovery`);
    }

    // Start background monitoring scheduler
    const schedulerId = startScheduler(db);
    console.log(`📡 Continuous Monitoring scheduler active`);

    // Clean up scheduler on shutdown
    process.on('SIGTERM', () => clearInterval(schedulerId));
    process.on('SIGINT', () => clearInterval(schedulerId));
  });

  return app;
}

// Start the server
const appPromise = startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

module.exports = appPromise;
