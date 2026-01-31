// Scanning API routes
const express = require('express');
const router = express.Router();
const { AgentShieldScanner } = require('../scanner');
const { requireFeature } = require('../middleware/auth');
const { scanRateLimit, batchScanRateLimit } = require('../middleware/rateLimit');

// Initialize scanner
const scanner = new AgentShieldScanner();

// POST /scan - Main scanning endpoint
router.post('/', scanRateLimit, async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { content, url, github, source } = req.body;
    
    // Validate input
    if (!content && !url && !github) {
      return res.status(400).json({
        error: 'Invalid input',
        message: 'Provide either content, url, or github repository',
        examples: {
          content: 'Raw SKILL.md content as string',
          url: 'https://example.com/SKILL.md',
          github: 'https://github.com/user/repo'
        }
      });
    }

    // Prepare scan input
    let scanInput;
    if (content) {
      scanInput = { content, source: source || 'inline' };
    } else if (url) {
      scanInput = { url };
    } else if (github) {
      scanInput = { github };
    }

    // Perform scan
    const result = await scanner.scanContent(scanInput);
    
    if (result.error) {
      return res.status(400).json(result);
    }

    // Save to database
    if (req.db) {
      await req.db.saveScan(result, {
        userId: req.user?.id || 'anonymous',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });
    }

    // Add scan performance metrics
    result.metadata = {
      ...result.metadata,
      scanDurationMs: Date.now() - startTime,
      apiVersion: '1.0.0'
    };

    res.json(result);

  } catch (error) {
    console.error('Scan error:', error);
    
    res.status(500).json({
      error: 'Scan failed',
      message: 'Internal error during scanning',
      scanId: null,
      timestamp: new Date().toISOString()
    });
  }
});

// POST /scan/batch - Batch scanning endpoint
router.post('/batch', batchScanRateLimit, requireFeature('batch-scan'), async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { inputs, options = {} } = req.body;
    
    // Validate input
    if (!Array.isArray(inputs) || inputs.length === 0) {
      return res.status(400).json({
        error: 'Invalid input',
        message: 'Provide an array of scan inputs',
        example: {
          inputs: [
            { content: 'SKILL.md content', source: 'skill1' },
            { url: 'https://example.com/skill2.md' },
            { github: 'https://github.com/user/skill3' }
          ]
        }
      });
    }

    // Limit batch size based on plan
    const maxBatchSize = getBatchLimit(req.user?.plan);
    if (inputs.length > maxBatchSize) {
      return res.status(400).json({
        error: 'Batch size exceeded',
        message: `Maximum batch size for ${req.user?.plan || 'free'} plan is ${maxBatchSize}`,
        provided: inputs.length,
        maximum: maxBatchSize
      });
    }

    // Perform batch scan
    const result = await scanner.batchScan(inputs);
    
    // Save individual scans to database
    if (req.db && result.results) {
      for (const scanResult of result.results) {
        if (!scanResult.error) {
          await req.db.saveScan(scanResult, {
            userId: req.user?.id || 'anonymous',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
          });
        }
      }
    }

    // Add batch performance metrics
    result.metadata = {
      batchDurationMs: Date.now() - startTime,
      apiVersion: '1.0.0',
      processingOptions: options
    };

    res.json(result);

  } catch (error) {
    console.error('Batch scan error:', error);
    
    res.status(500).json({
      error: 'Batch scan failed',
      message: 'Internal error during batch scanning',
      timestamp: new Date().toISOString()
    });
  }
});

// POST /scan/url - URL-specific scanning endpoint with additional options
router.post('/url', scanRateLimit, async (req, res) => {
  try {
    const { url, options = {} } = req.body;
    
    if (!url) {
      return res.status(400).json({
        error: 'URL required',
        message: 'Provide a URL to scan'
      });
    }

    // Validate URL format
    try {
      const urlObj = new URL(url);
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        throw new Error('Invalid protocol');
      }
    } catch (e) {
      return res.status(400).json({
        error: 'Invalid URL',
        message: 'URL must be a valid HTTP or HTTPS URL'
      });
    }

    const scanInput = { url, options };
    const result = await scanner.scanContent(scanInput);
    
    if (result.error) {
      return res.status(400).json(result);
    }

    // Save to database
    if (req.db) {
      await req.db.saveScan(result, {
        userId: req.user?.id || 'anonymous',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });
    }

    res.json(result);

  } catch (error) {
    console.error('URL scan error:', error);
    
    res.status(500).json({
      error: 'URL scan failed',
      message: error.message || 'Internal error during URL scanning'
    });
  }
});

// GET /scan/stats - Scanning statistics
router.get('/stats', (req, res) => {
  try {
    const stats = scanner.getStats();
    res.json({
      ...stats,
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to retrieve stats',
      message: error.message
    });
  }
});

// GET /scan/health - Scanner health check
router.get('/health', (req, res) => {
  try {
    const health = scanner.healthCheck();
    res.json(health);
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Helper function to get batch size limits
function getBatchLimit(plan) {
  switch (plan) {
    case 'enterprise':
      return 100;
    case 'pro':
      return 25;
    case 'free':
    default:
      return 0; // Free plan doesn't support batch scanning
  }
}

// POST /scan/validate - Validate scan input without performing full scan
router.post('/validate', async (req, res) => {
  try {
    const { content, url, github } = req.body;
    
    const validation = {
      isValid: false,
      issues: [],
      suggestions: []
    };

    if (content) {
      // Basic content validation
      if (typeof content !== 'string') {
        validation.issues.push('Content must be a string');
      } else if (content.trim().length === 0) {
        validation.issues.push('Content cannot be empty');
      } else if (content.length > 1000000) { // 1MB limit
        validation.issues.push('Content too large (max 1MB)');
      } else {
        validation.isValid = true;
        validation.suggestions.push('Content format looks valid');
      }
    } else if (url) {
      try {
        const urlObj = new URL(url);
        if (!['http:', 'https:'].includes(urlObj.protocol)) {
          validation.issues.push('URL must use HTTP or HTTPS protocol');
        } else {
          validation.isValid = true;
          validation.suggestions.push('URL format looks valid');
        }
      } catch (e) {
        validation.issues.push('Invalid URL format');
      }
    } else if (github) {
      const githubPattern = /^https:\/\/github\.com\/[^\/]+\/[^\/]+/;
      if (!githubPattern.test(github)) {
        validation.issues.push('Invalid GitHub repository URL format');
      } else {
        validation.isValid = true;
        validation.suggestions.push('GitHub URL format looks valid');
      }
    } else {
      validation.issues.push('Must provide content, url, or github parameter');
    }

    res.json(validation);

  } catch (error) {
    res.status(500).json({
      error: 'Validation failed',
      message: error.message
    });
  }
});

module.exports = router;