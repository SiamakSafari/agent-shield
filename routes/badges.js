// Badge generation API routes
const express = require('express');
const router = express.Router();
const { 
  generateDynamicBadge, 
  generateAllBadges,
  generateMarkdownSnippet,
  generateHTMLSnippet 
} = require('../scanner/badges');
const { badgeRateLimit } = require('../middleware/rateLimit');

// GET /badges/:scanId - Generate badge for specific scan
router.get('/:scanId', badgeRateLimit, async (req, res) => {
  try {
    const { scanId } = req.params;
    const { style = 'default', format = 'svg' } = req.query;
    
    // Validate scan ID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(scanId)) {
      return res.status(400).json({
        error: 'Invalid scan ID',
        message: 'Scan ID must be a valid UUID'
      });
    }

    // Retrieve scan result from database
    const scanResult = await req.db?.getScan(scanId);
    
    if (!scanResult) {
      return res.status(404).json({
        error: 'Scan not found',
        message: 'No scan found with the provided ID',
        scanId: scanId
      });
    }

    // Generate badge based on style
    const validStyles = ['default', 'compact', 'detailed', 'trust-score'];
    const badgeStyle = validStyles.includes(style) ? style : 'default';
    
    const badgeSVG = generateDynamicBadge(scanResult, badgeStyle);

    // Set appropriate headers
    res.set('Content-Type', 'image/svg+xml');
    res.set('Cache-Control', 'max-age=3600'); // Cache for 1 hour
    res.set('X-Scan-ID', scanId);
    res.set('X-Threat-Level', scanResult.threatLevel);
    res.set('X-Trust-Score', scanResult.trustScore.toString());
    
    res.send(badgeSVG);

  } catch (error) {
    console.error('Badge generation error:', error);
    
    // Return error badge
    const errorBadge = generateErrorBadge(error.message);
    res.set('Content-Type', 'image/svg+xml');
    res.status(500).send(errorBadge);
  }
});

// GET /badges/:scanId/all - Get all badge variants for a scan
router.get('/:scanId/all', badgeRateLimit, async (req, res) => {
  try {
    const { scanId } = req.params;
    
    // Validate scan ID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(scanId)) {
      return res.status(400).json({
        error: 'Invalid scan ID',
        message: 'Scan ID must be a valid UUID'
      });
    }

    // Retrieve scan result from database
    const scanResult = await req.db?.getScan(scanId);
    
    if (!scanResult) {
      return res.status(404).json({
        error: 'Scan not found',
        message: 'No scan found with the provided ID',
        scanId: scanId
      });
    }

    // Generate all badge variants
    const badges = generateAllBadges(scanResult);
    
    // Generate embedding code snippets
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const embedSnippets = {
      markdown: generateMarkdownSnippet(scanId, scanResult.badge, baseUrl),
      html: generateHTMLSnippet(scanId, scanResult.badge, baseUrl)
    };

    res.json({
      scanId: scanId,
      threatLevel: scanResult.threatLevel,
      trustScore: scanResult.trustScore,
      badge: scanResult.badge,
      badges: badges,
      embedSnippets: embedSnippets,
      urls: {
        default: `${baseUrl}/badges/${scanId}`,
        compact: `${baseUrl}/badges/${scanId}?style=compact`,
        detailed: `${baseUrl}/badges/${scanId}?style=detailed`,
        trustScore: `${baseUrl}/badges/${scanId}?style=trust-score`
      }
    });

  } catch (error) {
    console.error('Badge variants error:', error);
    res.status(500).json({
      error: 'Failed to generate badge variants',
      message: error.message
    });
  }
});

// GET /badges/:scanId/embed - Get embedding instructions
router.get('/:scanId/embed', async (req, res) => {
  try {
    const { scanId } = req.params;
    const { platform = 'markdown' } = req.query;
    
    // Validate scan ID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(scanId)) {
      return res.status(400).json({
        error: 'Invalid scan ID',
        message: 'Scan ID must be a valid UUID'
      });
    }

    // Retrieve scan result
    const scanResult = await req.db?.getScan(scanId);
    
    if (!scanResult) {
      return res.status(404).json({
        error: 'Scan not found',
        message: 'No scan found with the provided ID'
      });
    }

    const baseUrl = `${req.protocol}://${req.get('host')}`;
    
    const embedInstructions = {
      markdown: {
        name: 'Markdown',
        description: 'For GitHub README, GitLab, Bitbucket, and other Markdown files',
        code: generateMarkdownSnippet(scanId, scanResult.badge, baseUrl),
        preview: `![AgentShield Security Badge](${baseUrl}/badges/${scanId})`
      },
      html: {
        name: 'HTML',
        description: 'For websites, HTML documentation, and web pages',
        code: generateHTMLSnippet(scanId, scanResult.badge, baseUrl),
        preview: `<img src="${baseUrl}/badges/${scanId}" alt="AgentShield Security Badge" />`
      },
      bbcode: {
        name: 'BBCode',
        description: 'For forums and bulletin boards',
        code: `[url=${baseUrl}/report/${scanId}][img]${baseUrl}/badges/${scanId}[/img][/url]`,
        preview: `[img]${baseUrl}/badges/${scanId}[/img]`
      },
      rst: {
        name: 'reStructuredText',
        description: 'For Python documentation and Sphinx',
        code: `.. image:: ${baseUrl}/badges/${scanId}\n   :target: ${baseUrl}/report/${scanId}\n   :alt: AgentShield Security Badge`,
        preview: `.. image:: ${baseUrl}/badges/${scanId}`
      }
    };

    const requestedPlatform = embedInstructions[platform] || embedInstructions.markdown;

    res.json({
      scanId: scanId,
      platform: platform,
      instructions: requestedPlatform,
      allPlatforms: embedInstructions,
      badgeUrl: `${baseUrl}/badges/${scanId}`,
      reportUrl: `${baseUrl}/report/${scanId}`,
      styles: [
        { name: 'default', url: `${baseUrl}/badges/${scanId}` },
        { name: 'compact', url: `${baseUrl}/badges/${scanId}?style=compact` },
        { name: 'detailed', url: `${baseUrl}/badges/${scanId}?style=detailed` },
        { name: 'trust-score', url: `${baseUrl}/badges/${scanId}?style=trust-score` }
      ]
    });

  } catch (error) {
    console.error('Embed instructions error:', error);
    res.status(500).json({
      error: 'Failed to generate embed instructions',
      message: error.message
    });
  }
});

// GET /badges/preview/:threatLevel/:trustScore - Preview badge without scan
router.get('/preview/:threatLevel/:trustScore', (req, res) => {
  try {
    const { threatLevel, trustScore } = req.params;
    const { style = 'default' } = req.query;
    
    // Validate threat level
    const validThreatLevels = ['clean', 'low', 'medium', 'high', 'critical'];
    if (!validThreatLevels.includes(threatLevel)) {
      return res.status(400).json({
        error: 'Invalid threat level',
        message: 'Threat level must be one of: clean, low, medium, high, critical',
        provided: threatLevel
      });
    }

    // Validate trust score
    const score = parseInt(trustScore);
    if (isNaN(score) || score < 0 || score > 100) {
      return res.status(400).json({
        error: 'Invalid trust score',
        message: 'Trust score must be a number between 0 and 100',
        provided: trustScore
      });
    }

    // Create mock scan result for preview
    const mockScanResult = {
      threatLevel: threatLevel,
      trustScore: score,
      badge: getBadgeType(score, threatLevel),
      findings: [] // Empty for preview
    };

    // Generate badge
    const badgeSVG = generateDynamicBadge(mockScanResult, style);

    res.set('Content-Type', 'image/svg+xml');
    res.set('Cache-Control', 'max-age=86400'); // Cache for 24 hours
    res.set('X-Preview', 'true');
    
    res.send(badgeSVG);

  } catch (error) {
    console.error('Badge preview error:', error);
    
    const errorBadge = generateErrorBadge('Preview Error');
    res.set('Content-Type', 'image/svg+xml');
    res.status(500).send(errorBadge);
  }
});

// GET /badges/styles - Get available badge styles and examples
router.get('/styles', (req, res) => {
  try {
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    
    const styles = [
      {
        name: 'default',
        description: 'Standard AgentShield badge with threat level and branding',
        example: `${baseUrl}/badges/preview/high/65`,
        features: ['Threat level', 'AgentShield branding', 'Color coding']
      },
      {
        name: 'compact',
        description: 'Smaller badge with minimal text and status icon',
        example: `${baseUrl}/badges/preview/high/65?style=compact`,
        features: ['Compact size', 'Status icon', 'Color coding']
      },
      {
        name: 'detailed',
        description: 'Extended badge showing threat level and trust score percentage',
        example: `${baseUrl}/badges/preview/high/65?style=detailed`,
        features: ['Threat level', 'Trust score percentage', 'Detailed status']
      },
      {
        name: 'trust-score',
        description: 'Badge focused on displaying the numerical trust score',
        example: `${baseUrl}/badges/preview/high/65?style=trust-score`,
        features: ['Trust score out of 100', 'Color-coded rating', 'Clean design']
      }
    ];

    res.json({
      styles: styles,
      colors: {
        clean: '#4CAF50',
        low: '#8BC34A', 
        medium: '#FF9800',
        high: '#FF5722',
        critical: '#F44336'
      },
      usage: {
        endpoint: '/badges/:scanId',
        parameters: {
          style: 'Badge style (default, compact, detailed, trust-score)',
          format: 'Output format (currently only svg supported)'
        },
        examples: {
          default: `${baseUrl}/badges/{scan-id}`,
          styled: `${baseUrl}/badges/{scan-id}?style=compact`
        }
      }
    });

  } catch (error) {
    console.error('Styles endpoint error:', error);
    res.status(500).json({
      error: 'Failed to retrieve badge styles',
      message: error.message
    });
  }
});

// Helper function to determine badge type
function getBadgeType(trustScore, threatLevel) {
  if (threatLevel === 'critical' || trustScore < 40) return 'dangerous';
  if (threatLevel === 'high' || trustScore < 70) return 'caution';
  if (threatLevel === 'clean' && trustScore >= 90) return 'verified-safe';
  return 'caution';
}

// Helper function to generate error badge
function generateErrorBadge(errorMessage) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="110" height="20" role="img" aria-label="Error: ${errorMessage}">
  <title>Error: ${errorMessage}</title>
  <rect width="110" height="20" rx="3" fill="#F44336"/>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text x="550" y="140" transform="scale(.1)" fill="#fff">⚠ Error</text>
  </g>
</svg>`;
}

module.exports = router;