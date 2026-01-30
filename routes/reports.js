// Reports API routes
const express = require('express');
const router = express.Router();
const { generateMarkdownReport } = require('../scanner/reporter');

// GET /report/:scanId - Retrieve specific scan report
router.get('/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;
    const { format = 'json' } = req.query;
    
    // Validate scan ID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(scanId)) {
      return res.status(400).json({
        error: 'Invalid scan ID',
        message: 'Scan ID must be a valid UUID'
      });
    }

    // Retrieve from database
    const report = req.db?.getScan(scanId);
    
    if (!report) {
      return res.status(404).json({
        error: 'Scan not found',
        message: 'No scan found with the provided ID',
        scanId: scanId
      });
    }

    // Format response based on requested format
    switch (format.toLowerCase()) {
      case 'markdown':
      case 'md':
        res.set('Content-Type', 'text/markdown');
        res.send(generateMarkdownReport(report));
        break;
        
      case 'html':
        res.set('Content-Type', 'text/html');
        res.send(generateHTMLReport(report));
        break;
        
      case 'summary':
        res.json(generateSummaryReport(report));
        break;
        
      case 'json':
      default:
        res.json(report);
        break;
    }

  } catch (error) {
    console.error('Report retrieval error:', error);
    res.status(500).json({
      error: 'Failed to retrieve report',
      message: error.message
    });
  }
});

// GET /reports/user/:userId - Get user's scan history  
router.get('/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const { limit = 50, offset = 0, threatLevel, dateFrom, dateTo } = req.query;
    
    // Authorization check - users can only see their own reports unless admin
    if (req.user?.id !== userId && req.user?.plan !== 'enterprise') {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You can only access your own scan reports'
      });
    }

    const reports = req.db?.getUserScans(userId, parseInt(limit));
    
    if (!reports) {
      return res.json({
        scans: [],
        pagination: {
          total: 0,
          limit: parseInt(limit),
          offset: parseInt(offset)
        }
      });
    }

    // Apply filters
    let filteredReports = reports;
    
    if (threatLevel) {
      filteredReports = filteredReports.filter(r => r.threat_level === threatLevel);
    }
    
    if (dateFrom) {
      const fromDate = new Date(dateFrom).toISOString();
      filteredReports = filteredReports.filter(r => r.timestamp >= fromDate);
    }
    
    if (dateTo) {
      const toDate = new Date(dateTo).toISOString();
      filteredReports = filteredReports.filter(r => r.timestamp <= toDate);
    }

    // Apply pagination
    const paginatedReports = filteredReports.slice(
      parseInt(offset), 
      parseInt(offset) + parseInt(limit)
    );

    res.json({
      scans: paginatedReports,
      pagination: {
        total: filteredReports.length,
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: parseInt(offset) + parseInt(limit) < filteredReports.length
      },
      filters: {
        threatLevel,
        dateFrom,
        dateTo
      }
    });

  } catch (error) {
    console.error('User reports error:', error);
    res.status(500).json({
      error: 'Failed to retrieve user reports',
      message: error.message
    });
  }
});

// GET /reports/analytics - Analytics and reporting dashboard data
router.get('/analytics', async (req, res) => {
  try {
    // Require pro plan or higher for analytics
    if (!req.user?.isAuthenticated || !['pro', 'enterprise'].includes(req.user.plan)) {
      return res.status(403).json({
        error: 'Feature not available',
        message: 'Analytics require Pro plan or higher',
        currentPlan: req.user?.plan || 'none'
      });
    }

    const { days = 30, groupBy = 'day' } = req.query;
    const userId = req.user.id;

    // Get user analytics
    const analytics = req.analytics?.getUserStats(userId, parseInt(days)) || {};
    
    // Get scan statistics
    const scanStats = req.db?.getStats() || {};
    
    // Calculate trends
    const trends = calculateTrends(analytics.dailyUsage || []);

    res.json({
      summary: {
        totalScans: analytics.summary?.total_requests || 0,
        successRate: analytics.summary ? 
          (analytics.summary.successful_requests / analytics.summary.total_requests * 100).toFixed(2) : 0,
        avgResponseTime: analytics.summary?.avg_response_time || 0,
        activeDays: analytics.summary?.active_days || 0
      },
      trends: trends,
      dailyUsage: analytics.dailyUsage || [],
      topEndpoints: analytics.topEndpoints || [],
      systemStats: scanStats,
      period: {
        days: parseInt(days),
        groupBy: groupBy,
        from: new Date(Date.now() - parseInt(days) * 24 * 60 * 60 * 1000).toISOString(),
        to: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Analytics error:', error);
    res.status(500).json({
      error: 'Failed to generate analytics',
      message: error.message
    });
  }
});

// GET /reports/export - Export scan reports in various formats
router.get('/export', async (req, res) => {
  try {
    const { format = 'csv', userId, dateFrom, dateTo, threatLevel } = req.query;
    
    // Authorization check
    if (req.user?.id !== userId && req.user?.plan !== 'enterprise') {
      return res.status(403).json({
        error: 'Access denied',
        message: 'You can only export your own scan reports'
      });
    }

    const reports = req.db?.getUserScans(userId || req.user?.id, 1000); // Max 1000 for export
    
    if (!reports || reports.length === 0) {
      return res.status(404).json({
        error: 'No data to export',
        message: 'No scan reports found for export'
      });
    }

    // Apply filters
    let filteredReports = reports;
    
    if (threatLevel) {
      filteredReports = filteredReports.filter(r => r.threat_level === threatLevel);
    }
    
    if (dateFrom) {
      const fromDate = new Date(dateFrom).toISOString();
      filteredReports = filteredReports.filter(r => r.timestamp >= fromDate);
    }
    
    if (dateTo) {
      const toDate = new Date(dateTo).toISOString();
      filteredReports = filteredReports.filter(r => r.timestamp <= toDate);
    }

    // Generate export based on format
    switch (format.toLowerCase()) {
      case 'csv':
        const csv = generateCSVExport(filteredReports);
        res.set('Content-Type', 'text/csv');
        res.set('Content-Disposition', `attachment; filename="agentshield-reports-${new Date().toISOString().split('T')[0]}.csv"`);
        res.send(csv);
        break;
        
      case 'json':
        res.set('Content-Type', 'application/json');
        res.set('Content-Disposition', `attachment; filename="agentshield-reports-${new Date().toISOString().split('T')[0]}.json"`);
        res.json(filteredReports);
        break;
        
      default:
        res.status(400).json({
          error: 'Unsupported format',
          message: 'Supported formats: csv, json',
          requested: format
        });
    }

  } catch (error) {
    console.error('Export error:', error);
    res.status(500).json({
      error: 'Export failed',
      message: error.message
    });
  }
});

// Helper function to generate summary report
function generateSummaryReport(report) {
  return {
    scanId: report.scanId,
    timestamp: report.timestamp,
    source: report.source,
    threatLevel: report.threatLevel,
    trustScore: report.trustScore,
    badge: report.badge,
    summary: report.summary,
    findingsCount: {
      total: report.findings.length,
      critical: report.findings.filter(f => f.severity === 'critical').length,
      high: report.findings.filter(f => f.severity === 'high').length,
      medium: report.findings.filter(f => f.severity === 'medium').length,
      low: report.findings.filter(f => f.severity === 'low').length
    },
    permissions: report.permissions,
    scanDuration: report.metadata?.scanDurationMs
  };
}

// Helper function to generate HTML report
function generateHTMLReport(report) {
  const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AgentShield Security Report - ${report.scanId}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; line-height: 1.6; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { border-bottom: 2px solid #eee; padding-bottom: 20px; margin-bottom: 30px; }
        .threat-level { padding: 8px 16px; border-radius: 6px; font-weight: bold; color: white; display: inline-block; }
        .critical { background: #dc3545; }
        .high { background: #fd7e14; }
        .medium { background: #ffc107; color: #000; }
        .low { background: #28a745; }
        .clean { background: #20c997; }
        .finding { margin: 20px 0; padding: 20px; border-left: 4px solid #ddd; background: #f8f9fa; }
        .finding.critical { border-left-color: #dc3545; }
        .finding.high { border-left-color: #fd7e14; }
        .finding.medium { border-left-color: #ffc107; }
        .finding.low { border-left-color: #28a745; }
        .code { background: #f1f3f4; padding: 2px 6px; border-radius: 3px; font-family: 'Monaco', 'Courier New', monospace; }
        .metadata { background: #f8f9fa; padding: 20px; border-radius: 6px; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AgentShield Security Report</h1>
            <p><strong>Scan ID:</strong> ${report.scanId}</p>
            <p><strong>Timestamp:</strong> ${new Date(report.timestamp).toLocaleString()}</p>
            <p><strong>Source:</strong> ${report.source}</p>
            <p><strong>Threat Level:</strong> <span class="threat-level ${report.threatLevel}">${report.threatLevel.toUpperCase()}</span></p>
            <p><strong>Trust Score:</strong> ${report.trustScore}/100</p>
        </div>

        <h2>Summary</h2>
        <p>${report.summary}</p>

        ${report.findings.length > 0 ? `
        <h2>Security Findings</h2>
        ${report.findings.map((finding, index) => `
            <div class="finding ${finding.severity}">
                <h3>${index + 1}. ${finding.title}</h3>
                <p><strong>Severity:</strong> ${finding.severity.toUpperCase()}</p>
                <p><strong>Category:</strong> ${finding.category}</p>
                <p>${finding.description}</p>
                ${finding.line > 0 ? `<p><strong>Line:</strong> ${finding.line}</p>` : ''}
                <p><strong>Evidence:</strong> <code class="code">${finding.evidence}</code></p>
                <p><strong>Remediation:</strong> ${finding.remediation}</p>
            </div>
        `).join('')}
        ` : '<p>No security issues found.</p>'}

        <div class="metadata">
            <h3>Scan Metadata</h3>
            <p><strong>Lines Scanned:</strong> ${report.metadata?.linesScanned || 'N/A'}</p>
            <p><strong>Patterns Checked:</strong> ${report.metadata?.patternsChecked || 'N/A'}</p>
            <p><strong>Scan Duration:</strong> ${report.metadata?.scanDurationMs || 'N/A'}ms</p>
            <p><strong>Scanner Version:</strong> ${report.metadata?.version || '1.0.0'}</p>
        </div>
    </div>
</body>
</html>`;

  return htmlTemplate;
}

// Helper function to generate CSV export
function generateCSVExport(reports) {
  const headers = [
    'Scan ID',
    'Timestamp',
    'Source',
    'Threat Level',
    'Trust Score',
    'Badge',
    'Findings Count',
    'Critical Count',
    'High Count',
    'Medium Count',
    'Low Count'
  ];

  const rows = reports.map(report => [
    report.id,
    report.timestamp,
    report.source,
    report.threat_level,
    report.trust_score,
    report.badge,
    report.findings_count,
    report.critical_count,
    report.high_count,
    report.medium_count,
    report.low_count
  ]);

  const csvContent = [headers, ...rows]
    .map(row => row.map(cell => `"${cell}"`).join(','))
    .join('\n');

  return csvContent;
}

// Helper function to calculate trends
function calculateTrends(dailyUsage) {
  if (!dailyUsage || dailyUsage.length < 2) {
    return { trend: 'neutral', change: 0 };
  }

  const recent = dailyUsage.slice(0, 7); // Last 7 days
  const previous = dailyUsage.slice(7, 14); // Previous 7 days

  const recentAvg = recent.reduce((sum, day) => sum + day.requests, 0) / recent.length;
  const previousAvg = previous.reduce((sum, day) => sum + day.requests, 0) / previous.length;

  if (previousAvg === 0) {
    return { trend: 'neutral', change: 0 };
  }

  const change = ((recentAvg - previousAvg) / previousAvg) * 100;
  
  return {
    trend: change > 10 ? 'up' : change < -10 ? 'down' : 'neutral',
    change: Math.round(change * 10) / 10
  };
}

module.exports = router;