// Shield Score API routes — aggregate security scoring for agent skill stacks
const express = require('express');
const router = express.Router();
const { AgentShieldScanner } = require('../scanner');

const scanner = new AgentShieldScanner();

// ── Helpers ──────────────────────────────────────────────────────────────────

function getBadgeLevel(score) {
  if (score >= 80) return 'Verified Secure';
  if (score >= 60) return 'Trusted';
  if (score >= 40) return 'Needs Review';
  return 'At Risk';
}

function getBadgeColor(score) {
  if (score >= 80) return '#22c55e'; // green
  if (score >= 60) return '#3b82f6'; // blue
  if (score >= 40) return '#f97316'; // orange
  return '#ef4444';                  // red
}

function getBadgeColorName(score) {
  if (score >= 80) return 'green';
  if (score >= 60) return 'blue';
  if (score >= 40) return 'orange';
  return 'red';
}

// ── GET /api/shield-score ────────────────────────────────────────────────────
// Public for basic score. Auth adds detailed findings.
router.get('/', async (req, res) => {
  try {
    // Accept skills from query string or JSON body (express.json parsed upstream)
    let skills = [];
    if (req.query.skills) {
      skills = req.query.skills.split(',').map(s => s.trim()).filter(Boolean);
    } else if (req.body && Array.isArray(req.body.skills)) {
      skills = req.body.skills.map(s => s.trim()).filter(Boolean);
    }

    if (skills.length === 0) {
      return res.status(400).json({
        error: 'No skills provided',
        message: 'Pass skill URLs via ?skills=url1,url2 or JSON body {"skills":["url1","url2"]}',
        example: '/api/shield-score?skills=https://example.com/SKILL.md'
      });
    }

    if (skills.length > 25) {
      return res.status(400).json({
        error: 'Too many skills',
        message: 'Maximum 25 skills per request',
        provided: skills.length
      });
    }

    // Scan each skill
    const results = [];
    for (const url of skills) {
      try {
        const result = await scanner.scanContent({ url });
        results.push({
          url,
          score: result.error ? 0 : (result.trustScore ?? 0),
          threatLevel: result.error ? 'error' : result.threatLevel,
          badge: result.error ? 'error' : result.badge,
          error: result.error ? result.message : null,
          findingsCount: result.error ? 0 : (result.findings?.length ?? 0),
          // Only include detailed findings for authenticated users
          ...(req.user?.isAuthenticated ? { findings: result.findings || [] } : {})
        });

        // Save scan to DB
        if (req.db && !result.error) {
          await req.db.saveScan(result, {
            userId: req.user?.id || 'anonymous',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent')
          });
        }
      } catch (err) {
        results.push({
          url,
          score: 0,
          threatLevel: 'error',
          badge: 'error',
          error: err.message,
          findingsCount: 0
        });
      }
    }

    // Calculate aggregate score (only from successful scans)
    const validResults = results.filter(r => r.threatLevel !== 'error');
    const aggregateScore = validResults.length > 0
      ? Math.round(validResults.reduce((sum, r) => sum + r.score, 0) / validResults.length)
      : 0;

    const badgeLevel = getBadgeLevel(aggregateScore);
    const baseUrl = `${req.protocol}://${req.get('host')}`;

    // Store in shield_scores if we have a DB
    if (req.db) {
      const agentId = req.user?.id || `anon_${req.ip}`;
      const apiKey = req.user?.keyId || null;
      try {
        await req.db.run(
          `INSERT INTO shield_scores (agent_id, api_key, score, badge_level, skills_scanned, skill_urls, last_updated)
           VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
           ON CONFLICT(agent_id) DO UPDATE SET
             score = excluded.score,
             badge_level = excluded.badge_level,
             skills_scanned = excluded.skills_scanned,
             skill_urls = excluded.skill_urls,
             last_updated = excluded.last_updated`,
          [agentId, apiKey, aggregateScore, badgeLevel, skills.length, JSON.stringify(skills)]
        );
      } catch (dbErr) {
        console.error('Shield score DB save error:', dbErr.message);
      }
    }

    res.json({
      shieldScore: aggregateScore,
      badgeLevel,
      badgeColor: getBadgeColorName(aggregateScore),
      badgeUrl: `${baseUrl}/api/shield-score/badge/${aggregateScore}`,
      skillsScanned: skills.length,
      skillsSuccessful: validResults.length,
      skillsFailed: results.length - validResults.length,
      skills: results,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Shield score error:', error);
    res.status(500).json({
      error: 'Shield score calculation failed',
      message: error.message
    });
  }
});

// Also support POST for JSON body
router.post('/', async (req, res) => {
  // Forward to the GET handler (it already reads req.body)
  req.query.skills = req.query.skills || '';
  // Merge body skills into query if not already there
  if (!req.query.skills && req.body?.skills) {
    req.query.skills = Array.isArray(req.body.skills) ? req.body.skills.join(',') : req.body.skills;
  }
  return router.handle(req, res, () => {});
});

// ── GET /api/shield-score/badge/:score ───────────────────────────────────────
// Returns a dynamic SVG badge
router.get('/badge/:score', (req, res) => {
  const scoreValue = parseInt(req.params.score, 10);
  const score = Math.max(0, Math.min(100, isNaN(scoreValue) ? 0 : scoreValue));
  const badgeLevel = getBadgeLevel(score);
  const color = getBadgeColor(score);
  const darkColor = adjustColor(color, -30);

  const labelText = 'Shield Score';
  const valueText = `${score} · ${badgeLevel}`;
  const labelWidth = 90;
  const valueWidth = Math.max(120, valueText.length * 7.2 + 20);
  const totalWidth = labelWidth + valueWidth;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="28" role="img" aria-label="${labelText}: ${valueText}">
  <title>${labelText}: ${valueText}</title>
  <defs>
    <linearGradient id="s" x2="0" y2="100%">
      <stop offset="0" stop-color="#fff" stop-opacity=".15"/>
      <stop offset="1" stop-opacity=".15"/>
    </linearGradient>
    <clipPath id="r">
      <rect width="${totalWidth}" height="28" rx="6" fill="#fff"/>
    </clipPath>
  </defs>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="28" fill="#2d333b"/>
    <rect x="${labelWidth}" width="${valueWidth}" height="28" fill="${color}"/>
    <rect width="${totalWidth}" height="28" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="'Inter','Segoe UI','Helvetica Neue',Helvetica,Arial,sans-serif" text-rendering="geometricPrecision">
    <text x="${labelWidth / 2}" y="18.5" font-size="11" font-weight="600" fill="#e6edf3">🛡️ ${labelText}</text>
    <text x="${labelWidth + valueWidth / 2}" y="18.5" font-size="11.5" font-weight="700">${score} · ${badgeLevel}</text>
  </g>
</svg>`;

  res.set('Content-Type', 'image/svg+xml');
  res.set('Cache-Control', 'public, max-age=300'); // 5 min cache
  res.set('X-Shield-Score', String(score));
  res.set('X-Badge-Level', badgeLevel);
  res.send(svg);
});

// ── GET /api/shield-score/leaderboard ────────────────────────────────────────
// Top 100 agents by Shield Score (auth required)
router.get('/leaderboard', async (req, res) => {
  try {
    if (!req.user?.isAuthenticated) {
      return res.status(401).json({
        error: 'Authentication required',
        message: 'Provide an API key via X-API-Key header to access the leaderboard'
      });
    }

    if (!req.db) {
      return res.status(503).json({ error: 'Database unavailable' });
    }

    const rows = await req.db.all(
      `SELECT agent_id, score, badge_level, skills_scanned, last_updated
       FROM shield_scores
       ORDER BY score DESC, last_updated DESC
       LIMIT 100`
    );

    const leaderboard = rows.map((row, idx) => ({
      rank: idx + 1,
      agentId: row.agent_id,
      score: row.score,
      badgeLevel: row.badge_level,
      skillsScanned: row.skills_scanned,
      lastUpdated: row.last_updated
    }));

    res.json({
      leaderboard,
      total: leaderboard.length,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({
      error: 'Failed to retrieve leaderboard',
      message: error.message
    });
  }
});

// Darken a hex color
function adjustColor(hex, amount) {
  const num = parseInt(hex.replace('#', ''), 16);
  const r = Math.max(0, Math.min(255, (num >> 16) + amount));
  const g = Math.max(0, Math.min(255, ((num >> 8) & 0x00FF) + amount));
  const b = Math.max(0, Math.min(255, (num & 0x0000FF) + amount));
  return `#${(1 << 24 | r << 16 | g << 8 | b).toString(16).slice(1)}`;
}

module.exports = router;
