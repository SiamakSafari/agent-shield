// Agent Reputation API routes
const express = require('express');
const router = express.Router();
const fetch = require('node-fetch');
const { AgentShieldScanner } = require('../scanner');

const scanner = new AgentShieldScanner();

/**
 * Parse owner/repo from agent_id or url parameter
 */
function parseAgentId(agentId, url) {
  if (agentId) {
    // Direct owner/repo format
    const match = agentId.match(/^([^\/]+)\/([^\/\s?#]+)$/);
    if (match) return { owner: match[1], repo: match[2].replace(/\.git$/, '') };
    throw new Error('Invalid agent_id format. Expected: OWNER/REPO');
  }
  if (url) {
    const match = url.match(/github\.com\/([^\/]+)\/([^\/\s?#]+)/);
    if (match) return { owner: match[1], repo: match[2].replace(/\.git$/, '') };
    throw new Error('Invalid GitHub URL format');
  }
  throw new Error('Provide agent_id (OWNER/REPO) or url (GitHub URL)');
}

/**
 * Calculate age score based on repo creation date
 */
function calculateAgeScore(createdAt) {
  const ageMs = Date.now() - new Date(createdAt).getTime();
  const ageDays = ageMs / (1000 * 60 * 60 * 24);
  if (ageDays > 365) return 100;
  if (ageDays > 180) return 80;
  if (ageDays > 90) return 60;
  if (ageDays > 30) return 40;
  return 20;
}

/**
 * Calculate activity score based on last push
 */
function calculateActivityScore(pushedAt) {
  const daysSincePush = (Date.now() - new Date(pushedAt).getTime()) / (1000 * 60 * 60 * 24);
  if (daysSincePush <= 7) return 100;
  if (daysSincePush <= 30) return 80;
  if (daysSincePush <= 90) return 60;
  if (daysSincePush <= 180) return 40;
  return 20;
}

/**
 * Calculate popularity score based on stars + forks
 */
function calculatePopularityScore(stars, forks) {
  const total = (stars || 0) + (forks || 0);
  if (total > 1000) return 100;
  if (total > 100) return 80;
  if (total > 10) return 60;
  if (total > 0) return 40;
  return 20;
}

/**
 * Calculate documentation score
 */
function calculateDocScore(repoData, files) {
  let score = 0;
  // Has README (check via GitHub API - size > 0 or has_readme isn't direct, but description + has_pages etc.)
  if (files.hasReadme) score += 40;
  if (files.hasSkillMd) score += 30;
  if (repoData.description) score += 15;
  if (repoData.license) score += 15;
  return Math.min(score, 100);
}

/**
 * Get rating from score
 */
function getRating(score) {
  if (score >= 80) return 'high-trust';
  if (score >= 60) return 'moderate-trust';
  if (score >= 40) return 'low-trust';
  return 'untrusted';
}

/**
 * Fetch GitHub repo metadata
 */
async function fetchGitHubMeta(owner, repo) {
  const headers = { 'User-Agent': 'AgentShield/1.0' };
  const ghToken = process.env.GITHUB_TOKEN;
  if (ghToken) headers['Authorization'] = `token ${ghToken}`;

  const repoResp = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
  if (!repoResp.ok) {
    if (repoResp.status === 404) throw new Error(`Repository ${owner}/${repo} not found`);
    if (repoResp.status === 403) throw new Error('GitHub API rate limit exceeded. Try again later.');
    throw new Error(`GitHub API error: ${repoResp.status}`);
  }
  const repoData = await repoResp.json();

  // Check for specific files
  const branch = repoData.default_branch || 'main';
  const checkFile = async (path) => {
    try {
      const r = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`, { headers: { 'User-Agent': 'AgentShield/1.0' } });
      return r.ok;
    } catch { return false; }
  };

  const [hasReadme, hasSkillMd] = await Promise.all([
    checkFile('README.md'),
    checkFile('SKILL.md'),
  ]);

  return { repoData, files: { hasReadme, hasSkillMd } };
}

// GET /api/reputation
router.get('/', async (req, res) => {
  const startTime = Date.now();

  try {
    const { agent_id, url } = req.query;
    const { owner, repo } = parseAgentId(agent_id, url);
    const agentId = `${owner}/${repo}`;

    // Check cache (24h)
    if (req.db) {
      const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const cached = await req.db.get(
        'SELECT * FROM reputation_cache WHERE agent_id = ? AND updated_at > ?',
        [agentId, cutoff]
      );
      if (cached) {
        return res.json(JSON.parse(cached.result_json));
      }
    }

    // 1. Fetch GitHub metadata
    const { repoData, files } = await fetchGitHubMeta(owner, repo);

    // 2. Run security scan
    let securityScore = 50; // default if scan fails
    let flags = [];
    try {
      const scanResult = await scanner.scanContent({ github: `https://github.com/${owner}/${repo}` });
      if (!scanResult.error) {
        securityScore = scanResult.trustScore || 50;
        // Extract flags from critical/high findings
        if (scanResult.findings) {
          flags = scanResult.findings
            .filter(f => f.severity === 'critical' || f.severity === 'high')
            .slice(0, 5)
            .map(f => f.title);
        }
      }
    } catch (e) {
      console.error('Security scan failed for reputation:', e.message);
    }

    // 3. Calculate all signals
    const ageScore = calculateAgeScore(repoData.created_at);
    const activityScore = calculateActivityScore(repoData.pushed_at);
    const popularityScore = calculatePopularityScore(repoData.stargazers_count, repoData.forks_count);
    const docScore = calculateDocScore(repoData, files);

    // 4. Weighted reputation score
    const reputationScore = Math.round(
      securityScore * 0.5 +
      ageScore * 0.15 +
      activityScore * 0.15 +
      popularityScore * 0.1 +
      docScore * 0.1
    );

    const rating = getRating(reputationScore);
    const now = new Date().toISOString();

    const result = {
      agentId,
      reputationScore,
      rating,
      signals: {
        security: { score: securityScore, weight: 0.5, source: 'AgentShield scan' },
        age: { score: ageScore, weight: 0.15, source: 'GitHub repo age' },
        activity: { score: activityScore, weight: 0.15, source: 'Recent commits/updates' },
        popularity: { score: popularityScore, weight: 0.1, source: 'GitHub stars/forks' },
        documentation: { score: docScore, weight: 0.1, source: 'README/SKILL.md quality' },
      },
      flags,
      recommendation: rating,
      metadata: {
        stars: repoData.stargazers_count,
        forks: repoData.forks_count,
        createdAt: repoData.created_at,
        lastPush: repoData.pushed_at,
        language: repoData.language,
        scanDurationMs: Date.now() - startTime,
      },
      lastUpdated: now,
    };

    // 5. Cache result
    if (req.db) {
      await req.db.run(
        `INSERT INTO reputation_cache (agent_id, result_json, updated_at)
         VALUES (?, ?, ?)
         ON CONFLICT(agent_id) DO UPDATE SET result_json = excluded.result_json, updated_at = excluded.updated_at`,
        [agentId, JSON.stringify(result), now]
      );
    }

    res.json(result);
  } catch (error) {
    console.error('Reputation API error:', error.message);
    const status = error.message.includes('not found') ? 404 :
                   error.message.includes('rate limit') ? 429 :
                   error.message.includes('Invalid') || error.message.includes('Provide') ? 400 : 500;
    res.status(status).json({
      error: error.message,
      timestamp: new Date().toISOString(),
    });
  }
});

module.exports = router;
