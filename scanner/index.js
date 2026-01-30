// Main scanner orchestrator - coordinates all analysis modules
const { v4: uuidv4 } = require('uuid');
const fetch = require('node-fetch');
const { 
  analyzeCode, 
  analyzeStructure, 
  analyzeDependencies,
  calculateThreatLevel,
  calculateTrustScore,
  getBadgeType 
} = require('./patterns');
const { analyzeSkillStructure } = require('./analyzer');
const { generateReport } = require('./reporter');

class AgentShieldScanner {
  constructor() {
    this.scanStats = {
      totalScans: 0,
      threatsDetected: 0,
      cleanSkills: 0
    };
  }

  async scanContent(input) {
    const startTime = Date.now();
    const scanId = uuidv4();
    
    try {
      // Parse input - could be raw content, URL, or GitHub repo
      const { content, source, metadata } = await this.parseInput(input);
      
      // Core analysis
      const codeAnalysis = analyzeCode(content);
      const structureAnalysis = analyzeStructure(content);
      const dependencyAnalysis = metadata.packageJson ? 
        analyzeDependencies(metadata.packageJson) : [];
      const skillAnalysis = analyzeSkillStructure(content);

      // Combine all findings
      const allFindings = [
        ...codeAnalysis.findings,
        ...structureAnalysis.map(s => ({
          severity: s.severity,
          category: 'skill-structure',
          title: `SKILL.md structure issue: ${s.type}`,
          description: `Potential security issue in skill structure`,
          evidence: s.evidence,
          line: s.line,
          remediation: 'Review and fix skill structure according to security best practices'
        })),
        ...dependencyAnalysis.map(d => ({
          severity: d.severity,
          category: 'dependency-vulnerability',
          title: `Vulnerable dependency: ${d.dependency}`,
          description: d.issue,
          evidence: d.dependency,
          line: 0,
          remediation: d.remediation
        })),
        ...skillAnalysis.issues.map(i => ({
          severity: i.severity,
          category: 'skill-analysis',
          title: i.title,
          description: i.description,
          evidence: i.evidence,
          line: i.line || 0,
          remediation: i.remediation
        }))
      ];

      // Calculate final scores
      const threatLevel = calculateThreatLevel(allFindings);
      const trustScore = calculateTrustScore(allFindings);
      const badge = getBadgeType(trustScore, threatLevel);

      // Generate comprehensive report
      const report = generateReport({
        scanId,
        source,
        content,
        findings: allFindings,
        permissions: codeAnalysis.permissions,
        threatLevel,
        trustScore,
        badge,
        metadata: {
          linesScanned: content.split('\n').length,
          patternsChecked: this.getTotalPatterns(),
          scanDurationMs: Date.now() - startTime,
          skillStructure: skillAnalysis.structure
        }
      });

      // Update stats
      this.updateStats(threatLevel);

      return report;

    } catch (error) {
      return {
        scanId,
        error: true,
        message: error.message,
        timestamp: new Date().toISOString(),
        source: input.url || input.source || 'inline'
      };
    }
  }

  async parseInput(input) {
    if (typeof input === 'string') {
      // Raw content provided
      return {
        content: input,
        source: 'inline',
        metadata: {}
      };
    }

    if (input.url) {
      return await this.fetchFromUrl(input.url);
    }

    if (input.github) {
      return await this.fetchFromGitHub(input.github);
    }

    if (input.content) {
      return {
        content: input.content,
        source: input.source || 'inline',
        metadata: input.metadata || {}
      };
    }

    throw new Error('Invalid input format. Provide content, URL, or GitHub repository.');
  }

  async fetchFromUrl(url) {
    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const content = await response.text();
      
      return {
        content,
        source: url,
        metadata: {
          contentType: response.headers.get('content-type'),
          contentLength: response.headers.get('content-length')
        }
      };
    } catch (error) {
      throw new Error(`Failed to fetch from URL: ${error.message}`);
    }
  }

  async fetchFromGitHub(repoUrl) {
    try {
      // Parse GitHub URL
      const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/);
      if (!match) {
        throw new Error('Invalid GitHub URL format');
      }

      const [, owner, repo] = match;
      const cleanRepo = repo.replace('.git', '');

      // Fetch SKILL.md and package.json from GitHub API
      const skillUrl = `https://api.github.com/repos/${owner}/${cleanRepo}/contents/SKILL.md`;
      const packageUrl = `https://api.github.com/repos/${owner}/${cleanRepo}/contents/package.json`;

      const skillResponse = await fetch(skillUrl);
      let skillContent = '';
      let packageContent = '';

      if (skillResponse.ok) {
        const skillData = await skillResponse.json();
        skillContent = Buffer.from(skillData.content, 'base64').toString('utf8');
      }

      try {
        const packageResponse = await fetch(packageUrl);
        if (packageResponse.ok) {
          const packageData = await packageResponse.json();
          packageContent = Buffer.from(packageData.content, 'base64').toString('utf8');
        }
      } catch (e) {
        // package.json is optional
      }

      return {
        content: skillContent,
        source: repoUrl,
        metadata: {
          packageJson: packageContent,
          repository: `${owner}/${cleanRepo}`
        }
      };

    } catch (error) {
      throw new Error(`Failed to fetch from GitHub: ${error.message}`);
    }
  }

  async batchScan(inputs) {
    const results = [];
    
    for (const input of inputs) {
      try {
        const result = await this.scanContent(input);
        results.push(result);
      } catch (error) {
        results.push({
          error: true,
          message: error.message,
          input
        });
      }
    }

    return {
      scanId: uuidv4(),
      timestamp: new Date().toISOString(),
      results,
      summary: {
        total: inputs.length,
        successful: results.filter(r => !r.error).length,
        failed: results.filter(r => r.error).length,
        critical: results.filter(r => !r.error && r.threatLevel === 'critical').length,
        high: results.filter(r => !r.error && r.threatLevel === 'high').length,
        medium: results.filter(r => !r.error && r.threatLevel === 'medium').length,
        low: results.filter(r => !r.error && r.threatLevel === 'low').length,
        clean: results.filter(r => !r.error && r.threatLevel === 'clean').length
      }
    };
  }

  getTotalPatterns() {
    const patterns = require('./patterns');
    return Object.values(patterns.SECURITY_PATTERNS)
      .reduce((total, group) => total + group.length, 0);
  }

  updateStats(threatLevel) {
    this.scanStats.totalScans++;
    
    if (threatLevel !== 'clean') {
      this.scanStats.threatsDetected++;
    } else {
      this.scanStats.cleanSkills++;
    }
  }

  getStats() {
    return {
      ...this.scanStats,
      cleanPercentage: this.scanStats.totalScans > 0 ? 
        Math.round((this.scanStats.cleanSkills / this.scanStats.totalScans) * 100) : 0,
      threatPercentage: this.scanStats.totalScans > 0 ? 
        Math.round((this.scanStats.threatsDetected / this.scanStats.totalScans) * 100) : 0
    };
  }

  // Health check method
  healthCheck() {
    return {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      scanner: {
        patterns: this.getTotalPatterns(),
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage()
      },
      stats: this.getStats()
    };
  }
}

module.exports = { AgentShieldScanner };