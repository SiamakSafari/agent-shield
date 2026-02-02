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
const { Deobfuscator } = require('./deobfuscator');

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
      
      // Deobfuscation pass — run BEFORE pattern matching
      const deobfuscator = new Deobfuscator();
      const deobResult = deobfuscator.deobfuscate(content);

      // Core analysis on ORIGINAL content
      const codeAnalysis = analyzeCode(content);
      const structureAnalysis = analyzeStructure(content);
      const dependencyAnalysis = metadata.packageJson ? 
        analyzeDependencies(metadata.packageJson) : [];
      const skillAnalysis = analyzeSkillStructure(content);

      // If obfuscation was detected, also scan the deobfuscated version
      let deobfuscatedFindings = [];
      if (deobResult.obfuscationDetected && deobResult.deobfuscated !== content) {
        const deobCodeAnalysis = analyzeCode(deobResult.deobfuscated);
        const deobStructureAnalysis = analyzeStructure(deobResult.deobfuscated);

        // Collect findings from deobfuscated code that weren't found in original
        // Deduplicate by patternId + evidence to avoid noise
        const originalIds = new Set(codeAnalysis.findings.map(f => `${f.patternId}:${f.evidence}`));
        deobfuscatedFindings = deobCodeAnalysis.findings
          .filter(f => !originalIds.has(`${f.patternId}:${f.evidence}`))
          // Skip low-severity noise from deobfuscation artifacts (comments, etc)
          .filter(f => f.severity !== 'low')
          .map(f => ({
            ...f,
            title: `[DEOBFUSCATED] ${f.title}`,
            description: `Found after deobfuscation: ${f.description}`
          }));

        // Merge permissions
        Object.keys(deobCodeAnalysis.permissions).forEach(key => {
          if (deobCodeAnalysis.permissions[key]) {
            codeAnalysis.permissions[key] = true;
          }
        });

        // Also add structure findings from deobfuscated
        const origStructIds = new Set(structureAnalysis.map(s => `${s.type}:${s.line}`));
        deobStructureAnalysis
          .filter(s => !origStructIds.has(`${s.type}:${s.line}`))
          .forEach(s => structureAnalysis.push({ ...s, type: `deobfuscated-${s.type}` }));
      }

      // Add obfuscation meta-finding if detected
      const obfuscationFindings = [];
      if (deobResult.obfuscationDetected) {
        obfuscationFindings.push({
          severity: 'high',
          category: 'obfuscation',
          title: 'Code obfuscation detected',
          description: `Obfuscation techniques found: ${deobResult.obfuscationTypes.join(', ')}. ` +
            `${deobResult.transformations.length} transformation(s) applied to reveal hidden code.`,
          evidence: deobResult.transformations.slice(0, 3).join('; '),
          line: 0,
          remediation: 'Use readable, transparent code. Obfuscation in AI agent skills is inherently suspicious.',
          patternId: 'obfuscation-meta'
        });
      }

      // Combine all findings
      let allFindings = [
        ...codeAnalysis.findings,
        ...deobfuscatedFindings,
        ...obfuscationFindings,
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

      // For GitHub repos: filter out false positives from legitimate code patterns
      // The scanner patterns were designed for SKILL.md files, not general source code.
      // Normal code legitimately uses exec, ../, readFile, etc.
      if (metadata.isGitHubRepo) {
        // Pattern IDs that are normal in source code and produce false positives
        const CODE_NOISE_PATTERNS = new Set([
          'directory-traversal',       // ../ is normal in imports
          'no-input-validation',       // req.body etc. is normal
          'missing-error-handling',    // not all code needs inline try/catch
          'deprecated-functions',      // readFileSync etc. are fine
          'broad-permissions',         // readdir, find, etc. are normal
          'hardcoded-credentials',     // example configs, test fixtures
          'timing-evasion',           // setTimeout/delay is normal
          'logging-disabling',        // 2>&1, quiet flags are normal
          'dynamic-url-construction', // building URLs is normal in code
          'mount-host-filesystem',    // /dev references in docs/configs
          'proc-sys-access',          // /proc, /sys refs in docs
        ]);

        // Categories that produce excessive noise in real code
        const CODE_NOISE_CATEGORIES = new Set([
          'best-practice-violation',
          'skill-structure',          // code files aren't SKILL.md
        ]);

        // For skill-analysis findings, filter out common false positives
        const SKILL_ANALYSIS_NOISE = new Set([
          'Dangerous permission request',  // words like "exec", "shell" in code
          'Missing required section: title',
          'Missing required section: description',
          'Missing required section: usage',
          'Missing required section: permissions',
        ]);

        allFindings = allFindings.filter(f => {
          // Always keep critical findings — those are genuinely concerning
          if (f.severity === 'critical') return true;

          // Filter out known noisy pattern IDs
          if (f.patternId && CODE_NOISE_PATTERNS.has(f.patternId)) return false;

          // Filter out noisy categories entirely  
          if (CODE_NOISE_CATEGORIES.has(f.category)) return false;

          // Filter skill-analysis noise (e.g., "Dangerous permission request" for word "exec")
          if (f.category === 'skill-analysis' && SKILL_ANALYSIS_NOISE.has(f.title)) return false;

          // Keep high-severity findings
          if (f.severity === 'high') return true;

          // For medium findings, only keep obfuscation-related ones
          if (f.severity === 'medium') {
            return f.category === 'obfuscation';
          }

          // Drop low-severity findings for repo scans
          return false;
        });
      }

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
          skillStructure: skillAnalysis.structure,
          deobfuscation: {
            obfuscationDetected: deobResult.obfuscationDetected,
            obfuscationTypes: deobResult.obfuscationTypes,
            transformationsApplied: deobResult.transformations.length,
            additionalFindingsFromDeobfuscation: deobfuscatedFindings.length
          }
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
      // Detect GitHub repository URLs and redirect to proper GitHub handling
      const githubMatch = url.match(/^https?:\/\/github\.com\/([^\/]+)\/([^\/\s?#]+)/);
      if (githubMatch) {
        return await this.fetchFromGitHub(url);
      }

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
      const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/\s?#]+)/);
      if (!match) {
        throw new Error('Invalid GitHub URL format');
      }

      const [, owner, repo] = match;
      const cleanRepo = repo.replace(/\.git$/, '');

      // Skill definition files — scanned with full pattern set
      const DEFINITION_FILES = [
        'SKILL.md', 'skill.md', 'skill.json', 'package.json',
        'README.md', 'readme.md', 'manifest.json', 'plugin.json'
      ];

      // Entry-point code files — scanned for critical patterns only
      const ENTRY_CODE_FILES = [
        'index.js', 'index.ts', 'main.js', 'main.ts',
        'src/index.js', 'src/index.ts', 'src/main.js', 'src/main.ts',
        'lib/index.js', 'lib/index.ts', 'app.js', 'app.ts'
      ];

      const MAX_FILE_SIZE = 200000; // 200KB per file

      // Try to detect the default branch
      let defaultBranch = 'main';
      try {
        const repoInfoUrl = `https://api.github.com/repos/${owner}/${cleanRepo}`;
        const repoInfoResp = await fetch(repoInfoUrl, {
          headers: { 'User-Agent': 'AgentShield/1.0' }
        });
        if (repoInfoResp.ok) {
          const repoInfo = await repoInfoResp.json();
          defaultBranch = repoInfo.default_branch || 'main';
        }
      } catch (e) {
        // Fall back to 'main', also try 'master' below
      }

      // Helper: fetch a raw file from the repo, returns null if not found
      const fetchRaw = async (filePath) => {
        const rawUrl = `https://raw.githubusercontent.com/${owner}/${cleanRepo}/${defaultBranch}/${filePath}`;
        try {
          const resp = await fetch(rawUrl);
          if (!resp.ok) return null;
          const text = await resp.text();
          if (text.length > MAX_FILE_SIZE) return null;
          return text;
        } catch (e) {
          return null;
        }
      };

      // Fetch definition files (these are what matter most for skill scanning)
      let definitionContent = '';
      let packageContent = '';
      let filesFetched = 0;

      const defResults = await Promise.allSettled(
        DEFINITION_FILES.map(async (f) => {
          const content = await fetchRaw(f);
          return content ? { path: f, content } : null;
        })
      );

      for (const result of defResults) {
        if (result.status === 'fulfilled' && result.value) {
          const { path: filePath, content } = result.value;
          filesFetched++;
          if (filePath === 'package.json') {
            packageContent = content;
          }
          definitionContent += `\n// === FILE: ${filePath} ===\n${content}\n`;
        }
      }

      // Fetch entry-point code files (scan only for critical issues)
      let codeContent = '';
      const codeResults = await Promise.allSettled(
        ENTRY_CODE_FILES.map(async (f) => {
          const content = await fetchRaw(f);
          return content ? { path: f, content } : null;
        })
      );

      for (const result of codeResults) {
        if (result.status === 'fulfilled' && result.value) {
          const { path: filePath, content } = result.value;
          filesFetched++;
          codeContent += `\n// === FILE: ${filePath} ===\n${content}\n`;
        }
      }

      // If we got nothing at all, try 'master' branch as fallback
      if (filesFetched === 0 && defaultBranch === 'main') {
        defaultBranch = 'master';
        const readmeContent = await fetchRaw('README.md');
        if (readmeContent) {
          definitionContent = `\n// === FILE: README.md ===\n${readmeContent}\n`;
          filesFetched = 1;
        }
      }

      if (filesFetched === 0) {
        throw new Error(`No scannable files found in ${owner}/${cleanRepo}`);
      }

      // Combine: definition content is primary, code content is secondary
      // The scan will analyze this combined content, but code files naturally
      // have fewer truly dangerous patterns than GitHub HTML did
      const allContent = definitionContent + codeContent;

      return {
        content: allContent,
        source: repoUrl,
        metadata: {
          packageJson: packageContent,
          repository: `${owner}/${cleanRepo}`,
          defaultBranch,
          filesFetched,
          isGitHubRepo: true
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