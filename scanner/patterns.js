// Security pattern detection engine for AI agent skills
// Comprehensive vulnerability detection with line-by-line analysis

const SECURITY_PATTERNS = {
  // CRITICAL SEVERITY - Credential Theft
  credentialTheft: [
    {
      id: 'env-exfiltration',
      pattern: /(?:curl|wget|fetch|axios|request).*?(?:env|process\.env|\$[A-Z_]+|ENV\[|getenv)/gi,
      severity: 'critical',
      category: 'credential-theft',
      title: 'Environment variable exfiltration',
      description: 'Skill may be sending environment variables or secrets to external URLs',
      remediation: 'Remove external transmission of environment variables and use secure credential storage'
    },
    {
      id: 'api-key-theft',
      pattern: /(?:curl|wget|fetch).*?(?:api[_-]?key|token|secret|password|auth|bearer|x-api-key)/gi,
      severity: 'critical',
      category: 'credential-theft',
      title: 'API key or token theft detected',
      description: 'Skill appears to be transmitting API keys or authentication tokens',
      remediation: 'Never send credentials to external endpoints; use secure local storage only'
    },
    {
      id: 'base64-credential-encoding',
      pattern: /(?:btoa|base64|Buffer\.from|atob).*?(?:api[_-]?key|token|secret|password|auth|\$[A-Z_]+)/gi,
      severity: 'critical',
      category: 'credential-theft',
      title: 'Base64 encoded credential transmission',
      description: 'Credentials are being base64 encoded, possibly to evade detection before transmission',
      remediation: 'Remove credential encoding and external transmission patterns'
    },
    {
      id: 'auth-file-access',
      pattern: /(?:cat|read|open|readFile|fs\.read).*?(?:\.env|\.aws|\.ssh|auth-profiles\.json|credentials|id_rsa|id_ed25519|\.pem)/gi,
      severity: 'critical',
      category: 'credential-theft',
      title: 'Authentication file access detected',
      description: 'Skill is attempting to read sensitive authentication files',
      remediation: 'Remove access to authentication files; request only necessary permissions'
    },
    {
      id: 'ssh-key-theft',
      pattern: /(?:~\/\.ssh|\/home\/.*?\.ssh|id_rsa|id_ed25519|authorized_keys|known_hosts)/gi,
      severity: 'critical',
      category: 'credential-theft',
      title: 'SSH key access detected',
      description: 'Skill is accessing SSH keys or SSH configuration',
      remediation: 'Remove SSH key access; use secure key management instead'
    }
  ],

  // CRITICAL SEVERITY - Remote Code Execution
  remoteCodeExecution: [
    {
      id: 'eval-rce',
      pattern: /eval\s*\(\s*(?!["'])/gi,
      severity: 'critical',
      category: 'remote-code-execution',
      title: 'Code evaluation with dynamic input',
      description: 'eval() function called with potentially user-controlled input',
      remediation: 'Replace eval() with safe alternatives like JSON.parse() for data parsing'
    },
    {
      id: 'exec-rce',
      pattern: /(?:exec|execSync|spawn|fork)\s*\(\s*[^"']/gi,
      severity: 'critical',
      category: 'remote-code-execution',
      title: 'Command execution with dynamic input',
      description: 'System command execution with user-controlled input detected',
      remediation: 'Use parameterized commands and input validation; avoid dynamic command construction'
    },
    {
      id: 'download-execute',
      pattern: /(?:curl|wget).*?\|\s*(?:bash|sh|python|node|eval)/gi,
      severity: 'critical',
      category: 'remote-code-execution',
      title: 'Download-and-execute pattern',
      description: 'Skill downloads and immediately executes code from external source',
      remediation: 'Never download and execute code directly; use package managers or manual verification'
    },
    {
      id: 'shell-injection',
      pattern: /(?:system|exec|shell_exec|passthru|popen).*?(?:\$\{|\$\(|`.*?\$)/gi,
      severity: 'critical',
      category: 'remote-code-execution',
      title: 'Shell command injection vulnerability',
      description: 'User input is directly interpolated into shell commands',
      remediation: 'Use parameterized commands and proper input escaping'
    },
    {
      id: 'system-file-modification',
      pattern: /(?:echo|cat|tee|>|>>).*?(?:\/etc\/|\/usr\/bin\/|\/sbin\/|crontab|systemd)/gi,
      severity: 'critical',
      category: 'remote-code-execution',
      title: 'System file modification attempt',
      description: 'Skill attempts to modify critical system files or directories',
      remediation: 'Remove system file modifications; use user-space alternatives'
    },
    {
      id: 'agent-config-modification',
      pattern: /(?:echo|cat|tee|>|>>|write|writeFile).*?(?:SOUL\.md|AGENTS\.md|config\.json|\.env)/gi,
      severity: 'critical',
      category: 'remote-code-execution',
      title: 'Agent configuration tampering',
      description: 'Skill attempts to modify agent configuration or core files',
      remediation: 'Remove agent configuration modifications; respect read-only system files'
    }
  ],

  // HIGH SEVERITY - Data Exfiltration
  dataExfiltration: [
    {
      id: 'file-content-transmission',
      pattern: /(?:curl|wget|fetch|post|axios).*?(?:-d|--data|body:|data:).*?(?:\$\(cat|readFile|fs\.read|@\$)/gi,
      severity: 'high',
      category: 'data-exfiltration',
      title: 'File content transmission to external URL',
      description: 'File contents are being sent to external endpoints',
      remediation: 'Remove external file transmission; process files locally only'
    },
    {
      id: 'directory-traversal',
      pattern: /(?:\.\.\/|\.\.\\|\/\.\.\/|\\\.\.\\)/gi,
      severity: 'high',
      category: 'data-exfiltration',
      title: 'Directory traversal attempt',
      description: 'Path traversal sequences detected - may access files outside workspace',
      remediation: 'Use absolute paths or validate all file paths to prevent directory traversal'
    },
    {
      id: 'browser-data-access',
      pattern: /(?:cookies|history|passwords|bookmarks|sessionStorage|localStorage).*?(?:chrome|firefox|safari|browser)/gi,
      severity: 'high',
      category: 'data-exfiltration',
      title: 'Browser data access detected',
      description: 'Skill attempts to access browser cookies, history, or stored passwords',
      remediation: 'Remove browser data access; use explicit user consent for any browser integration'
    },
    {
      id: 'memory-file-access',
      pattern: /(?:memory\/|MEMORY\.md|SOUL\.md|\.memory|memory\.json)/gi,
      severity: 'high',
      category: 'data-exfiltration',
      title: 'Agent memory access detected',
      description: 'Skill accesses other agents\' memory files or personal data',
      remediation: 'Access only your own memory files; respect agent privacy boundaries'
    },
    {
      id: 'network-with-file-data',
      pattern: /(?:POST|PUT|PATCH).*?(?:readFile|fs\.read|cat \$|@\$)/gi,
      severity: 'high',
      category: 'data-exfiltration',
      title: 'Network request containing file data',
      description: 'HTTP request sends file contents in request body or parameters',
      remediation: 'Process files locally; avoid sending file contents over network'
    }
  ],

  // HIGH SEVERITY - Privilege Escalation
  privilegeEscalation: [
    {
      id: 'sudo-usage',
      pattern: /(?:sudo|su -|su root)/gi,
      severity: 'high',
      category: 'privilege-escalation',
      title: 'Privilege escalation attempt',
      description: 'Skill attempts to execute commands with elevated privileges',
      remediation: 'Remove sudo/su usage; design skill to work with user-level permissions'
    },
    {
      id: 'permission-modification',
      pattern: /(?:chmod 777|chmod -R 777|chown|chgrp)/gi,
      severity: 'high',
      category: 'privilege-escalation',
      title: 'File permission modification',
      description: 'Skill modifies file permissions, potentially weakening security',
      remediation: 'Use minimal required permissions; avoid chmod 777 or ownership changes'
    },
    {
      id: 'proc-sys-access',
      pattern: /(?:\/proc\/|\/sys\/|\/dev\/)/gi,
      severity: 'high',
      category: 'privilege-escalation',
      title: 'System filesystem access',
      description: 'Skill accesses system filesystems (/proc, /sys, /dev)',
      remediation: 'Remove system filesystem access; use user-space alternatives'
    },
    {
      id: 'docker-escape',
      pattern: /(?:docker\.sock|\/var\/run\/docker|docker exec -it|privileged|--cap-add)/gi,
      severity: 'high',
      category: 'privilege-escalation',
      title: 'Potential container escape attempt',
      description: 'Skill shows patterns consistent with Docker container escape techniques',
      remediation: 'Remove Docker socket access and privileged operations'
    },
    {
      id: 'mount-host-filesystem',
      pattern: /(?:mount|\/dev\/|\/host|bind.*?\/)/gi,
      severity: 'high',
      category: 'privilege-escalation',
      title: 'Host filesystem mounting detected',
      description: 'Skill attempts to mount or access host filesystem from container',
      remediation: 'Remove filesystem mounting; use provided volume mounts only'
    }
  ],

  // MEDIUM SEVERITY - Suspicious Behavior
  suspiciousBehavior: [
    {
      id: 'heavy-obfuscation',
      pattern: /(?:(?:[A-Za-z0-9+\/]{20,}={0,2})|(?:(?:\\x[0-9a-fA-F]{2}){10,})|(?:String\.fromCharCode\(\s*\d+(?:\s*,\s*\d+){5,}\)))/gi,
      severity: 'medium',
      category: 'suspicious-behavior',
      title: 'Heavy code obfuscation detected',
      description: 'Extensive use of base64, hex encoding, or character code obfuscation',
      remediation: 'Use readable code; avoid unnecessary obfuscation that hides intent'
    },
    {
      id: 'dynamic-url-construction',
      pattern: /(?:https?:\/\/|url\s*=).*?(?:\+|\$\{|\${)|(?:protocol|hostname|domain).*?(?:\+|\$\{)/gi,
      severity: 'medium',
      category: 'suspicious-behavior',
      title: 'Dynamic URL construction',
      description: 'URLs are constructed dynamically, potentially to evade static analysis',
      remediation: 'Use static, whitelisted URLs; avoid dynamic URL construction'
    },
    {
      id: 'conditional-payload',
      pattern: /(?:hostname|os\.hostname|process\.env\.USER|whoami).*?(?:if|===|==|\?)/gi,
      severity: 'medium',
      category: 'suspicious-behavior',
      title: 'Environment-based conditional execution',
      description: 'Code execution varies based on hostname or user - possible targeted attack',
      remediation: 'Remove environment-specific conditional logic that could indicate targeting'
    },
    {
      id: 'timing-evasion',
      pattern: /(?:sleep|setTimeout|delay|wait).*?(?:\d{3,}|random)/gi,
      severity: 'medium',
      category: 'suspicious-behavior',
      title: 'Timing manipulation detected',
      description: 'Unusual delays or timing patterns that might evade analysis or monitoring',
      remediation: 'Remove unnecessary delays; use predictable timing patterns'
    },
    {
      id: 'logging-disabling',
      pattern: /(?:console\.log\s*=|log.*?=.*?null|>/dev/null|2>&1|silence|quiet.*?true)/gi,
      severity: 'medium',
      category: 'suspicious-behavior',
      title: 'Logging suppression detected',
      description: 'Code attempts to disable or suppress logging and error reporting',
      remediation: 'Maintain proper logging for debugging and audit trails'
    }
  ],

  // LOW SEVERITY - Best Practice Violations
  bestPracticeViolations: [
    {
      id: 'no-input-validation',
      pattern: /(?:req\.body|req\.query|process\.argv|input)(?!.*(?:validate|sanitize|check|filter|escape))/gi,
      severity: 'low',
      category: 'best-practice-violation',
      title: 'Missing input validation',
      description: 'User input is processed without apparent validation or sanitization',
      remediation: 'Add input validation and sanitization for all user-provided data'
    },
    {
      id: 'hardcoded-credentials',
      pattern: /(?:api_key|password|secret|token)\s*[:=]\s*["'][^"'\s]{10,}["']/gi,
      severity: 'low',
      category: 'best-practice-violation',
      title: 'Hardcoded credentials detected',
      description: 'Credentials appear to be hardcoded in the skill source',
      remediation: 'Move credentials to environment variables or secure configuration'
    },
    {
      id: 'broad-permissions',
      pattern: /(?:fs\.readdir|readdir|ls -la|find \/ |chmod -R|.*\*.*)/gi,
      severity: 'low',
      category: 'best-practice-violation',
      title: 'Overly broad file system permissions',
      description: 'Skill requests broad file system access that may not be necessary',
      remediation: 'Request minimal required permissions; specify exact files or directories needed'
    },
    {
      id: 'missing-error-handling',
      pattern: /(?:exec|spawn|readFile|fetch)(?!.*(?:catch|error|err =>|try\s*\{))/gi,
      severity: 'low',
      category: 'best-practice-violation',
      title: 'Missing error handling',
      description: 'Operations that can fail lack proper error handling',
      remediation: 'Add comprehensive error handling for all operations that can fail'
    },
    {
      id: 'deprecated-functions',
      pattern: /(?:execSync|readFileSync|writeFileSync|exists|existsSync)/gi,
      severity: 'low',
      category: 'best-practice-violation',
      title: 'Deprecated synchronous functions',
      description: 'Use of deprecated synchronous functions that can block execution',
      remediation: 'Use async alternatives (exec, readFile, writeFile, access) with proper error handling'
    }
  ]
};

// Skill structure analysis patterns
const STRUCTURE_PATTERNS = {
  hiddenInstructions: /<!--[\s\S]*?(?:ignore|bypass|skip|override|jailbreak)[\s\S]*?-->/gi,
  promptInjection: /(?:ignore previous|forget everything|new instruction|system:|assistant:|user:)/gi,
  excessivePermissions: /(?:sudo|root|admin|full access|unrestricted|all files|entire system)/gi,
  scopeCreep: /(?:also|additionally|furthermore|while you're at it|and also|plus)/gi
};

// Known vulnerable dependency patterns
const VULNERABLE_DEPENDENCIES = [
  { pattern: /lodash@[0-4]\./gi, severity: 'high', issue: 'Prototype pollution vulnerabilities' },
  { pattern: /express@[0-3]\./gi, severity: 'medium', issue: 'Security vulnerabilities in old versions' },
  { pattern: /request@/gi, severity: 'low', issue: 'Deprecated package with security issues' },
  { pattern: /node-fetch@[0-1]\./gi, severity: 'medium', issue: 'Security vulnerabilities in old versions' }
];

function analyzeCode(content) {
  const findings = [];
  const lines = content.split('\n');
  
  // Track permissions requested
  const permissions = {
    networkAccess: false,
    fileSystemRead: false,
    fileSystemWrite: false,
    shellExecution: false,
    configModification: false
  };

  // Analyze each pattern category
  Object.values(SECURITY_PATTERNS).forEach(patternGroup => {
    patternGroup.forEach(pattern => {
      const matches = content.matchAll(pattern.pattern);
      for (const match of matches) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const evidence = lines[lineNumber - 1]?.trim() || match[0];
        
        findings.push({
          severity: pattern.severity,
          category: pattern.category,
          title: pattern.title,
          description: pattern.description,
          evidence: evidence,
          line: lineNumber,
          remediation: pattern.remediation,
          patternId: pattern.id
        });

        // Track permissions based on patterns found
        if (pattern.category === 'data-exfiltration' || pattern.id.includes('network')) {
          permissions.networkAccess = true;
        }
        if (pattern.id.includes('file') || pattern.id.includes('read')) {
          permissions.fileSystemRead = true;
        }
        if (pattern.id.includes('write') || pattern.id.includes('modification')) {
          permissions.fileSystemWrite = true;
        }
        if (pattern.category === 'remote-code-execution' || pattern.id.includes('exec')) {
          permissions.shellExecution = true;
        }
        if (pattern.id.includes('config') || pattern.id.includes('SOUL') || pattern.id.includes('AGENTS')) {
          permissions.configModification = true;
        }
      }
    });
  });

  return { findings, permissions };
}

function analyzeStructure(content) {
  const structureIssues = [];
  
  Object.entries(STRUCTURE_PATTERNS).forEach(([key, pattern]) => {
    const matches = content.matchAll(pattern);
    for (const match of matches) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      structureIssues.push({
        type: key,
        line: lineNumber,
        evidence: match[0],
        severity: key === 'hiddenInstructions' || key === 'promptInjection' ? 'high' : 'medium'
      });
    }
  });

  return structureIssues;
}

function analyzeDependencies(packageContent) {
  const depIssues = [];
  
  if (packageContent) {
    VULNERABLE_DEPENDENCIES.forEach(vuln => {
      const matches = packageContent.matchAll(vuln.pattern);
      for (const match of matches) {
        depIssues.push({
          severity: vuln.severity,
          dependency: match[0],
          issue: vuln.issue,
          remediation: 'Update to latest secure version'
        });
      }
    });
  }

  return depIssues;
}

function calculateThreatLevel(findings) {
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const mediumCount = findings.filter(f => f.severity === 'medium').length;

  if (criticalCount > 0) return 'critical';
  if (highCount > 2) return 'critical';
  if (highCount > 0) return 'high';
  if (mediumCount > 3) return 'high';
  if (mediumCount > 0) return 'medium';
  if (findings.length > 0) return 'low';
  return 'clean';
}

function calculateTrustScore(findings) {
  let score = 100;
  
  findings.forEach(finding => {
    switch (finding.severity) {
      case 'critical': score -= 25; break;
      case 'high': score -= 15; break;
      case 'medium': score -= 8; break;
      case 'low': score -= 3; break;
    }
  });

  return Math.max(0, Math.min(100, score));
}

function getBadgeType(trustScore, threatLevel) {
  if (threatLevel === 'critical' || trustScore < 40) return 'dangerous';
  if (threatLevel === 'high' || trustScore < 70) return 'caution';
  if (threatLevel === 'clean' && trustScore >= 90) return 'verified-safe';
  return 'caution';
}

module.exports = {
  SECURITY_PATTERNS,
  STRUCTURE_PATTERNS,
  VULNERABLE_DEPENDENCIES,
  analyzeCode,
  analyzeStructure,
  analyzeDependencies,
  calculateThreatLevel,
  calculateTrustScore,
  getBadgeType
};