// Security report generator - creates comprehensive security reports
const { v4: uuidv4 } = require('uuid');

function generateReport(data) {
  const {
    scanId,
    source,
    content,
    findings,
    permissions,
    threatLevel,
    trustScore,
    badge,
    metadata
  } = data;

  // Generate summary
  const summary = generateSummary(findings, threatLevel);
  
  // Sort findings by severity
  const sortedFindings = sortFindingsBySeverity(findings);
  
  // Generate detailed analysis
  const analysis = generateAnalysis(findings, permissions);
  
  // Generate recommendations
  const recommendations = generateRecommendations(findings, trustScore, threatLevel);

  const report = {
    scanId,
    timestamp: new Date().toISOString(),
    source,
    threatLevel,
    trustScore,
    badge,
    summary,
    findings: sortedFindings,
    permissions,
    analysis,
    recommendations,
    metadata: {
      ...metadata,
      version: '1.0.0',
      scanner: 'AgentShield'
    }
  };

  return report;
}

function generateSummary(findings, threatLevel) {
  const counts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length
  };

  const total = counts.critical + counts.high + counts.medium + counts.low;
  
  let summary = '';
  
  if (total === 0) {
    summary = 'No security issues detected. Skill appears to follow security best practices.';
  } else {
    const parts = [];
    
    if (counts.critical > 0) {
      parts.push(`${counts.critical} critical issue${counts.critical > 1 ? 's' : ''}`);
    }
    if (counts.high > 0) {
      parts.push(`${counts.high} high-severity issue${counts.high > 1 ? 's' : ''}`);
    }
    if (counts.medium > 0) {
      parts.push(`${counts.medium} medium-severity issue${counts.medium > 1 ? 's' : ''}`);
    }
    if (counts.low > 0) {
      parts.push(`${counts.low} low-severity issue${counts.low > 1 ? 's' : ''}`);
    }
    
    summary = `Found ${parts.join(', ')}.`;
    
    // Add threat level context
    switch (threatLevel) {
      case 'critical':
        summary += ' Immediate action required - do not use this skill until issues are resolved.';
        break;
      case 'high':
        summary += ' Significant security concerns identified - review carefully before use.';
        break;
      case 'medium':
        summary += ' Some security concerns identified - use with caution.';
        break;
      case 'low':
        summary += ' Minor issues identified - generally safe to use with awareness.';
        break;
    }
  }

  return summary;
}

function sortFindingsBySeverity(findings) {
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  
  return findings.sort((a, b) => {
    const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
    if (severityDiff !== 0) return severityDiff;
    
    // Sort by line number if same severity
    return (a.line || 0) - (b.line || 0);
  });
}

function generateAnalysis(findings, permissions) {
  const analysis = {
    riskProfile: calculateRiskProfile(findings),
    attackVectors: identifyAttackVectors(findings),
    dataFlow: analyzeDataFlow(findings, permissions),
    complianceIssues: identifyComplianceIssues(findings)
  };

  return analysis;
}

function calculateRiskProfile(findings) {
  const profile = {
    confidentialityRisk: 'low',
    integrityRisk: 'low',
    availabilityRisk: 'low',
    overallRisk: 'low'
  };

  // Analyze confidentiality risk
  const dataTheftFindings = findings.filter(f => 
    f.category === 'credential-theft' || 
    f.category === 'data-exfiltration'
  );
  
  if (dataTheftFindings.some(f => f.severity === 'critical')) {
    profile.confidentialityRisk = 'critical';
  } else if (dataTheftFindings.some(f => f.severity === 'high')) {
    profile.confidentialityRisk = 'high';
  } else if (dataTheftFindings.length > 0) {
    profile.confidentialityRisk = 'medium';
  }

  // Analyze integrity risk
  const integrityFindings = findings.filter(f => 
    f.category === 'remote-code-execution' || 
    f.category === 'privilege-escalation' ||
    f.title.includes('modification')
  );
  
  if (integrityFindings.some(f => f.severity === 'critical')) {
    profile.integrityRisk = 'critical';
  } else if (integrityFindings.some(f => f.severity === 'high')) {
    profile.integrityRisk = 'high';
  } else if (integrityFindings.length > 0) {
    profile.integrityRisk = 'medium';
  }

  // Analyze availability risk
  const availabilityFindings = findings.filter(f => 
    f.category === 'remote-code-execution' ||
    f.title.includes('resource') ||
    f.title.includes('denial')
  );
  
  if (availabilityFindings.some(f => f.severity === 'critical')) {
    profile.availabilityRisk = 'critical';
  } else if (availabilityFindings.some(f => f.severity === 'high')) {
    profile.availabilityRisk = 'high';
  } else if (availabilityFindings.length > 0) {
    profile.availabilityRisk = 'medium';
  }

  // Calculate overall risk
  const risks = [profile.confidentialityRisk, profile.integrityRisk, profile.availabilityRisk];
  if (risks.includes('critical')) {
    profile.overallRisk = 'critical';
  } else if (risks.includes('high')) {
    profile.overallRisk = 'high';
  } else if (risks.includes('medium')) {
    profile.overallRisk = 'medium';
  }

  return profile;
}

function identifyAttackVectors(findings) {
  const vectors = [];

  // Group findings by attack vector
  const credentialTheft = findings.filter(f => f.category === 'credential-theft');
  const codeExecution = findings.filter(f => f.category === 'remote-code-execution');
  const dataExfiltration = findings.filter(f => f.category === 'data-exfiltration');
  const privilegeEscalation = findings.filter(f => f.category === 'privilege-escalation');

  if (credentialTheft.length > 0) {
    vectors.push({
      type: 'Credential Theft',
      severity: Math.max(...credentialTheft.map(getSeverityScore)),
      description: 'Skill may steal or exfiltrate user credentials, API keys, or sensitive authentication data',
      findings: credentialTheft.length,
      impact: 'Account compromise, unauthorized access to external services'
    });
  }

  if (codeExecution.length > 0) {
    vectors.push({
      type: 'Remote Code Execution',
      severity: Math.max(...codeExecution.map(getSeverityScore)),
      description: 'Skill may execute arbitrary code on the host system',
      findings: codeExecution.length,
      impact: 'Full system compromise, malware installation, data destruction'
    });
  }

  if (dataExfiltration.length > 0) {
    vectors.push({
      type: 'Data Exfiltration',
      severity: Math.max(...dataExfiltration.map(getSeverityScore)),
      description: 'Skill may extract and transmit sensitive data to external parties',
      findings: dataExfiltration.length,
      impact: 'Privacy breach, data theft, intellectual property loss'
    });
  }

  if (privilegeEscalation.length > 0) {
    vectors.push({
      type: 'Privilege Escalation',
      severity: Math.max(...privilegeEscalation.map(getSeverityScore)),
      description: 'Skill may attempt to gain elevated system privileges',
      findings: privilegeEscalation.length,
      impact: 'Administrative access, system control, security control bypass'
    });
  }

  return vectors.sort((a, b) => b.severity - a.severity);
}

function getSeverityScore(finding) {
  const scores = { critical: 4, high: 3, medium: 2, low: 1 };
  return scores[finding.severity] || 0;
}

function analyzeDataFlow(findings, permissions) {
  const dataFlow = {
    inputs: [],
    outputs: [],
    storage: [],
    processing: []
  };

  // Analyze what data the skill might access based on findings
  if (permissions.fileSystemRead) {
    dataFlow.inputs.push('Local files and directories');
  }
  
  if (permissions.networkAccess) {
    dataFlow.outputs.push('External network endpoints');
    dataFlow.inputs.push('Network requests and responses');
  }

  if (permissions.shellExecution) {
    dataFlow.inputs.push('Command line arguments and environment');
    dataFlow.processing.push('Shell command execution');
  }

  if (permissions.configModification) {
    dataFlow.storage.push('Agent configuration files');
    dataFlow.processing.push('Configuration modification');
  }

  // Add specific flows based on findings
  const credentialFindings = findings.filter(f => f.category === 'credential-theft');
  if (credentialFindings.length > 0) {
    dataFlow.inputs.push('Credentials and authentication tokens');
    dataFlow.outputs.push('Credential data to external services');
  }

  const exfiltrationFindings = findings.filter(f => f.category === 'data-exfiltration');
  if (exfiltrationFindings.length > 0) {
    dataFlow.outputs.push('Sensitive file contents to external URLs');
  }

  return dataFlow;
}

function identifyComplianceIssues(findings) {
  const complianceIssues = [];

  // GDPR compliance issues
  const privacyFindings = findings.filter(f => 
    f.category === 'data-exfiltration' || 
    f.title.includes('personal') ||
    f.title.includes('privacy')
  );
  
  if (privacyFindings.length > 0) {
    complianceIssues.push({
      regulation: 'GDPR',
      issue: 'Potential unauthorized data processing',
      description: 'Skill may process personal data without proper consent or legal basis',
      severity: 'high'
    });
  }

  // SOC 2 compliance issues
  const securityControlFindings = findings.filter(f => 
    f.category === 'credential-theft' || 
    f.category === 'privilege-escalation' ||
    f.severity === 'critical'
  );
  
  if (securityControlFindings.length > 0) {
    complianceIssues.push({
      regulation: 'SOC 2',
      issue: 'Inadequate security controls',
      description: 'Skill lacks proper security controls required for SOC 2 compliance',
      severity: 'high'
    });
  }

  // PCI DSS compliance issues
  const paymentDataFindings = findings.filter(f => 
    f.evidence && /(?:card|payment|credit|cvv|pan)/i.test(f.evidence)
  );
  
  if (paymentDataFindings.length > 0) {
    complianceIssues.push({
      regulation: 'PCI DSS',
      issue: 'Insecure payment data handling',
      description: 'Skill may handle payment card data insecurely',
      severity: 'critical'
    });
  }

  return complianceIssues;
}

function generateRecommendations(findings, trustScore, threatLevel) {
  const recommendations = {
    immediate: [],
    shortTerm: [],
    longTerm: [],
    bestPractices: []
  };

  // Immediate actions for critical/high severity
  const criticalFindings = findings.filter(f => f.severity === 'critical');
  const highFindings = findings.filter(f => f.severity === 'high');

  if (criticalFindings.length > 0) {
    recommendations.immediate.push('DO NOT USE - Address all critical security issues before deployment');
    recommendations.immediate.push('Review and remove any credential theft or code execution vulnerabilities');
    recommendations.immediate.push('Audit all external network connections and data transmissions');
  }

  if (highFindings.length > 0 && criticalFindings.length === 0) {
    recommendations.immediate.push('Use with extreme caution - address high-severity issues promptly');
    recommendations.immediate.push('Implement additional monitoring and access controls');
  }

  // Short-term recommendations
  if (trustScore < 70) {
    recommendations.shortTerm.push('Implement comprehensive input validation and sanitization');
    recommendations.shortTerm.push('Add proper error handling and logging');
    recommendations.shortTerm.push('Review and minimize requested permissions');
  }

  // Long-term recommendations
  recommendations.longTerm.push('Establish regular security audits and code reviews');
  recommendations.longTerm.push('Implement automated security testing in development pipeline');
  recommendations.longTerm.push('Follow secure coding best practices and guidelines');

  // Best practices
  recommendations.bestPractices = [
    'Use least privilege principle - request minimal necessary permissions',
    'Validate and sanitize all user inputs',
    'Avoid dynamic code execution (eval, exec with user input)',
    'Use secure communication protocols (HTTPS) for external connections',
    'Implement proper error handling without exposing sensitive information',
    'Keep dependencies updated and monitor for vulnerabilities',
    'Document all external dependencies and network connections',
    'Follow the principle of fail-safe defaults'
  ];

  return recommendations;
}

// Generate a human-readable security report in markdown format
function generateMarkdownReport(report) {
  let markdown = `# Security Scan Report\n\n`;
  markdown += `**Scan ID:** ${report.scanId}\n`;
  markdown += `**Timestamp:** ${report.timestamp}\n`;
  markdown += `**Source:** ${report.source}\n`;
  markdown += `**Threat Level:** ${report.threatLevel.toUpperCase()}\n`;
  markdown += `**Trust Score:** ${report.trustScore}/100\n`;
  markdown += `**Badge:** ${report.badge}\n\n`;

  markdown += `## Summary\n\n${report.summary}\n\n`;

  if (report.findings.length > 0) {
    markdown += `## Security Findings\n\n`;
    
    report.findings.forEach((finding, index) => {
      markdown += `### ${index + 1}. ${finding.title}\n\n`;
      markdown += `**Severity:** ${finding.severity.toUpperCase()}\n`;
      markdown += `**Category:** ${finding.category}\n`;
      markdown += `**Description:** ${finding.description}\n`;
      if (finding.line > 0) {
        markdown += `**Line:** ${finding.line}\n`;
      }
      markdown += `**Evidence:** \`${finding.evidence}\`\n`;
      markdown += `**Remediation:** ${finding.remediation}\n\n`;
    });
  }

  markdown += `## Permissions Analysis\n\n`;
  Object.entries(report.permissions).forEach(([key, value]) => {
    markdown += `- **${key}:** ${value ? '✓ Granted' : '✗ Not Required'}\n`;
  });

  if (report.recommendations.immediate.length > 0) {
    markdown += `\n## Immediate Actions Required\n\n`;
    report.recommendations.immediate.forEach(rec => {
      markdown += `- ${rec}\n`;
    });
  }

  return markdown;
}

module.exports = {
  generateReport,
  generateSummary,
  generateAnalysis,
  generateRecommendations,
  generateMarkdownReport
};