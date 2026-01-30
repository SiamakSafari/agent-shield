// SKILL.md structure analyzer - validates skill format and detects structural issues
const fs = require('fs');
const path = require('path');

// Expected SKILL.md structure patterns
const EXPECTED_SECTIONS = [
  { name: 'title', pattern: /^# .+/m, required: true },
  { name: 'description', pattern: /## Description\s*\n/m, required: true },
  { name: 'installation', pattern: /## Installation\s*\n/m, required: false },
  { name: 'usage', pattern: /## Usage\s*\n/m, required: true },
  { name: 'permissions', pattern: /## Permissions\s*\n/m, required: true }
];

// Dangerous permission requests
const DANGEROUS_PERMISSIONS = [
  { pattern: /sudo|root|administrator/gi, severity: 'high', description: 'Requests elevated privileges' },
  { pattern: /full.{0,10}access|unrestricted|all.{0,10}files/gi, severity: 'high', description: 'Requests unrestricted access' },
  { pattern: /network.{0,10}access|internet|external.{0,10}api/gi, severity: 'medium', description: 'Requests network access' },
  { pattern: /file.{0,10}system|disk.{0,10}access/gi, severity: 'medium', description: 'Requests file system access' },
  { pattern: /shell|command.{0,10}line|exec/gi, severity: 'high', description: 'Requests shell/command execution' }
];

// Suspicious instruction patterns in skill descriptions
const SUSPICIOUS_INSTRUCTIONS = [
  { 
    pattern: /ignore.{0,20}(?:previous|above|security|warnings)/gi, 
    severity: 'critical', 
    title: 'Ignore instruction injection',
    description: 'Skill contains instructions to ignore security measures'
  },
  { 
    pattern: /(?:jailbreak|bypass|override|disable).{0,20}(?:security|safety|protection)/gi, 
    severity: 'critical', 
    title: 'Security bypass instruction',
    description: 'Skill attempts to bypass security measures'
  },
  { 
    pattern: /new.{0,10}instruction|system.{0,10}prompt|role.{0,10}play/gi, 
    severity: 'high', 
    title: 'Prompt manipulation',
    description: 'Skill may contain prompt injection attempts'
  },
  { 
    pattern: /secret|hidden|don\'t.{0,10}tell|confidential/gi, 
    severity: 'medium', 
    title: 'Secretive behavior instruction',
    description: 'Skill instructs secretive or hidden behavior'
  }
];

// Tool declaration analysis patterns
const TOOL_SCOPE_ISSUES = [
  {
    pattern: /parameters.*?"type":\s*"object".*?"properties":\s*\{\s*\}/gs,
    severity: 'medium',
    title: 'Overly broad tool parameters',
    description: 'Tool accepts arbitrary object parameters without validation'
  },
  {
    pattern: /"required":\s*\[\s*\]/g,
    severity: 'low',
    title: 'No required parameters',
    description: 'Tool has no required parameters, potentially too permissive'
  },
  {
    pattern: /"additionalProperties":\s*true/g,
    severity: 'medium',
    title: 'Accepts additional properties',
    description: 'Tool accepts undefined additional properties'
  }
];

function analyzeSkillStructure(content) {
  const issues = [];
  const structure = {
    hasTitle: false,
    hasDescription: false,
    hasUsage: false,
    hasPermissions: false,
    hasDangerousPermissions: false,
    hasToolDeclarations: false,
    sectionsFound: [],
    missingRequiredSections: []
  };

  // Check for required sections
  EXPECTED_SECTIONS.forEach(section => {
    const found = section.pattern.test(content);
    structure[`has${section.name.charAt(0).toUpperCase() + section.name.slice(1)}`] = found;
    
    if (found) {
      structure.sectionsFound.push(section.name);
    } else if (section.required) {
      structure.missingRequiredSections.push(section.name);
      issues.push({
        severity: 'medium',
        title: `Missing required section: ${section.name}`,
        description: `SKILL.md should include a ${section.name} section`,
        evidence: `No ${section.name} section found`,
        remediation: `Add a properly formatted ${section.name} section to your SKILL.md`
      });
    }
  });

  // Check for dangerous permission requests
  DANGEROUS_PERMISSIONS.forEach(perm => {
    const matches = content.matchAll(perm.pattern);
    for (const match of matches) {
      structure.hasDangerousPermissions = true;
      const lineNumber = content.substring(0, match.index).split('\n').length;
      
      issues.push({
        severity: perm.severity,
        title: 'Dangerous permission request',
        description: perm.description,
        evidence: match[0],
        line: lineNumber,
        remediation: 'Request only minimal necessary permissions; avoid broad access requests'
      });
    }
  });

  // Check for suspicious instructions
  SUSPICIOUS_INSTRUCTIONS.forEach(instruction => {
    const matches = content.matchAll(instruction.pattern);
    for (const match of matches) {
      const lineNumber = content.substring(0, match.index).split('\n').length;
      
      issues.push({
        severity: instruction.severity,
        title: instruction.title,
        description: instruction.description,
        evidence: match[0],
        line: lineNumber,
        remediation: 'Remove instructions that attempt to manipulate agent behavior or bypass security'
      });
    }
  });

  // Check for tool declarations
  if (content.includes('function') || content.includes('tool') || content.includes('parameters')) {
    structure.hasToolDeclarations = true;
    
    // Analyze tool scope issues
    TOOL_SCOPE_ISSUES.forEach(scope => {
      const matches = content.matchAll(scope.pattern);
      for (const match of matches) {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        
        issues.push({
          severity: scope.severity,
          title: scope.title,
          description: scope.description,
          evidence: match[0].substring(0, 100) + '...',
          line: lineNumber,
          remediation: 'Define specific, validated parameters for tools; avoid overly permissive schemas'
        });
      }
    });
  }

  // Check for hidden content in HTML comments
  const htmlComments = content.matchAll(/<!--([\s\S]*?)-->/g);
  for (const comment of htmlComments) {
    const commentContent = comment[1];
    const lineNumber = content.substring(0, comment.index).split('\n').length;
    
    // Check if comment contains suspicious content
    if (/(?:ignore|bypass|secret|hidden|jailbreak)/i.test(commentContent)) {
      issues.push({
        severity: 'high',
        title: 'Hidden instructions in HTML comment',
        description: 'HTML comment contains potentially malicious instructions',
        evidence: `<!-- ${commentContent.substring(0, 50)}... -->`,
        line: lineNumber,
        remediation: 'Remove hidden instructions from HTML comments'
      });
    }
  }

  // Check for markdown link manipulation
  const suspiciousLinks = content.matchAll(/\[([^\]]*)\]\(([^)]*(?:javascript:|data:|file:|ftp:)[^)]*)\)/g);
  for (const link of suspiciousLinks) {
    const lineNumber = content.substring(0, link.index).split('\n').length;
    
    issues.push({
      severity: 'medium',
      title: 'Suspicious link protocol',
      description: 'Markdown link uses potentially dangerous protocol',
      evidence: link[0],
      line: lineNumber,
      remediation: 'Use only safe link protocols (http, https); avoid javascript:, data:, file: links'
    });
  }

  // Check for excessive external links
  const externalLinks = content.match(/https?:\/\/[^\s)]+/g) || [];
  if (externalLinks.length > 10) {
    issues.push({
      severity: 'low',
      title: 'Excessive external links',
      description: `Skill contains ${externalLinks.length} external links`,
      evidence: `${externalLinks.length} external links found`,
      remediation: 'Minimize external dependencies; justify need for each external link'
    });
  }

  // Check for code injection in examples
  const codeBlocks = content.matchAll(/```[\s\S]*?```/g);
  for (const codeBlock of codeBlocks) {
    const code = codeBlock[0];
    const lineNumber = content.substring(0, codeBlock.index).split('\n').length;
    
    // Check for dangerous patterns in code examples
    if (/(?:eval|exec|system|shell_exec)\s*\(/i.test(code)) {
      issues.push({
        severity: 'medium',
        title: 'Dangerous code in examples',
        description: 'Code examples contain potentially dangerous functions',
        evidence: code.substring(0, 100) + '...',
        line: lineNumber,
        remediation: 'Use safe code examples; avoid demonstrating dangerous functions'
      });
    }
  }

  return {
    structure,
    issues
  };
}

// Validate against known good skill formats
function validateSkillFormat(content) {
  const validation = {
    isValid: true,
    errors: [],
    warnings: [],
    score: 100
  };

  // Check basic markdown structure
  if (!content.trim()) {
    validation.isValid = false;
    validation.errors.push('SKILL.md is empty');
    validation.score = 0;
    return validation;
  }

  // Must start with a title
  if (!/^#\s+/.test(content.trim())) {
    validation.errors.push('SKILL.md must start with a title (# Title)');
    validation.score -= 20;
  }

  // Should have description
  if (!/##\s+Description/i.test(content)) {
    validation.warnings.push('Consider adding a Description section');
    validation.score -= 10;
  }

  // Should have usage examples
  if (!/##\s+Usage/i.test(content)) {
    validation.warnings.push('Consider adding a Usage section with examples');
    validation.score -= 10;
  }

  // Check for proper markdown formatting
  const lines = content.split('\n');
  let inCodeBlock = false;
  
  lines.forEach((line, index) => {
    if (line.startsWith('```')) {
      inCodeBlock = !inCodeBlock;
    }
    
    if (!inCodeBlock) {
      // Check for malformed headers
      if (/^#{7,}/.test(line)) {
        validation.warnings.push(`Line ${index + 1}: Header too deep (max 6 levels)`);
        validation.score -= 2;
      }
      
      // Check for suspicious patterns in regular text
      if (/(?:javascript:|data:|file:)/i.test(line)) {
        validation.errors.push(`Line ${index + 1}: Potentially dangerous URI scheme`);
        validation.score -= 15;
      }
    }
  });

  validation.isValid = validation.errors.length === 0;
  return validation;
}

module.exports = {
  analyzeSkillStructure,
  validateSkillFormat,
  EXPECTED_SECTIONS,
  DANGEROUS_PERMISSIONS,
  SUSPICIOUS_INSTRUCTIONS
};