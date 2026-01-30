// SVG badge generator for security scan results
// Generates embeddable badges for marketplaces and repositories

function generateBadgeSVG(badgeType, trustScore) {
  const badges = {
    'verified-safe': {
      color: '#4CAF50',
      textColor: '#FFFFFF',
      label: 'AgentShield',
      message: 'Verified Safe',
      icon: '🛡️'
    },
    'caution': {
      color: '#FF9800', 
      textColor: '#FFFFFF',
      label: 'AgentShield',
      message: 'Use Caution',
      icon: '⚠️'
    },
    'dangerous': {
      color: '#F44336',
      textColor: '#FFFFFF', 
      label: 'AgentShield',
      message: 'Dangerous',
      icon: '🚨'
    }
  };

  const badge = badges[badgeType] || badges['caution'];
  const width = calculateBadgeWidth(badge.label, badge.message);

  return `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${width}" height="20" role="img" aria-label="${badge.label}: ${badge.message}">
  <title>${badge.label}: ${badge.message}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="78" height="20" fill="#555"/>
    <rect x="78" width="${width - 78}" height="20" fill="${badge.color}"/>
    <rect width="${width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="400" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="680">${badge.label}</text>
    <text x="400" y="140" transform="scale(.1)" fill="#fff" textLength="680">${badge.label}</text>
    <text aria-hidden="true" x="${(78 + (width - 78) / 2) * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(width - 88) * 10}">${badge.message}</text>
    <text x="${(78 + (width - 78) / 2) * 10}" y="140" transform="scale(.1)" fill="#fff" textLength="${(width - 88) * 10}">${badge.message}</text>
  </g>
</svg>`;
}

function generateTrustScoreBadge(trustScore) {
  let color, message;
  
  if (trustScore >= 90) {
    color = '#4CAF50';
    message = 'Excellent';
  } else if (trustScore >= 75) {
    color = '#8BC34A';
    message = 'Good';
  } else if (trustScore >= 60) {
    color = '#FF9800';
    message = 'Fair';
  } else if (trustScore >= 40) {
    color = '#FF5722';
    message = 'Poor';
  } else {
    color = '#F44336';
    message = 'Critical';
  }

  const scoreText = `${trustScore}/100`;
  const width = 120;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" role="img" aria-label="Trust Score: ${scoreText}">
  <title>Trust Score: ${scoreText}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="75" height="20" fill="#555"/>
    <rect x="75" width="${width - 75}" height="20" fill="${color}"/>
    <rect width="${width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="385" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="650">Trust Score</text>
    <text x="385" y="140" transform="scale(.1)" fill="#fff" textLength="650">Trust Score</text>
    <text aria-hidden="true" x="975" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="350">${scoreText}</text>
    <text x="975" y="140" transform="scale(.1)" fill="#fff" textLength="350">${scoreText}</text>
  </g>
</svg>`;
}

function generateCompactBadge(badgeType, trustScore) {
  const badges = {
    'verified-safe': { color: '#4CAF50', symbol: '✓', text: 'Safe' },
    'caution': { color: '#FF9800', symbol: '⚠', text: 'Caution' },
    'dangerous': { color: '#F44336', symbol: '✗', text: 'Danger' }
  };

  const badge = badges[badgeType] || badges['caution'];
  const width = 70;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" role="img" aria-label="Security: ${badge.text}">
  <title>Security: ${badge.text}</title>
  <rect width="${width}" height="20" rx="3" fill="${badge.color}"/>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text x="350" y="140" transform="scale(.1)" fill="#fff">${badge.symbol} ${badge.text}</text>
  </g>
</svg>`;
}

function generateDetailedBadge(scanResult) {
  const { threatLevel, trustScore, findings } = scanResult;
  
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  
  let color = '#4CAF50';
  let status = 'Clean';
  
  if (criticalCount > 0) {
    color = '#F44336';
    status = 'Critical Issues';
  } else if (highCount > 0) {
    color = '#FF5722';
    status = 'High Risk';
  } else if (threatLevel === 'medium') {
    color = '#FF9800';
    status = 'Medium Risk';
  } else if (threatLevel === 'low') {
    color = '#FFC107';
    status = 'Low Risk';
  }

  const width = 160;
  const scoreText = `${trustScore}%`;
  
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="20" role="img" aria-label="AgentShield: ${status} (${scoreText})">
  <title>AgentShield: ${status} (${scoreText})</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="78" height="20" fill="#555"/>
    <rect x="78" width="${width - 78}" height="20" fill="${color}"/>
    <rect width="${width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="100">
    <text aria-hidden="true" x="400" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="680">AgentShield</text>
    <text x="400" y="140" transform="scale(.1)" fill="#fff" textLength="680">AgentShield</text>
    <text aria-hidden="true" x="${(78 + (width - 78) / 2) * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">${status} ${scoreText}</text>
    <text x="${(78 + (width - 78) / 2) * 10}" y="140" transform="scale(.1)" fill="#fff">${status} ${scoreText}</text>
  </g>
</svg>`;
}

function calculateBadgeWidth(label, message) {
  // Approximate character width calculation for badge sizing
  const charWidth = 6;
  const padding = 20;
  const labelWidth = label.length * charWidth + 10;
  const messageWidth = message.length * charWidth + 10;
  return labelWidth + messageWidth + padding;
}

// Generate a markdown snippet for embedding badges
function generateMarkdownSnippet(scanId, badgeType, baseUrl) {
  const badgeUrl = `${baseUrl}/badges/${scanId}`;
  const reportUrl = `${baseUrl}/report/${scanId}`;
  
  return `[![AgentShield Security Badge](${badgeUrl})](${reportUrl})`;
}

// Generate HTML snippet for embedding badges
function generateHTMLSnippet(scanId, badgeType, baseUrl) {
  const badgeUrl = `${baseUrl}/badges/${scanId}`;
  const reportUrl = `${baseUrl}/report/${scanId}`;
  
  return `<a href="${reportUrl}"><img src="${badgeUrl}" alt="AgentShield Security Badge" /></a>`;
}

// Generate dynamic badge based on current scan results
function generateDynamicBadge(scanResult, style = 'default') {
  switch (style) {
    case 'compact':
      return generateCompactBadge(scanResult.badge, scanResult.trustScore);
    case 'detailed':
      return generateDetailedBadge(scanResult);
    case 'trust-score':
      return generateTrustScoreBadge(scanResult.trustScore);
    default:
      return generateBadgeSVG(scanResult.badge, scanResult.trustScore);
  }
}

// Generate all badge variants for a scan result
function generateAllBadges(scanResult) {
  return {
    default: generateBadgeSVG(scanResult.badge, scanResult.trustScore),
    compact: generateCompactBadge(scanResult.badge, scanResult.trustScore),
    detailed: generateDetailedBadge(scanResult),
    trustScore: generateTrustScoreBadge(scanResult.trustScore)
  };
}

module.exports = {
  generateBadgeSVG,
  generateTrustScoreBadge,
  generateCompactBadge,
  generateDetailedBadge,
  generateDynamicBadge,
  generateAllBadges,
  generateMarkdownSnippet,
  generateHTMLSnippet
};