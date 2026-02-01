# Public Comment: NIST RFI on AI Agent Security (NIST-2025-0035)
## Submitted by: AgentShield
## Date: [To be submitted before March 9, 2026]

---

**RE: Request for Information on Securing AI Agent Systems**

To the National Institute of Standards and Technology:

We appreciate the opportunity to comment on the security challenges posed by autonomous AI agent systems. As the developers of AgentShield — an open security scanning platform that has analyzed thousands of AI agent skills and tool integrations — we offer observations grounded in direct operational experience.

### 1. The Trust Gap in Agent Tool Use

AI agents increasingly consume third-party tools, APIs, and skills through protocols like the Model Context Protocol (MCP). Our scanning of agent skills across public marketplaces reveals a consistent pattern: **the majority of tool integrations lack any form of security verification before execution.**

Agents routinely:
- Execute code from unverified sources
- Pass credentials to third-party endpoints without validation
- Accept responses without integrity checking
- Grant file system and network access to untrusted tools

This is analogous to the pre-SSL web — transactions happening over channels with no verification infrastructure.

### 2. Observed Threat Patterns

From our analysis of agent skills across public repositories and marketplaces, the most prevalent security risks include:

- **Credential exfiltration via environment variable access** — Skills that read API keys, tokens, and secrets, then transmit them to external endpoints
- **Prompt injection through tool responses** — Malicious payloads embedded in API responses that redirect agent behavior
- **Obfuscated payloads** — Base64 encoding, string concatenation, and dynamic code generation used to evade static analysis
- **Excessive permission requests** — Skills requesting file system, network, and shell access beyond their stated function
- **Data exfiltration channels** — Encoding sensitive data in URLs, headers, or DNS queries to bypass content filtering

We have catalogued 464+ distinct attack patterns across 11 categories of obfuscation techniques.

### 3. Recommendations

**a. Mandatory Security Scanning for Agent Tool Marketplaces**
Platforms distributing agent tools and skills should implement automated security scanning before publication — analogous to app store review processes. Static analysis can catch the majority of credential theft, data exfiltration, and obfuscated payload patterns.

**b. Trust Scoring and Certification Standards**
The ecosystem needs a standardized trust scoring framework for agent tools. We propose a model similar to SSL certificates: tools that pass security verification receive a machine-readable trust badge that agents can verify programmatically before execution.

**c. Runtime Sandboxing Requirements**
Agent tool execution should occur in sandboxed environments with explicit permission boundaries. Skills should declare required permissions upfront (file access, network access, environment variables), and agents should enforce least-privilege execution.

**d. Provenance and Integrity Verification**
Agent tools should support cryptographic signing and hash verification to ensure code integrity between publication and execution. Supply chain attacks are a demonstrated risk in traditional package ecosystems; the agent ecosystem inherits these risks with the added complexity of autonomous execution.

**e. Continuous Monitoring, Not Point-in-Time Assessment**
APIs and tool endpoints change. A skill that passes security review at publication may become compromised through upstream dependency changes or endpoint modifications. Continuous scanning infrastructure is essential.

### 4. Industry Alignment

Our recommendations align with existing frameworks including:
- OWASP LLM Top 10 (particularly LLM07: Insecure Plugin Design)
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
- NIST AI RMF (AI 100-1)
- The EU AI Act's requirements for high-risk AI system transparency

### 5. About AgentShield

AgentShield provides free, open security scanning for AI agent skills. Our platform analyzes code and tool integrations against 464+ threat patterns using 11-pass deobfuscation, producing trust scores and actionable vulnerability reports. We serve the independent developer and small team segment of the AI agent ecosystem — the builders most likely to lack dedicated security resources.

We welcome the opportunity to collaborate with NIST on developing practical security standards for the AI agent ecosystem.

Respectfully submitted,

**AgentShield**
https://agent-shield-production.up.railway.app
GitHub: github.com/SiamakSafari/agent-shield
