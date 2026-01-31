// Database setup and operations for AgentShield
// Supports Turso (libsql) with local SQLite fallback
const { createClient } = require('@libsql/client');
const path = require('path');
const fs = require('fs');

class AgentShieldDB {
  constructor(options = {}) {
    this.options = options;
    this.db = null;
  }

  async init() {
    const tursoUrl = process.env.TURSO_DATABASE_URL;
    const tursoToken = process.env.TURSO_AUTH_TOKEN;

    if (tursoUrl && tursoToken) {
      // Use Turso remote database
      this.db = createClient({
        url: tursoUrl,
        authToken: tursoToken,
      });
      console.log('📡 Connected to Turso database');
    } else {
      // Fall back to local SQLite file via libsql
      const dbPath = this.options.dbPath || process.env.DATABASE_PATH || './agent-shield.db';
      const dbDir = path.dirname(dbPath);
      if (!fs.existsSync(dbDir)) {
        fs.mkdirSync(dbDir, { recursive: true });
      }
      this.db = createClient({
        url: `file:${dbPath}`,
      });
      console.log(`💾 Using local SQLite database: ${dbPath}`);
    }

    await this.createTables();
    await this.setupIndexes();
  }

  async createTables() {
    await this.db.executeMultiple(`
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        source TEXT NOT NULL,
        source_type TEXT NOT NULL,
        threat_level TEXT NOT NULL,
        trust_score INTEGER NOT NULL,
        badge TEXT NOT NULL,
        findings_count INTEGER NOT NULL,
        critical_count INTEGER NOT NULL,
        high_count INTEGER NOT NULL,
        medium_count INTEGER NOT NULL,
        low_count INTEGER NOT NULL,
        scan_duration_ms INTEGER,
        lines_scanned INTEGER,
        patterns_checked INTEGER,
        user_id TEXT,
        ip_address TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        evidence TEXT,
        line_number INTEGER,
        remediation TEXT,
        pattern_id TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
      );

      CREATE TABLE IF NOT EXISTS api_usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key TEXT,
        endpoint TEXT NOT NULL,
        method TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        response_time_ms INTEGER,
        status_code INTEGER,
        error_message TEXT
      );

      CREATE TABLE IF NOT EXISTS api_keys (
        key_id TEXT PRIMARY KEY,
        key_hash TEXT UNIQUE NOT NULL,
        user_id TEXT NOT NULL,
        plan TEXT DEFAULT 'free',
        daily_limit INTEGER DEFAULT 10,
        monthly_limit INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used_at DATETIME,
        is_active BOOLEAN DEFAULT TRUE
      );

      CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key TEXT,
        ip_address TEXT,
        endpoint TEXT,
        request_count INTEGER DEFAULT 1,
        window_start DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(api_key, ip_address, endpoint, window_start)
      );

      CREATE TABLE IF NOT EXISTS stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT UNIQUE NOT NULL,
        total_scans INTEGER DEFAULT 0,
        threats_detected INTEGER DEFAULT 0,
        clean_skills INTEGER DEFAULT 0,
        unique_users INTEGER DEFAULT 0,
        avg_trust_score REAL DEFAULT 0,
        avg_scan_duration_ms REAL DEFAULT 0
      );
    `);
  }

  async setupIndexes() {
    await this.db.executeMultiple(`
      CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
      CREATE INDEX IF NOT EXISTS idx_scans_threat_level ON scans(threat_level);
      CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
      CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
      CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
      CREATE INDEX IF NOT EXISTS idx_api_usage_timestamp ON api_usage(timestamp);
      CREATE INDEX IF NOT EXISTS idx_api_usage_api_key ON api_usage(api_key);
      CREATE INDEX IF NOT EXISTS idx_rate_limits_api_key ON rate_limits(api_key);
      CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);
    `);
  }

  // Helper: execute a query and return first row (like .get())
  async get(sql, args = []) {
    const result = await this.db.execute({ sql, args });
    return result.rows.length > 0 ? result.rows[0] : null;
  }

  // Helper: execute a query and return all rows (like .all())
  async all(sql, args = []) {
    const result = await this.db.execute({ sql, args });
    return result.rows;
  }

  // Helper: execute a statement (like .run())
  async run(sql, args = []) {
    const result = await this.db.execute({ sql, args });
    return { changes: result.rowsAffected, lastInsertRowid: result.lastInsertRowid };
  }

  // Save scan result to database
  async saveScan(scanResult, metadata = {}) {
    const criticalCount = scanResult.findings.filter(f => f.severity === 'critical').length;
    const highCount = scanResult.findings.filter(f => f.severity === 'high').length;
    const mediumCount = scanResult.findings.filter(f => f.severity === 'medium').length;
    const lowCount = scanResult.findings.filter(f => f.severity === 'low').length;

    let sourceType = 'inline';
    if (scanResult.source.startsWith('http')) {
      sourceType = scanResult.source.includes('github.com') ? 'github' : 'url';
    }

    // Build batch of statements for transaction
    const statements = [
      {
        sql: `INSERT INTO scans (
          id, timestamp, source, source_type, threat_level, trust_score, badge,
          findings_count, critical_count, high_count, medium_count, low_count,
          scan_duration_ms, lines_scanned, patterns_checked, user_id, ip_address, user_agent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          scanResult.scanId,
          scanResult.timestamp,
          scanResult.source,
          sourceType,
          scanResult.threatLevel,
          scanResult.trustScore,
          scanResult.badge,
          scanResult.findings.length,
          criticalCount,
          highCount,
          mediumCount,
          lowCount,
          scanResult.metadata?.scanDurationMs || null,
          scanResult.metadata?.linesScanned || null,
          scanResult.metadata?.patternsChecked || null,
          metadata.userId || null,
          metadata.ipAddress || null,
          metadata.userAgent || null,
        ],
      },
    ];

    // Add finding inserts
    for (const finding of scanResult.findings) {
      statements.push({
        sql: `INSERT INTO findings (
          scan_id, severity, category, title, description, evidence, line_number, remediation, pattern_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        args: [
          scanResult.scanId,
          finding.severity,
          finding.category,
          finding.title,
          finding.description,
          finding.evidence || null,
          finding.line || null,
          finding.remediation || null,
          finding.patternId || null,
        ],
      });
    }

    await this.db.batch(statements, 'write');
    await this.updateDailyStats();
  }

  // Retrieve scan result by ID
  async getScan(scanId) {
    const scan = await this.get('SELECT * FROM scans WHERE id = ?', [scanId]);
    if (!scan) return null;

    const findings = await this.all(
      'SELECT * FROM findings WHERE scan_id = ? ORDER BY severity, line_number',
      [scanId]
    );

    return {
      scanId: scan.id,
      timestamp: scan.timestamp,
      source: scan.source,
      threatLevel: scan.threat_level,
      trustScore: scan.trust_score,
      badge: scan.badge,
      findings: findings.map(f => ({
        severity: f.severity,
        category: f.category,
        title: f.title,
        description: f.description,
        evidence: f.evidence,
        line: f.line_number,
        remediation: f.remediation,
        patternId: f.pattern_id,
      })),
      metadata: {
        scanDurationMs: scan.scan_duration_ms,
        linesScanned: scan.lines_scanned,
        patternsChecked: scan.patterns_checked,
      },
    };
  }

  // Get recent scans for a user
  async getUserScans(userId, limit = 50) {
    return await this.all(
      `SELECT id, timestamp, source, threat_level, trust_score, badge, findings_count
       FROM scans
       WHERE user_id = ?
       ORDER BY timestamp DESC
       LIMIT ?`,
      [userId, limit]
    );
  }

  // Get global statistics
  async getStats() {
    const today = new Date().toISOString().split('T')[0];
    let todayStats = await this.get('SELECT * FROM stats WHERE date = ?', [today]);

    if (!todayStats) {
      await this.updateDailyStats();
      todayStats = await this.get('SELECT * FROM stats WHERE date = ?', [today]);
    }

    const totalStats = await this.get(`
      SELECT
        COUNT(*) as total_scans,
        SUM(CASE WHEN threat_level != 'clean' THEN 1 ELSE 0 END) as threats_detected,
        SUM(CASE WHEN threat_level = 'clean' THEN 1 ELSE 0 END) as clean_skills,
        AVG(trust_score) as avg_trust_score,
        AVG(scan_duration_ms) as avg_scan_duration_ms
      FROM scans
    `);

    return {
      today: todayStats || {
        total_scans: 0,
        threats_detected: 0,
        clean_skills: 0,
        avg_trust_score: 0,
      },
      allTime: totalStats,
    };
  }

  // Update daily statistics
  async updateDailyStats() {
    const today = new Date().toISOString().split('T')[0];

    const dailyStats = await this.get(
      `SELECT
        COUNT(*) as total_scans,
        SUM(CASE WHEN threat_level != 'clean' THEN 1 ELSE 0 END) as threats_detected,
        SUM(CASE WHEN threat_level = 'clean' THEN 1 ELSE 0 END) as clean_skills,
        COUNT(DISTINCT user_id) as unique_users,
        AVG(trust_score) as avg_trust_score,
        AVG(scan_duration_ms) as avg_scan_duration_ms
      FROM scans
      WHERE DATE(created_at) = ?`,
      [today]
    );

    await this.run(
      `INSERT INTO stats (date, total_scans, threats_detected, clean_skills, unique_users, avg_trust_score, avg_scan_duration_ms)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(date) DO UPDATE SET
         total_scans = excluded.total_scans,
         threats_detected = excluded.threats_detected,
         clean_skills = excluded.clean_skills,
         unique_users = excluded.unique_users,
         avg_trust_score = excluded.avg_trust_score,
         avg_scan_duration_ms = excluded.avg_scan_duration_ms`,
      [
        today,
        dailyStats?.total_scans || 0,
        dailyStats?.threats_detected || 0,
        dailyStats?.clean_skills || 0,
        dailyStats?.unique_users || 0,
        dailyStats?.avg_trust_score || 0,
        dailyStats?.avg_scan_duration_ms || 0,
      ]
    );
  }

  // Log API usage
  async logAPIUsage(apiKey, endpoint, method, ipAddress, userAgent, responseTimeMs, statusCode, errorMessage = null) {
    await this.run(
      `INSERT INTO api_usage (api_key, endpoint, method, ip_address, user_agent, response_time_ms, status_code, error_message)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [apiKey, endpoint, method, ipAddress, userAgent, responseTimeMs, statusCode, errorMessage]
    );
  }

  // Check rate limit
  async checkRateLimit(apiKey, ipAddress, endpoint, windowMinutes = 60, limit = 10) {
    const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000).toISOString();

    const currentCount = await this.get(
      `SELECT COUNT(*) as count
       FROM api_usage
       WHERE (api_key = ? OR ip_address = ?)
         AND endpoint = ?
         AND timestamp > ?`,
      [apiKey, ipAddress, endpoint, windowStart]
    );

    return {
      allowed: currentCount.count < limit,
      current: currentCount.count,
      limit: limit,
      resetTime: new Date(Date.now() + windowMinutes * 60 * 1000),
    };
  }

  // Close database connection
  close() {
    if (this.db) {
      this.db.close();
    }
  }
}

module.exports = { AgentShieldDB };
