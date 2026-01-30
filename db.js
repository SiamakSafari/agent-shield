// SQLite database setup and operations for AgentShield
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

class AgentShieldDB {
  constructor(dbPath = './agent-shield.db') {
    this.dbPath = dbPath;
    this.init();
  }

  init() {
    // Ensure database directory exists
    const dbDir = path.dirname(this.dbPath);
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }

    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL');
    
    this.createTables();
    this.setupIndexes();
  }

  createTables() {
    // Scan results table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        source TEXT NOT NULL,
        source_type TEXT NOT NULL, -- 'inline', 'url', 'github'
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
      )
    `);

    // Detailed findings table
    this.db.exec(`
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
      )
    `);

    // API usage tracking
    this.db.exec(`
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
      )
    `);

    // API keys and rate limiting
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS api_keys (
        key_id TEXT PRIMARY KEY,
        key_hash TEXT UNIQUE NOT NULL,
        user_id TEXT NOT NULL,
        plan TEXT DEFAULT 'free', -- 'free', 'pro', 'enterprise'
        daily_limit INTEGER DEFAULT 10,
        monthly_limit INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used_at DATETIME,
        is_active BOOLEAN DEFAULT TRUE
      )
    `);

    // Rate limiting tracking
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key TEXT,
        ip_address TEXT,
        endpoint TEXT,
        request_count INTEGER DEFAULT 1,
        window_start DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(api_key, ip_address, endpoint, window_start)
      )
    `);

    // Statistics tracking
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT UNIQUE NOT NULL,
        total_scans INTEGER DEFAULT 0,
        threats_detected INTEGER DEFAULT 0,
        clean_skills INTEGER DEFAULT 0,
        unique_users INTEGER DEFAULT 0,
        avg_trust_score REAL DEFAULT 0,
        avg_scan_duration_ms REAL DEFAULT 0
      )
    `);
  }

  setupIndexes() {
    // Performance indexes
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_scans_threat_level ON scans(threat_level)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_api_usage_timestamp ON api_usage(timestamp)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_api_usage_api_key ON api_usage(api_key)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_rate_limits_api_key ON rate_limits(api_key)');
    this.db.exec('CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start)');
  }

  // Save scan result to database
  saveScan(scanResult, metadata = {}) {
    const insertScan = this.db.prepare(`
      INSERT INTO scans (
        id, timestamp, source, source_type, threat_level, trust_score, badge,
        findings_count, critical_count, high_count, medium_count, low_count,
        scan_duration_ms, lines_scanned, patterns_checked, user_id, ip_address, user_agent
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertFinding = this.db.prepare(`
      INSERT INTO findings (
        scan_id, severity, category, title, description, evidence, line_number, remediation, pattern_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const transaction = this.db.transaction((result, meta) => {
      const criticalCount = result.findings.filter(f => f.severity === 'critical').length;
      const highCount = result.findings.filter(f => f.severity === 'high').length;
      const mediumCount = result.findings.filter(f => f.severity === 'medium').length;
      const lowCount = result.findings.filter(f => f.severity === 'low').length;

      // Determine source type
      let sourceType = 'inline';
      if (result.source.startsWith('http')) {
        sourceType = result.source.includes('github.com') ? 'github' : 'url';
      }

      insertScan.run(
        result.scanId,
        result.timestamp,
        result.source,
        sourceType,
        result.threatLevel,
        result.trustScore,
        result.badge,
        result.findings.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        result.metadata?.scanDurationMs,
        result.metadata?.linesScanned,
        result.metadata?.patternsChecked,
        meta.userId,
        meta.ipAddress,
        meta.userAgent
      );

      // Save individual findings
      result.findings.forEach(finding => {
        insertFinding.run(
          result.scanId,
          finding.severity,
          finding.category,
          finding.title,
          finding.description,
          finding.evidence,
          finding.line,
          finding.remediation,
          finding.patternId
        );
      });
    });

    transaction(scanResult, metadata);
    this.updateDailyStats();
  }

  // Retrieve scan result by ID
  getScan(scanId) {
    const scanQuery = this.db.prepare('SELECT * FROM scans WHERE id = ?');
    const findingsQuery = this.db.prepare('SELECT * FROM findings WHERE scan_id = ? ORDER BY severity, line_number');

    const scan = scanQuery.get(scanId);
    if (!scan) return null;

    const findings = findingsQuery.all(scanId);

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
        patternId: f.pattern_id
      })),
      metadata: {
        scanDurationMs: scan.scan_duration_ms,
        linesScanned: scan.lines_scanned,
        patternsChecked: scan.patterns_checked
      }
    };
  }

  // Get recent scans for a user
  getUserScans(userId, limit = 50) {
    const query = this.db.prepare(`
      SELECT id, timestamp, source, threat_level, trust_score, badge, findings_count
      FROM scans 
      WHERE user_id = ? 
      ORDER BY timestamp DESC 
      LIMIT ?
    `);
    
    return query.all(userId, limit);
  }

  // Get global statistics
  getStats() {
    const today = new Date().toISOString().split('T')[0];
    const statsQuery = this.db.prepare('SELECT * FROM stats WHERE date = ?');
    
    let todayStats = statsQuery.get(today);
    if (!todayStats) {
      this.updateDailyStats();
      todayStats = statsQuery.get(today);
    }

    const totalStats = this.db.prepare(`
      SELECT 
        COUNT(*) as total_scans,
        SUM(CASE WHEN threat_level != 'clean' THEN 1 ELSE 0 END) as threats_detected,
        SUM(CASE WHEN threat_level = 'clean' THEN 1 ELSE 0 END) as clean_skills,
        AVG(trust_score) as avg_trust_score,
        AVG(scan_duration_ms) as avg_scan_duration_ms
      FROM scans
    `).get();

    return {
      today: todayStats || {
        total_scans: 0,
        threats_detected: 0,
        clean_skills: 0,
        avg_trust_score: 0
      },
      allTime: totalStats
    };
  }

  // Update daily statistics
  updateDailyStats() {
    const today = new Date().toISOString().split('T')[0];
    
    const dailyStats = this.db.prepare(`
      SELECT 
        COUNT(*) as total_scans,
        SUM(CASE WHEN threat_level != 'clean' THEN 1 ELSE 0 END) as threats_detected,
        SUM(CASE WHEN threat_level = 'clean' THEN 1 ELSE 0 END) as clean_skills,
        COUNT(DISTINCT user_id) as unique_users,
        AVG(trust_score) as avg_trust_score,
        AVG(scan_duration_ms) as avg_scan_duration_ms
      FROM scans 
      WHERE DATE(created_at) = ?
    `).get(today);

    const upsertStats = this.db.prepare(`
      INSERT INTO stats (date, total_scans, threats_detected, clean_skills, unique_users, avg_trust_score, avg_scan_duration_ms)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(date) DO UPDATE SET
        total_scans = excluded.total_scans,
        threats_detected = excluded.threats_detected,
        clean_skills = excluded.clean_skills,
        unique_users = excluded.unique_users,
        avg_trust_score = excluded.avg_trust_score,
        avg_scan_duration_ms = excluded.avg_scan_duration_ms
    `);

    upsertStats.run(
      today,
      dailyStats.total_scans || 0,
      dailyStats.threats_detected || 0,
      dailyStats.clean_skills || 0,
      dailyStats.unique_users || 0,
      dailyStats.avg_trust_score || 0,
      dailyStats.avg_scan_duration_ms || 0
    );
  }

  // Log API usage
  logAPIUsage(apiKey, endpoint, method, ipAddress, userAgent, responseTimeMs, statusCode, errorMessage = null) {
    const insert = this.db.prepare(`
      INSERT INTO api_usage (api_key, endpoint, method, ip_address, user_agent, response_time_ms, status_code, error_message)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    insert.run(apiKey, endpoint, method, ipAddress, userAgent, responseTimeMs, statusCode, errorMessage);
  }

  // Check rate limit
  checkRateLimit(apiKey, ipAddress, endpoint, windowMinutes = 60, limit = 10) {
    const windowStart = new Date(Date.now() - windowMinutes * 60 * 1000).toISOString();
    
    const currentCount = this.db.prepare(`
      SELECT COUNT(*) as count 
      FROM api_usage 
      WHERE (api_key = ? OR ip_address = ?) 
        AND endpoint = ? 
        AND timestamp > ?
    `).get(apiKey, ipAddress, endpoint, windowStart);

    return {
      allowed: currentCount.count < limit,
      current: currentCount.count,
      limit: limit,
      resetTime: new Date(Date.now() + windowMinutes * 60 * 1000)
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