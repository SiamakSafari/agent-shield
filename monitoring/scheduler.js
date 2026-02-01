// Background monitoring scheduler — periodic scanning of monitored skill stacks
const crypto = require('crypto');
const fetch = require('node-fetch');
const { AgentShieldScanner } = require('../scanner');

const scanner = new AgentShieldScanner();

// Scan interval per plan (in ms)
const SCAN_INTERVALS = {
  free:       24 * 60 * 60 * 1000,  // 24 hours
  pro:         6 * 60 * 60 * 1000,  //  6 hours
  enterprise:  1 * 60 * 60 * 1000   //  1 hour
};

// Trust score drop threshold for critical alert
const SCORE_DROP_THRESHOLD = 10;

/**
 * Scan a single skill URL and return results
 */
async function scanSkill(url) {
  try {
    const response = await fetch(url, { timeout: 30000 });
    if (!response.ok) {
      return { error: true, message: `HTTP ${response.status}: ${response.statusText}`, unreachable: true };
    }
    const content = await response.text();
    const contentHash = crypto.createHash('sha256').update(content).digest('hex');
    const scanResult = await scanner.scanContent({ content, source: url });
    return {
      error: false,
      content,
      contentHash,
      scanResult,
      trustScore: scanResult.trustScore,
      threatLevel: scanResult.threatLevel,
      scanId: scanResult.scanId
    };
  } catch (err) {
    return { error: true, message: err.message, unreachable: true };
  }
}

/**
 * Create an alert and fire webhooks
 */
async function createAlert(db, monitorId, { type, severity, message, skillUrl, oldScore, newScore }) {
  const alertId = crypto.randomUUID();
  const now = new Date().toISOString();

  await db.run(
    `INSERT INTO alerts (id, monitor_id, type, severity, message, skill_url, old_score, new_score, acknowledged, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
    [alertId, monitorId, type, severity, message, skillUrl || null, oldScore ?? null, newScore ?? null, now]
  );

  // Fire webhooks
  const webhooks = await db.all(
    'SELECT id, url, secret FROM webhooks WHERE monitor_id = ? AND is_active = 1',
    [monitorId]
  );

  const payload = JSON.stringify({
    alertId,
    monitorId,
    type,
    severity,
    message,
    skillUrl,
    oldScore,
    newScore,
    timestamp: now
  });

  for (const wh of webhooks) {
    try {
      const signature = crypto.createHmac('sha256', wh.secret).update(payload).digest('hex');
      await fetch(wh.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-AgentShield-Signature': signature,
          'X-AgentShield-Event': type
        },
        body: payload,
        timeout: 10000
      });
    } catch (err) {
      console.error(`Webhook delivery failed for ${wh.id}:`, err.message);
    }
  }

  return alertId;
}

/**
 * Scan all skills in a single monitor, returning summary results
 */
async function scanMonitor(db, monitorId) {
  const skills = await db.all(
    'SELECT id, url, content_hash, last_trust_score FROM monitor_skills WHERE monitor_id = ?',
    [monitorId]
  );

  const results = [];

  for (const skill of skills) {
    const result = await scanSkill(skill.url);
    const now = new Date().toISOString();

    if (result.error) {
      // Skill unreachable
      await createAlert(db, monitorId, {
        type: 'skill_unreachable',
        severity: 'warning',
        message: `Skill became unreachable: ${skill.url} — ${result.message}`,
        skillUrl: skill.url,
        oldScore: skill.last_trust_score,
        newScore: null
      });

      await db.run(
        `INSERT INTO scan_history (id, monitor_id, skill_url, trust_score, threat_level, content_hash, scan_id, scanned_at, error)
         VALUES (?, ?, ?, NULL, NULL, NULL, NULL, ?, ?)`,
        [crypto.randomUUID(), monitorId, skill.url, now, result.message]
      );

      results.push({ url: skill.url, error: true, message: result.message });
      continue;
    }

    const contentChanged = skill.content_hash && skill.content_hash !== result.contentHash;
    const scoreDropped = skill.last_trust_score !== null &&
                         skill.last_trust_score !== undefined &&
                         result.trustScore < skill.last_trust_score;

    // Save scan result to main scans table too
    if (result.scanResult && !result.scanResult.error) {
      try {
        await db.saveScan(result.scanResult, {
          userId: 'monitor:' + monitorId,
          ipAddress: 'system',
          userAgent: 'AgentShield-Monitor/1.0'
        });
      } catch (e) {
        // Don't fail the whole scan if this errors
        console.error('Failed to save scan to main table:', e.message);
      }
    }

    // Save to scan_history
    await db.run(
      `INSERT INTO scan_history (id, monitor_id, skill_url, trust_score, threat_level, content_hash, scan_id, scanned_at, error)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
      [crypto.randomUUID(), monitorId, skill.url, result.trustScore, result.threatLevel, result.contentHash, result.scanId, now]
    );

    // Update skill record
    await db.run(
      'UPDATE monitor_skills SET content_hash = ?, last_trust_score = ?, last_scanned_at = ? WHERE id = ?',
      [result.contentHash, result.trustScore, now, skill.id]
    );

    // Generate alerts
    if (contentChanged) {
      const severity = scoreDropped && (skill.last_trust_score - result.trustScore >= SCORE_DROP_THRESHOLD)
        ? 'critical' : 'info';

      await createAlert(db, monitorId, {
        type: 'content_changed',
        severity,
        message: `Skill content changed: ${skill.url}. Score: ${skill.last_trust_score ?? '?'} → ${result.trustScore}`,
        skillUrl: skill.url,
        oldScore: skill.last_trust_score,
        newScore: result.trustScore
      });
    }

    if (scoreDropped && (skill.last_trust_score - result.trustScore >= SCORE_DROP_THRESHOLD)) {
      await createAlert(db, monitorId, {
        type: 'score_dropped',
        severity: 'critical',
        message: `Trust score dropped significantly for ${skill.url}: ${skill.last_trust_score} → ${result.trustScore}`,
        skillUrl: skill.url,
        oldScore: skill.last_trust_score,
        newScore: result.trustScore
      });
    }

    // First scan — no previous hash
    if (!skill.content_hash) {
      await createAlert(db, monitorId, {
        type: 'initial_scan',
        severity: 'info',
        message: `Initial scan complete for ${skill.url}. Trust score: ${result.trustScore}/100`,
        skillUrl: skill.url,
        oldScore: null,
        newScore: result.trustScore
      });
    }

    results.push({
      url: skill.url,
      trustScore: result.trustScore,
      threatLevel: result.threatLevel,
      contentChanged,
      scanId: result.scanId
    });
  }

  // Update monitor timestamp
  await db.run(
    'UPDATE monitors SET updated_at = ? WHERE id = ?',
    [new Date().toISOString(), monitorId]
  );

  return results;
}

/**
 * Run the background scan cycle — checks all active monitors due for scanning
 */
async function runScanCycle(db) {
  const now = Date.now();
  console.log(`🔄 [Monitor] Starting scan cycle at ${new Date(now).toISOString()}`);

  const monitors = await db.all(
    'SELECT id, plan, updated_at FROM monitors WHERE is_active = 1'
  );

  let scanned = 0;
  let skipped = 0;

  for (const monitor of monitors) {
    const interval = SCAN_INTERVALS[monitor.plan] || SCAN_INTERVALS.free;
    const lastUpdate = monitor.updated_at ? new Date(monitor.updated_at).getTime() : 0;

    if (now - lastUpdate < interval) {
      skipped++;
      continue;
    }

    try {
      console.log(`🔍 [Monitor] Scanning monitor ${monitor.id} (plan: ${monitor.plan})`);
      await scanMonitor(db, monitor.id);
      scanned++;
    } catch (err) {
      console.error(`❌ [Monitor] Failed to scan monitor ${monitor.id}:`, err.message);
    }
  }

  console.log(`✅ [Monitor] Scan cycle complete. Scanned: ${scanned}, Skipped: ${skipped}, Total: ${monitors.length}`);
}

/**
 * Start the background scheduler
 */
function startScheduler(db) {
  const checkInterval = parseInt(process.env.MONITOR_CHECK_INTERVAL_MS) || 15 * 60 * 1000; // Check every 15 min

  console.log(`📡 [Monitor] Background scheduler started (check interval: ${checkInterval / 1000}s)`);

  // Run first cycle after 30 seconds (let server boot)
  setTimeout(() => runScanCycle(db), 30000);

  // Then run on interval
  const intervalId = setInterval(() => runScanCycle(db), checkInterval);

  // Return handle for cleanup
  return intervalId;
}

module.exports = { startScheduler, runScanCycle, scanMonitor, scanSkill, createAlert };
