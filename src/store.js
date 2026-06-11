// Local-only persistence for claude-shield: session event logs and reports.
// Everything lives under ~/.claude-shield (override with CLAUDE_SHIELD_HOME).
// Nothing is ever sent anywhere — that is the product's core promise.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export function shieldHome() {
  return process.env.CLAUDE_SHIELD_HOME || path.join(os.homedir(), '.claude-shield');
}

function sessionFile(sessionId) {
  return path.join(shieldHome(), 'sessions', `${sessionId || 'unknown'}.jsonl`);
}

export function logEvent(sessionId, event) {
  try {
    const file = sessionFile(sessionId);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, JSON.stringify({ ts: new Date().toISOString(), ...event }) + '\n');
  } catch {
    // logging must never break the agent
  }
}

export function readEvents(sessionId) {
  try {
    return fs
      .readFileSync(sessionFile(sessionId), 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch {
    return [];
  }
}

export function buildReport(sessionId) {
  const events = readEvents(sessionId);
  if (!events.length) return null;

  const toolCounts = {};
  const incidents = [];
  for (const event of events) {
    if (event.tool) toolCounts[event.tool] = (toolCounts[event.tool] || 0) + 1;
    if (event.type === 'pre' && (event.decision === 'deny' || event.decision === 'ask' || event.audited)) {
      incidents.push(event);
    }
  }
  const blocked = incidents.filter((e) => e.decision === 'deny').length;
  const flagged = incidents.filter((e) => e.decision === 'ask').length;
  const audited = incidents.filter((e) => e.audited).length;

  const lines = [
    `# claude-shield session report`,
    ``,
    `- **Session:** \`${sessionId}\``,
    `- **Generated:** ${new Date().toISOString()}`,
    `- **Tool calls observed:** ${events.filter((e) => e.type === 'pre').length}`,
    `- **Blocked:** ${blocked} · **Flagged for confirmation:** ${flagged} · **Audit-only detections:** ${audited}`,
    ``,
  ];

  if (incidents.length) {
    lines.push(`## Security events`, ``, `| Time | Tool | Decision | Detail |`, `|---|---|---|---|`);
    for (const event of incidents) {
      const detail = (event.findings || []).map((f) => f.label).join('; ') || '-';
      const decision = event.audited ? 'audit' : event.decision;
      lines.push(`| ${event.ts} | ${event.tool} | ${decision} | ${detail} |`);
    }
    lines.push(``);
  } else {
    lines.push(`No security events this session. 🎉`, ``);
  }

  lines.push(`## Tool usage`, ``, `| Tool | Calls |`, `|---|---|`);
  for (const [tool, count] of Object.entries(toolCounts).sort((a, b) => b[1] - a[1])) {
    lines.push(`| ${tool} | ${count} |`);
  }
  lines.push(``, `_Generated locally by [claude-shield](https://github.com/psanchezp2/claude-shield). No data left this machine._`);
  return lines.join('\n');
}

export function writeReport(sessionId) {
  const report = buildReport(sessionId);
  if (!report) return null;
  const dir = path.join(shieldHome(), 'reports');
  fs.mkdirSync(dir, { recursive: true });
  const stamp = new Date().toISOString().slice(0, 10);
  const file = path.join(dir, `${stamp}-${String(sessionId).slice(0, 8)}.md`);
  fs.writeFileSync(file, report);
  return file;
}

export function readStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    // strip a UTF-8 BOM if the shell injected one
    process.stdin.on('end', () => resolve(data.replace(/^﻿/, '')));
    process.stdin.on('error', () => resolve(data));
  });
}
