#!/usr/bin/env node
// claude-shield CLI: install/uninstall the hooks into ~/.claude/settings.json
// (for users who don't use the plugin marketplace), test commands against the
// rules, and read session reports.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluate, loadConfig } from '../src/engine.js';
import { shieldHome } from '../src/store.js';

const HOOKS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'hooks');
const SETTINGS_FILE = path.join(os.homedir(), '.claude', 'settings.json');
const MARKER = 'claude-shield';

function hookCommand(script) {
  return `node "${path.join(HOOKS_DIR, script)}"`;
}

function readSettings() {
  try {
    return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function writeSettings(settings) {
  fs.mkdirSync(path.dirname(SETTINGS_FILE), { recursive: true });
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
}

function isShieldEntry(entry) {
  return (entry.hooks || []).some((h) => String(h.command || '').includes(MARKER));
}

function install() {
  const settings = readSettings();
  settings.hooks = settings.hooks || {};
  const wanted = {
    PreToolUse: { matcher: 'Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch', script: 'pretooluse.js' },
    PostToolUse: { matcher: '*', script: 'posttooluse.js' },
    SessionEnd: { script: 'sessionend.js' },
  };
  for (const [event, { matcher, script }] of Object.entries(wanted)) {
    const entries = (settings.hooks[event] = settings.hooks[event] || []);
    if (entries.some(isShieldEntry)) continue;
    const entry = { hooks: [{ type: 'command', command: hookCommand(script) }] };
    if (matcher) entry.matcher = matcher;
    entries.push(entry);
  }
  writeSettings(settings);
  console.log('claude-shield installed. Restart Claude Code (or start a new session) to activate.');
  console.log(`Hooks registered in ${SETTINGS_FILE}`);
}

function uninstall() {
  const settings = readSettings();
  for (const event of Object.keys(settings.hooks || {})) {
    settings.hooks[event] = settings.hooks[event].filter((entry) => !isShieldEntry(entry));
    if (!settings.hooks[event].length) delete settings.hooks[event];
  }
  writeSettings(settings);
  console.log('claude-shield hooks removed from ' + SETTINGS_FILE);
}

function status() {
  const settings = readSettings();
  const installed = Object.values(settings.hooks || {}).some((entries) => entries.some(isShieldEntry));
  const config = loadConfig();
  console.log(`Installed (settings.json): ${installed ? 'yes' : 'no — run: claude-shield install'}`);
  console.log(`Mode: ${config.mode}`);
  console.log(`Data dir: ${shieldHome()} (local only)`);
}

function check(command) {
  if (!command) {
    console.error('Usage: claude-shield check "<bash command>"');
    process.exit(1);
  }
  const result = evaluate({ tool_name: 'Bash', tool_input: { command } }, loadConfig());
  console.log(`Decision: ${result.decision.toUpperCase()}`);
  if (result.reason) console.log(result.reason);
  if (!result.findings.length) console.log('No rules triggered.');
}

function report() {
  const dir = path.join(shieldHome(), 'reports');
  let files = [];
  try {
    files = fs.readdirSync(dir).sort();
  } catch {
    // no reports yet
  }
  if (!files.length) {
    console.log('No reports yet. Reports are written when a Claude Code session ends.');
    return;
  }
  const latest = path.join(dir, files[files.length - 1]);
  console.log(fs.readFileSync(latest, 'utf8'));
  console.log(`\n(${latest})`);
}

const [, , cmd, ...args] = process.argv;
switch (cmd) {
  case 'install': install(); break;
  case 'uninstall': uninstall(); break;
  case 'status': status(); break;
  case 'check': check(args.join(' ')); break;
  case 'report': report(); break;
  default:
    console.log(`claude-shield — local DLP firewall for Claude Code

Usage:
  claude-shield install     Register hooks in ~/.claude/settings.json
  claude-shield uninstall   Remove the hooks
  claude-shield status      Show install state and active mode
  claude-shield check "..." Test a command against the rules
  claude-shield report      Print the latest session security report`);
}
