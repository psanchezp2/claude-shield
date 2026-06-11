// claude-shield evaluation engine. Pure functions, no I/O: takes a Claude Code
// PreToolUse payload plus a config object and returns a decision. The hook
// scripts in hooks/ are thin wrappers around this module.
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  SECRET_PATTERNS,
  SENSITIVE_FILE_PATTERNS,
  NETWORK_TOOLS,
  DESTRUCTIVE_RULES,
  isPlaceholder,
  globalRegex,
} from './rules.js';

const SEVERITY = { allow: 0, ask: 1, deny: 2 };
const CONTENT_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);

export const DEFAULT_CONFIG = { mode: 'enforce', rules: {}, allow: [] };

/**
 * Merge defaults <- ~/.claude-shield/config.json <- <cwd>/.claude-shield.json.
 * A malformed config file is ignored rather than breaking the agent.
 */
export function loadConfig(cwd = process.cwd()) {
  const config = { ...DEFAULT_CONFIG, rules: {}, allow: [] };
  const sources = [
    path.join(process.env.CLAUDE_SHIELD_HOME || path.join(os.homedir(), '.claude-shield'), 'config.json'),
    path.join(cwd, '.claude-shield.json'),
  ];
  for (const file of sources) {
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (parsed.mode === 'audit' || parsed.mode === 'enforce') config.mode = parsed.mode;
      if (parsed.rules && typeof parsed.rules === 'object') Object.assign(config.rules, parsed.rules);
      if (Array.isArray(parsed.allow)) config.allow.push(...parsed.allow);
    } catch {
      // missing or invalid file: keep going with what we have
    }
  }
  return config;
}

/** Replace every known secret in `text` with a typed mask. Used before anything is logged. */
export function redactSecrets(text) {
  let out = String(text ?? '');
  let count = 0;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(globalRegex(pattern.regex), () => {
      count += 1;
      return `<REDACTED:${pattern.id}>`;
    });
  }
  return { text: out, count };
}

function findSecrets(text) {
  const found = [];
  for (const pattern of SECRET_PATTERNS) {
    for (const match of String(text).matchAll(globalRegex(pattern.regex))) {
      if (!isPlaceholder(match[0])) found.push({ id: pattern.id, label: pattern.label });
    }
  }
  return found;
}

function findSensitiveFiles(command) {
  const found = [];
  for (const pattern of SENSITIVE_FILE_PATTERNS) {
    if (pattern.regex.test(command) && !(pattern.exclude && pattern.exclude.test(command))) {
      found.push({ id: pattern.id, label: pattern.label });
    }
  }
  return found;
}

function evalBashCommand(command) {
  const findings = [];
  for (const rule of DESTRUCTIVE_RULES) {
    if (rule.test(command)) {
      findings.push({ ruleId: rule.id, label: rule.label, action: rule.action });
    }
  }

  const touchesNetwork = NETWORK_TOOLS.test(command);
  for (const file of findSensitiveFiles(command)) {
    findings.push(touchesNetwork
      ? { ruleId: 'exfil-sensitive-file', label: `possible exfiltration of ${file.label}`, action: 'deny' }
      : { ruleId: 'read-sensitive-file', label: `access to ${file.label}`, action: 'ask' });
  }

  for (const secret of findSecrets(command)) {
    findings.push(touchesNetwork
      ? { ruleId: 'exfil-secret-literal', label: `${secret.label} sent over the network`, action: 'deny' }
      : { ruleId: 'secret-in-command', label: `${secret.label} in command`, action: 'ask' });
  }
  return findings;
}

function contentOf(toolName, toolInput) {
  if (toolName === 'Write') return toolInput.content;
  if (toolName === 'Edit') return toolInput.new_string;
  if (toolName === 'MultiEdit') return (toolInput.edits || []).map((e) => e.new_string).join('\n');
  if (toolName === 'NotebookEdit') return toolInput.new_source;
  return '';
}

function evalContent(toolName, toolInput) {
  const filePath = toolInput.file_path || toolInput.notebook_path || '';
  // Writing a secret into a .env file is correct practice, not a leak.
  if (path.basename(filePath).startsWith('.env')) return [];
  return findSecrets(contentOf(toolName, toolInput)).map((secret) => ({
    ruleId: 'hardcoded-secret',
    label: `hardcoded ${secret.label} in ${path.basename(filePath) || 'file'}`,
    action: 'deny',
  }));
}

function evalWebFetch(toolInput) {
  return findSecrets(toolInput.url || '').map((secret) => ({
    ruleId: 'secret-in-url',
    label: `${secret.label} embedded in fetched URL`,
    action: 'deny',
  }));
}

/**
 * Evaluate a PreToolUse payload. Returns:
 *   { decision: 'allow'|'ask'|'deny', reason, findings, audited }
 * `audited` is true when findings existed but mode 'audit' downgraded them.
 */
export function evaluate(payload, config = DEFAULT_CONFIG) {
  const toolName = payload.tool_name || '';
  const toolInput = payload.tool_input || {};
  const haystack = [toolInput.command, toolInput.file_path, toolInput.url, contentOf(toolName, toolInput)]
    .filter(Boolean)
    .join('\n');

  for (const allowPattern of config.allow || []) {
    try {
      if (new RegExp(allowPattern).test(haystack)) {
        return { decision: 'allow', reason: '', findings: [], audited: false };
      }
    } catch {
      // invalid user regex: ignore it
    }
  }

  let findings = [];
  if (toolName === 'Bash') findings = evalBashCommand(String(toolInput.command ?? ''));
  else if (CONTENT_TOOLS.has(toolName)) findings = evalContent(toolName, toolInput);
  else if (toolName === 'WebFetch') findings = evalWebFetch(toolInput);

  // Apply per-rule overrides from config, dropping rules set to allow/off.
  findings = findings
    .map((f) => ({ ...f, action: (config.rules || {})[f.ruleId] ?? f.action }))
    .filter((f) => f.action === 'ask' || f.action === 'deny');

  const top = findings.reduce((max, f) => (SEVERITY[f.action] > SEVERITY[max] ? f.action : max), 'allow');
  const reason = findings.length
    ? `claude-shield: ${[...new Set(findings.map((f) => f.label))].join('; ')}. ` +
      `Override with .claude-shield.json ({"rules":{"${findings[0].ruleId}":"allow"}}) if intentional.`
    : '';

  if (config.mode === 'audit' && top !== 'allow') {
    return { decision: 'allow', reason, findings, audited: true };
  }
  return { decision: top, reason, findings, audited: false };
}
