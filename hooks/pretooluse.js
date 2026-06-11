#!/usr/bin/env node
// PreToolUse hook: evaluates every tool call before it runs.
// Outputs a deny/ask decision as JSON when a rule fires; stays silent otherwise.
// Fails open on internal errors so a bug here can never brick someone's agent.
import { evaluate, loadConfig, redactSecrets } from '../src/engine.js';
import { logEvent, readStdin } from '../src/store.js';

try {
  const payload = JSON.parse(await readStdin());
  const config = loadConfig(payload.cwd || process.cwd());
  const result = evaluate(payload, config);

  const snippetSource =
    payload.tool_input?.command || payload.tool_input?.file_path || payload.tool_input?.url || '';
  logEvent(payload.session_id, {
    type: 'pre',
    tool: payload.tool_name,
    decision: result.decision,
    audited: result.audited,
    findings: result.findings,
    snippet: redactSecrets(String(snippetSource).slice(0, 200)).text,
  });

  if (result.decision === 'deny' || result.decision === 'ask') {
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: result.decision,
          permissionDecisionReason: result.reason,
        },
      }),
    );
  }
} catch (error) {
  // fail open; set CLAUDE_SHIELD_DEBUG=1 to see why
  if (process.env.CLAUDE_SHIELD_DEBUG) console.error(error);
}
// No process.exit(): exiting eagerly can truncate the stdout pipe on Windows
// before Claude Code reads the decision. The process ends when stdin closes.
