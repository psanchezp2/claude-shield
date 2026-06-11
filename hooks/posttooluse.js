#!/usr/bin/env node
// PostToolUse hook: records which tool ran (redacted, local-only) so the
// session report can show what the agent actually did.
import { redactSecrets } from '../src/engine.js';
import { logEvent, readStdin } from '../src/store.js';

try {
  const payload = JSON.parse(await readStdin());
  const target =
    payload.tool_input?.file_path || payload.tool_input?.command || payload.tool_input?.url || '';
  logEvent(payload.session_id, {
    type: 'post',
    tool: payload.tool_name,
    target: redactSecrets(String(target).slice(0, 200)).text,
  });
} catch {
  // never break the agent
}
