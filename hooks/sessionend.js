#!/usr/bin/env node
// SessionEnd hook: writes a markdown security report for the session under
// ~/.claude-shield/reports/. View the latest one with `claude-shield report`.
import { readStdin, writeReport } from '../src/store.js';

try {
  const payload = JSON.parse(await readStdin());
  writeReport(payload.session_id);
} catch {
  // never break the agent
}
