// Detection rules for claude-shield. Pure data and small predicates — no I/O.
// Every rule has a stable `id` so users can override its action in .claude-shield.json.

// High-confidence secret formats. Patterns are stored without the global flag;
// callers create a fresh global copy via `globalRegex()` to avoid lastIndex bugs.
export const SECRET_PATTERNS = [
  { id: 'anthropic-key', label: 'Anthropic API key', regex: /sk-ant-[A-Za-z0-9_-]{16,}/ },
  { id: 'openai-key', label: 'OpenAI API key', regex: /sk-proj-[A-Za-z0-9_-]{40,}/ },
  { id: 'aws-access-key', label: 'AWS access key ID', regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'aws-secret-key', label: 'AWS secret access key', regex: /aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}/i },
  { id: 'github-token', label: 'GitHub token', regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/ },
  { id: 'github-pat', label: 'GitHub fine-grained PAT', regex: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/ },
  { id: 'slack-token', label: 'Slack token', regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'stripe-live-key', label: 'Stripe live key', regex: /\b[sr]k_live_[A-Za-z0-9]{20,}\b/ },
  { id: 'google-api-key', label: 'Google API key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { id: 'npm-token', label: 'npm token', regex: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { id: 'private-key-block', label: 'private key block', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/ },
];

// Files whose contents are credentials by nature. `exclude` rescues known-safe variants.
export const SENSITIVE_FILE_PATTERNS = [
  {
    id: 'env-file', label: '.env file',
    regex: /(?:^|[\s"'`=/\\@:(])\.env(?:\.[\w-]+)*\b/,
    exclude: /\.env\.(?:example|sample|template|dist|test)\b/,
  },
  { id: 'ssh-keys', label: 'SSH keys', regex: /\.ssh[/\\]|\bid_(?:rsa|dsa|ecdsa|ed25519)\b/ },
  {
    id: 'cloud-creds', label: 'cloud credentials',
    regex: /\.aws[/\\]credentials|\.kube[/\\]config|\.docker[/\\]config\.json|gcloud[/\\](?:credentials|application_default_credentials)/,
  },
  { id: 'auth-files', label: 'auth/token files', regex: /\.netrc\b|\.npmrc\b|\.git-credentials\b|\.pgpass\b/ },
  { id: 'system-creds', label: 'system credential store', regex: /\/etc\/shadow\b/ },
];

// Anything that can move bytes off the machine.
export const NETWORK_TOOLS = /\b(?:curl|wget|nc|ncat|netcat|telnet|ftp|sftp|scp|rsync|ssh|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i;

// Irreversible / catastrophic commands. Checked as predicates because some need
// multi-condition logic that a single regex can't express readably.
export const DESTRUCTIVE_RULES = [
  {
    id: 'rm-no-preserve-root', label: 'rm --no-preserve-root', action: 'deny',
    test: (cmd) => /\brm\b[^;|&]*--no-preserve-root/.test(cmd),
  },
  {
    id: 'rm-root-or-home', label: 'recursive delete of root or home directory', action: 'deny',
    test: (cmd) =>
      /\brm\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*[rR][A-Za-z]*\s+(?:-[A-Za-z]+\s+)*["']?(?:\/|~\/?|\$HOME\/?|[A-Za-z]:[\\/]?)["']?\s*(?:$|[;&|])/.test(cmd),
  },
  {
    id: 'remove-item-root', label: 'Remove-Item -Recurse on root or home', action: 'deny',
    test: (cmd) =>
      /Remove-Item\b/i.test(cmd) && /-Recurse\b/i.test(cmd) &&
      /(?:^|\s)["']?(?:[A-Za-z]:[\\/]?|\$env:USERPROFILE\\?|~[\\/]?)["']?\s*(?:$|\s-)/.test(cmd),
  },
  {
    id: 'disk-destroy', label: 'disk-destroying command', action: 'deny',
    test: (cmd) => /\bmkfs(?:\.\w+)?\b|\bdd\b[^;|&]*\bof=\/dev\/(?:sd|hd|nvme|vd)|\bformat\s+[A-Za-z]:|\bdiskpart\b/i.test(cmd),
  },
  {
    id: 'fork-bomb', label: 'fork bomb', action: 'deny',
    test: (cmd) => /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/.test(cmd),
  },
  {
    id: 'chmod-root', label: 'recursive chmod 777 on root', action: 'deny',
    test: (cmd) => /\bchmod\s+(?:-[A-Za-z]+\s+)*777\s+\/\s*(?:$|[;&|])/.test(cmd) || /\bchmod\s+-R\s+777\s+\//.test(cmd),
  },
  {
    id: 'git-force-push', label: 'git force push', action: 'ask',
    test: (cmd) => /\bgit\s+push\b[^;|&]*(?:--force\b(?!-with-lease)|\s-f\b)/.test(cmd),
  },
  {
    id: 'curl-pipe-shell', label: 'piping a download straight into a shell', action: 'ask',
    test: (cmd) =>
      /\b(?:curl|wget)\b[^;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|fi)?sh\b/.test(cmd) ||
      (/\b(?:iex|Invoke-Expression)\b/i.test(cmd) && /\b(?:irm|Invoke-RestMethod|iwr|Invoke-WebRequest)\b/i.test(cmd)),
  },
  {
    id: 'env-dump-exfil', label: 'piping environment variables to the network', action: 'deny',
    test: (cmd) =>
      /\b(?:env|printenv|Get-ChildItem\s+env:|gci\s+env:)\b[^;]*\|[^;]*\b(?:curl|wget|nc|ncat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i.test(cmd),
  },
];

const PLACEHOLDER = /EXAMPLE|SAMPLE|PLACEHOLDER|CHANGEME|XXXXXXXX|YOUR[_-]|<REDACTED/i;

export function isPlaceholder(value) {
  return PLACEHOLDER.test(value);
}

export function globalRegex(regex) {
  const flags = regex.flags.includes('g') ? regex.flags : regex.flags + 'g';
  return new RegExp(regex.source, flags);
}
