import type { FileContext, RawFinding } from '../context.js';
import { entries, prop, range, str, type JsonNode } from '../json.js';
import { truncate } from '../text.js';
import { LOCAL_HOST, PATTERNS } from './commands.js';

const RISKY_CMDS =
  /^(?:curl|wget|nc|ncat|netcat|socat|ssh|scp|rsync|sh|bash|zsh|fish|dash|eval|exec|source|sudo|su|doas|python[0-9.]*|node|deno|bun|ruby|perl|php|osascript|powershell|pwsh|iex|xargs|env|rm|dd|chmod|chown|crontab|launchctl|security|base64|npx|bunx|uvx|pipx|docker|kubectl|aws|gcloud|az)$/;

function checkPermission(value: string): { severity: 'high' | 'medium'; why: string } | undefined {
  const v = value.trim();
  if (/^Bash$/.test(v) || /^Bash\(\s*(?:\*|:\*|\*\*|\s*)\s*\)$/.test(v)) return { severity: 'high', why: 'any shell command' };
  const m = /^Bash\(\s*([^\s:*)]+)(?:\s*:\s*\*|\s+\*|\*)\s*\)$/.exec(v);
  if (m && RISKY_CMDS.test(m[1]!)) return { severity: 'medium', why: `any \`${m[1]}\` invocation` };
  return undefined;
}

function walkHooks(hooks: JsonNode | undefined, cb: (cmd: string, node: JsonNode) => void) {
  for (const ev of entries(hooks)) {
    const arr = ev.value;
    if (arr.type !== 'array') continue;
    for (const matcher of arr.children ?? []) {
      const inner = prop(matcher, 'hooks');
      const list = inner?.type === 'array' ? inner.children ?? [] : [matcher];
      for (const h of list) {
        const cmdNode = prop(h, 'command');
        const cmd = str(cmdNode);
        if (cmd !== undefined && cmdNode) cb(cmd, cmdNode);
        const urlNode = prop(h, 'url');
        const url = str(urlNode);
        if (url !== undefined && urlNode && str(prop(h, 'type')) === 'http') cb(`http ${url}`, urlNode);
      }
    }
  }
}

const NET = /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|nc|ncat|http)\b[^\n]*?(https?:\/\/[^\s"'`|;)]+|\b(?:\d{1,3}\.){3}\d{1,3}\b)/i;
const RCE = PATTERNS.filter((p) => p.ruleId === 'PW009' || p.ruleId === 'PW010');

/** PW023–PW026 (Claude Code settings + plugin hooks) */
export function detectClaudeSettings(ctx: FileContext): RawFinding[] {
  const out: RawFinding[] = [];
  const root = ctx.json;
  if (!root || root.type !== 'object') return out;

  const perms = prop(root, 'permissions');
  const allow = prop(perms, 'allow');
  if (allow?.type === 'array') {
    for (const item of allow.children ?? []) {
      const v = str(item);
      if (v === undefined) continue;
      const r = checkPermission(v);
      if (r) {
        const [start, end] = range(item);
        out.push({ ruleId: 'PW023', start, end, message: `"${v}" pre-approves ${r.why} without a prompt`, severity: r.severity });
      }
    }
  }
  const mode = prop(perms, 'defaultMode') ?? prop(root, 'defaultMode');
  if (str(mode) === 'bypassPermissions' && mode) {
    const [start, end] = range(mode);
    out.push({ ruleId: 'PW024', start, end, message: 'defaultMode "bypassPermissions" disables all permission prompts' });
  }
  for (const key of ['skipDangerousModePermissionPrompt', 'dangerouslySkipPermissions']) {
    const n = prop(root, key);
    if (n?.type === 'boolean' && n.value === true) {
      const [start, end] = range(n);
      out.push({ ruleId: 'PW024', start, end, message: `${key} is enabled`, severity: 'medium' });
    }
  }
  const all = prop(root, 'enableAllProjectMcpServers');
  if (all?.type === 'boolean' && all.value === true) {
    const [start, end] = range(all);
    out.push({ ruleId: 'PW025', start, end, message: 'enableAllProjectMcpServers auto-starts every MCP server from any project .mcp.json' });
  }

  walkHooks(prop(root, 'hooks'), (cmd, node) => {
    const net = NET.exec(cmd);
    if (!net) return;
    const host = /^https?:\/\/([^/:?#]+)/i.exec(net[1] ?? '')?.[1];
    if (host && LOCAL_HOST.test(host)) return;
    // already reported as remote code execution by PW009/PW010
    if (RCE.some((p) => { p.re.lastIndex = 0; return p.re.test(cmd); })) return;
    const [start, end] = range(node);
    out.push({ ruleId: 'PW026', start, end, message: `Hook contacts a remote host on every trigger: ${truncate(cmd, 120)}` });
  });
  return out;
}

/** PW024 for ~/.codex/config.toml */
export function detectCodexConfig(ctx: FileContext): RawFinding[] {
  const out: RawFinding[] = [];
  for (const m of ctx.content.matchAll(/^\s*sandbox_mode\s*=\s*["']danger-full-access["']/gm)) {
    const start = m.index! + (m[0].length - m[0].trimStart().length);
    out.push({ ruleId: 'PW024', start, end: m.index! + m[0].length, message: 'Codex sandbox disabled (sandbox_mode = "danger-full-access")' });
  }
  for (const m of ctx.content.matchAll(/^\s*approval_policy\s*=\s*["']never["']/gm)) {
    const start = m.index! + (m[0].length - m[0].trimStart().length);
    out.push({ ruleId: 'PW024', start, end: m.index! + m[0].length, message: 'Codex never asks for approval (approval_policy = "never")', severity: 'medium' });
  }
  return out;
}
