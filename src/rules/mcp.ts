import type { FileContext, RawFinding } from '../context.js';
import { entries, findProps, prop, range, str, type JsonNode } from '../json.js';
import { entropy, findSecrets, maskValue } from '../text.js';
import { LOCAL_HOST } from './commands.js';

type Range = [number, number];
interface Val {
  value: string;
  range: Range;
}

export interface ServerSpec {
  name: string;
  nameRange: Range;
  command?: Val;
  args: Val[];
  urls: Val[];
  env: { key: string; value: Val }[];
  headers: { key: string; value: Val }[];
}

const SERVER_KEYS = new Set(['mcpServers', 'mcp_servers', 'context_servers']);

// ───────────────────────── extraction ─────────────────────────

function fromJsonServer(name: string, keyNode: JsonNode, node: JsonNode): ServerSpec | undefined {
  if (node.type !== 'object') return undefined;
  const v = (n: JsonNode | undefined): Val | undefined => {
    const s = str(n);
    return s !== undefined && n ? { value: s, range: range(n) } : undefined;
  };
  const spec: ServerSpec = { name, nameRange: range(keyNode), args: [], urls: [], env: [], headers: [] };
  // Zed nests command: { path, args, env }
  const cmdNode = prop(node, 'command');
  const container = cmdNode?.type === 'object' ? cmdNode : node;
  spec.command = v(cmdNode?.type === 'object' ? prop(cmdNode, 'path') : cmdNode);
  const args = prop(container, 'args');
  if (args?.type === 'array') for (const a of args.children ?? []) {
    const x = v(a);
    if (x) spec.args.push(x);
  }
  for (const k of ['url', 'serverUrl', 'httpUrl', 'uri', 'endpoint']) {
    const x = v(prop(node, k));
    if (x) spec.urls.push(x);
  }
  for (const e of entries(prop(container, 'env'))) {
    const x = v(e.value);
    if (x) spec.env.push({ key: e.key, value: x });
  }
  for (const e of entries(prop(node, 'headers'))) {
    const x = v(e.value);
    if (x) spec.headers.push({ key: e.key, value: x });
  }
  return spec;
}

export function serversFromJson(ctx: FileContext): ServerSpec[] {
  const out: ServerSpec[] = [];
  const containers = findProps(ctx.json, SERVER_KEYS);
  // VS Code .vscode/mcp.json uses top-level "servers"
  if (/(?:^|\/)\.vscode\/mcp\.json$/.test(ctx.absolutePath.replace(/\\/g, '/'))) {
    const s = prop(ctx.json, 'servers');
    const k = ctx.json?.children?.find((p) => p.children?.[0]?.value === 'servers')?.children?.[0];
    if (s && k) containers.push({ key: 'servers', keyNode: k, value: s });
  }
  for (const c of containers) {
    for (const e of entries(c.value)) {
      const spec = fromJsonServer(e.key, e.keyNode, e.value);
      if (spec) out.push(spec);
    }
  }
  return out;
}

export function serversFromToml(ctx: FileContext): ServerSpec[] {
  const servers = (ctx.toml?.['mcp_servers'] ?? undefined) as Record<string, Record<string, unknown>> | undefined;
  if (!servers || typeof servers !== 'object') return [];
  const text = ctx.content;
  const out: ServerSpec[] = [];
  for (const [name, cfg] of Object.entries(servers)) {
    if (!cfg || typeof cfg !== 'object') continue;
    const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const header = new RegExp(String.raw`^\s*\[\s*mcp_servers\s*\.\s*(?:"${esc}"|'${esc}'|${esc})\s*\]`, 'm').exec(text);
    const secStart = header ? header.index + (header[0].length - header[0].trimStart().length) : Math.max(0, text.indexOf(name));
    const nextHeader = /^\s*\[/m;
    const restIdx = header ? header.index + header[0].length : secStart;
    const nh = nextHeader.exec(text.slice(restIdx));
    const secEnd = nh ? restIdx + nh.index : text.length;
    const nameRange: Range = [secStart, secStart + (header ? header[0].trim().length : name.length)];
    let cursor = restIdx;
    const locate = (value: string): Range => {
      const quotedA = JSON.stringify(value);
      for (const needle of [quotedA, `'${value}'`, value]) {
        const i = text.indexOf(needle, cursor);
        if (i >= 0 && i < secEnd) {
          cursor = i + needle.length;
          return [i, i + needle.length];
        }
      }
      return nameRange;
    };
    const spec: ServerSpec = { name, nameRange, args: [], urls: [], env: [], headers: [] };
    if (typeof cfg.command === 'string') spec.command = { value: cfg.command, range: locate(cfg.command) };
    if (Array.isArray(cfg.args)) for (const a of cfg.args) if (typeof a === 'string') spec.args.push({ value: a, range: locate(a) });
    for (const k of ['url', 'server_url']) if (typeof cfg[k] === 'string') spec.urls.push({ value: cfg[k] as string, range: locate(cfg[k] as string) });
    const env = cfg.env as Record<string, unknown> | undefined;
    if (env && typeof env === 'object') for (const [k, v] of Object.entries(env)) if (typeof v === 'string') spec.env.push({ key: k, value: { value: v, range: locate(v) } });
    const hdr = (cfg.http_headers ?? cfg.headers) as Record<string, unknown> | undefined;
    if (hdr && typeof hdr === 'object') for (const [k, v] of Object.entries(hdr)) if (typeof v === 'string') spec.headers.push({ key: k, value: { value: v, range: locate(v) } });
    if (typeof cfg.bearer_token === 'string') spec.headers.push({ key: 'Authorization', value: { value: cfg.bearer_token, range: locate(cfg.bearer_token) } });
    out.push(spec);
  }
  return out;
}

// ───────────────────────── analysis ─────────────────────────

interface Token {
  value: string;
  range: Range;
}

function splitShell(s: string): string[] {
  const out: string[] = [];
  const re = /"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+)/g;
  for (const m of s.matchAll(re)) out.push(m[1] ?? m[2] ?? m[3] ?? '');
  return out;
}

/** Flatten command + args into tokens, unwrapping `cmd /c`, `bash -c "..."`. */
function tokens(spec: ServerSpec): Token[] {
  const toks: Token[] = [];
  if (spec.command) {
    // "command": "npx -y foo" (single string) is accepted by some clients
    const parts = splitShell(spec.command.value);
    for (const p of parts) toks.push({ value: p, range: spec.command.range });
  }
  for (const a of spec.args) toks.push({ value: a.value, range: a.range });
  // unwrap Windows cmd /c and shells with -c
  const base = (t?: Token) => t?.value.replace(/\\/g, '/').split('/').pop()?.replace(/\.(?:cmd|exe|bat)$/i, '').toLowerCase();
  const b0 = base(toks[0]);
  if (b0 === 'cmd' && /^\/c$/i.test(toks[1]?.value ?? '')) return toks.slice(2);
  if ((b0 === 'bash' || b0 === 'sh' || b0 === 'zsh') && toks[1]?.value === '-c' && toks[2]) {
    const inner = toks[2];
    return splitShell(inner.value).map((v) => ({ value: v, range: inner.range }));
  }
  return toks;
}

const RUNNERS: Record<string, { skip: number; eco: 'npm' | 'py' }> = {
  npx: { skip: 1, eco: 'npm' },
  bunx: { skip: 1, eco: 'npm' },
  pnpx: { skip: 1, eco: 'npm' },
  uvx: { skip: 1, eco: 'py' },
};

function findRunner(toks: Token[]): { idx: number; eco: 'npm' | 'py' } | undefined {
  for (let i = 0; i < Math.min(toks.length, 4); i++) {
    const v = toks[i]!.value.replace(/\\/g, '/').split('/').pop()!.replace(/\.(?:cmd|exe)$/i, '').toLowerCase();
    const next = toks[i + 1]?.value;
    if (RUNNERS[v]) return { idx: i + 1, eco: RUNNERS[v].eco };
    if ((v === 'pnpm' || v === 'yarn' || v === 'bun') && (next === 'dlx' || next === 'x')) return { idx: i + 2, eco: 'npm' };
    if (v === 'npm' && (next === 'exec' || next === 'x')) return { idx: i + 2, eco: 'npm' };
    if (v === 'pipx' && next === 'run') return { idx: i + 2, eco: 'py' };
    if (v === 'uv' && next === 'tool' && toks[i + 2]?.value === 'run') return { idx: i + 3, eco: 'py' };
    if (v === 'uv' && next === 'run' && toks.slice(i + 2).some((t) => t.value === '--with')) return undefined;
  }
  return undefined;
}

const NPM_FLAGS_WITH_VALUE = new Set(['-p', '--package', '--registry', '--cache', '--userconfig', '-c', '--call', '--node-options']);
const PY_FLAGS_WITH_VALUE = new Set(['--from', '--with', '--python', '-p', '--index-url', '--extra-index-url', '--index', '-w', '--with-requirements', '--spec']);

function isRemoteSource(spec: string): boolean {
  return /^(?:git\+|git:\/\/|github:|gitlab:|bitbucket:|https?:\/\/|ssh:\/\/|[\w.-]+\/[\w.-]+#)/i.test(spec) || /\.git(?:#|$)/.test(spec);
}

function npmPinned(spec: string): boolean {
  const m = /^(@[^/@\s]+\/[^@\s]+|[^@\s]+)@(.+)$/.exec(spec);
  if (!m) return false;
  return /^v?\d+\.\d+\.\d+(?:[-+][\w.-]+)?$/.test(m[2]!);
}

function pyPinned(spec: string): boolean {
  return /==\s*\d/.test(spec) || /@\s*\d+\.\d+/.test(spec) || /@\s*[0-9a-f]{40}\b/.test(spec);
}

function isLocalPath(spec: string): boolean {
  return /^(?:\.{1,2}[/\\]|\/|~|[A-Za-z]:[\\/]|file:)/.test(spec) || /\.(?:tgz|whl|tar\.gz)$/.test(spec) && !/^https?:/.test(spec);
}

const SECRET_KEY = /(?:TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|API_?KEY|APIKEY|ACCESS_?KEY|PRIVATE_?KEY|CLIENT_?SECRET|AUTH|CREDENTIALS?|(?:^|_)PAT$|COOKIE|SESSION_?KEY|SIGNING_?KEY)/i;
const NOT_SECRET_KEY = /(?:_PATH|_FILE|_URL|_URI|_DIR|_ENDPOINT|_HOST|_TYPE|_MODE|_ID|_NAME|_HEADER|_ENABLED|_DISABLED|_PROVIDER|_METHOD|_REGION|_EXPIRY|_EXPIRES|_TTL|_SCOPES?|_VERSION|_HELPER|_DOMAIN|_ISSUER|_AUDIENCE)$/i;

function isReference(v: string): boolean {
  return /^\s*(?:\$\{?[\w:.-]+\}?|\{env:[\w]+\}|\{\{[^}]+\}\}|env:|op:\/\/|vault:|keychain:|secret:|<[^>]+>|%[\w]+%)\s*$/i.test(v) || /\$\{[^}]+\}|\$\{env:/.test(v);
}

function looksLikeLiteralSecret(v: string): boolean {
  const s = v.replace(/^(?:Bearer|Basic|Token|token)\s+/, '').trim();
  if (s.length < 8 || isReference(s) || isReference(v)) return false;
  if (/^(?:true|false|null|none|yes|no|on|off|\d{1,7})$/i.test(s)) return false;
  if (/(?:x{4,}|\.\.\.|your[_-]?|example|placeholder|changeme|dummy|redacted|replace|insert|<|>|\*{3,})/i.test(s)) return false;
  if (/^https?:\/\//.test(s) || /^[./~]/.test(s)) return false;
  if (/\s/.test(s)) return false;
  return entropy(s) >= 2.8;
}

export function analyzeServer(spec: ServerSpec): RawFinding[] {
  const out: RawFinding[] = [];
  const toks = tokens(spec);
  const label = `MCP server "${spec.name}"`;

  // PW018 / PW022 – package runners
  const runner = findRunner(toks);
  if (runner) {
    const before = toks.slice(0, runner.idx).map((t) => t.value);
    const rest = toks.slice(runner.idx);
    const hasYes = [...before, ...rest.map((t) => t.value)].some((v) => v === '-y' || v === '--yes');
    const pkgs: Token[] = [];
    let positional: Token | undefined;
    for (let i = 0; i < rest.length; i++) {
      const t = rest[i]!;
      if (t.value === '--') {
        positional ??= rest[i + 1];
        break;
      }
      if (t.value.startsWith('-')) {
        const [flag, inline] = t.value.split('=', 2) as [string, string | undefined];
        const withValue = runner.eco === 'npm' ? NPM_FLAGS_WITH_VALUE : PY_FLAGS_WITH_VALUE;
        if (withValue.has(flag)) {
          const val = inline !== undefined ? { value: inline, range: t.range } : rest[++i];
          if (val && (flag === '-p' || flag === '--package' || flag === '--from' || flag === '--spec')) pkgs.push(val);
          if (val && runner.eco === 'py' && flag === '--with' && isRemoteSource(val.value)) pkgs.push(val);
        }
        continue;
      }
      positional = t;
      break;
    }
    if (pkgs.length === 0 && positional) pkgs.push(positional);
    for (const p of pkgs) {
      const spec0 = p.value;
      if (isRemoteSource(spec0)) {
        out.push({ ruleId: 'PW022', start: p.range[0], end: p.range[1], message: `${label} is installed straight from "${spec0}"` });
        continue;
      }
      if (isLocalPath(spec0)) continue;
      const pinned = runner.eco === 'npm' ? npmPinned(spec0) : pyPinned(spec0);
      if (!pinned) {
        out.push({
          ruleId: 'PW018',
          start: p.range[0],
          end: p.range[1],
          message: `${label} runs "${spec0}" without a pinned version${hasYes ? ' and with -y (auto-install)' : ''}`,
          severity: hasYes ? 'high' : 'medium',
        });
      }
    }
  }

  // PW022 – shell downloading code / git sources anywhere in args
  for (const t of toks) {
    if (/\b(?:curl|wget)\b[^\n]*\|\s*(?:ba|z)?sh\b/.test(t.value) || /^(?:git\+https?:\/\/|git\+ssh:\/\/|github:)/.test(t.value)) {
      if (!out.some((f) => f.start === t.range[0] && f.end === t.range[1])) {
        out.push({ ruleId: 'PW022', start: t.range[0], end: t.range[1], message: `${label} fetches code from a remote source at launch: "${t.value.slice(0, 100)}"` });
      }
    }
  }

  // PW019 – insecure transport
  const urlCandidates: Val[] = [...spec.urls, ...spec.args.filter((a) => /^http:\/\//i.test(a.value))];
  for (const u of urlCandidates) {
    const m = /^http:\/\/([^/:?#\s]+|\[[^\]]+\])/i.exec(u.value.trim());
    if (!m) continue;
    const host = m[1]!;
    if (LOCAL_HOST.test(host) || /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(host)) continue;
    out.push({ ruleId: 'PW019', start: u.range[0], end: u.range[1], message: `${label} connects to ${u.value} over plain HTTP` });
  }

  // PW020 – docker privileges
  const b = (t?: Token) => t?.value.replace(/\\/g, '/').split('/').pop()?.replace(/\.exe$/i, '').toLowerCase();
  const di = toks.findIndex((t) => b(t) === 'docker' || b(t) === 'podman');
  if (di >= 0 && toks.slice(di + 1).some((t) => t.value === 'run' || t.value === 'create')) {
    const rest = toks.slice(di + 1);
    for (let i = 0; i < rest.length; i++) {
      const t = rest[i]!;
      const v = t.value;
      const next = rest[i + 1]?.value ?? '';
      let why: string | undefined;
      if (v === '--privileged' || v === '--privileged=true') why = '--privileged';
      else if (/^--(?:network|net)=host$/.test(v) || (/^--(?:network|net)$/.test(v) && next === 'host')) why = 'host network';
      else if (/^--(?:pid|ipc|uts|userns)=host$/.test(v) || (/^--(?:pid|ipc|uts|userns)$/.test(v) && next === 'host')) why = `host ${v.replace(/^--|=host$/g, '')} namespace`;
      else if (/^--cap-add=?(?:SYS_ADMIN|ALL|SYS_PTRACE|SYS_MODULE)?$/.test(v) && /SYS_ADMIN|ALL|SYS_PTRACE|SYS_MODULE/.test(v + ' ' + next)) why = 'dangerous capability';
      else if (/^--security-opt/.test(v) && /(?:seccomp|apparmor)[=:]unconfined/.test(v + ' ' + next)) why = 'security profile disabled';
      else {
        const mount = /^(?:-v|--volume|--mount)$/.test(v) ? next : /^(?:-v|--volume|--mount)=(.*)$/.exec(v)?.[1] ?? (/^-v(\/.*)$/.exec(v)?.[1]);
        if (mount !== undefined && mount !== '') {
          const src = /(?:^|,)(?:source|src)=([^,]+)/.exec(mount)?.[1] ?? mount.split(':')[0]!;
          if (/^\/?$/.test(src)) why = 'mounts the host root filesystem';
          else if (/^(?:~|\$HOME|\$\{HOME\}|\/Users\/[^/]+|\/home\/[^/]+|\/root|%USERPROFILE%|C:\\Users\\[^\\]+)\/?$/.test(src)) why = 'mounts your entire home directory';
          else if (/docker\.sock$/.test(src)) why = 'mounts the Docker socket (root-equivalent)';
          else if (/^\/(?:etc|var|usr|private)\/?$/.test(src)) why = `mounts host ${src}`;
        }
      }
      if (why) out.push({ ruleId: 'PW020', start: t.range[0], end: (rest[i + 1] && !v.includes('=') && /^(?:-v|--volume|--mount|--network|--net|--pid|--ipc|--cap-add)$/.test(v) ? rest[i + 1]!.range[1] : t.range[1]), message: `${label} container: ${why}` });
    }
  }

  // PW021 – inline secrets
  const known = (v: string) => findSecrets(v).length > 0;
  for (const e of spec.env) {
    if (!SECRET_KEY.test(e.key) || NOT_SECRET_KEY.test(e.key)) continue;
    const v = e.value.value;
    if (!looksLikeLiteralSecret(v) || known(v)) continue;
    out.push({ ruleId: 'PW021', start: e.value.range[0], end: e.value.range[1], message: `${label}: env ${e.key} has a literal value (${maskValue(v)})`, mask: [v] });
  }
  for (const h of spec.headers) {
    if (!/^(?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token|x-access-token|cookie|[\w-]*(?:token|secret|key))$/i.test(h.key)) continue;
    const v = h.value.value;
    if (!looksLikeLiteralSecret(v) || known(v)) continue;
    out.push({ ruleId: 'PW021', start: h.value.range[0], end: h.value.range[1], message: `${label}: header ${h.key} has a literal credential (${maskValue(v)})`, mask: [v, v.replace(/^(?:Bearer|Basic|Token)\s+/i, '')] });
  }
  for (let i = 0; i < spec.args.length; i++) {
    const a = spec.args[i]!;
    const m = /^--?(?:api[-_]?key|token|access[-_]?token|auth[-_]?token|secret|password|client[-_]?secret|pat)(?:=(.+))?$/i.exec(a.value);
    if (!m) continue;
    const valTok = m[1] !== undefined ? { value: m[1], range: a.range } : spec.args[i + 1];
    if (!valTok || !looksLikeLiteralSecret(valTok.value) || known(valTok.value)) continue;
    out.push({ ruleId: 'PW021', start: valTok.range[0], end: valTok.range[1], message: `${label}: ${a.value.split('=')[0]} passed as a literal argument (${maskValue(valTok.value)})`, mask: [valTok.value] });
  }
  return out;
}

/** PW018–PW022 */
export function detectMcp(ctx: FileContext): RawFinding[] {
  const servers = ctx.kind === 'codex-config' ? serversFromToml(ctx) : ctx.json ? serversFromJson(ctx) : [];
  return servers.flatMap(analyzeServer);
}

/** Ranges of mcpServers sub-trees (used to restrict text rules in ~/.claude.json). */
export function mcpRegions(ctx: FileContext): [number, number][] {
  return findProps(ctx.json, SERVER_KEYS, 4).map((p) => range(p.value));
}
