import { createHash } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { createContext, type FileContext, type RawFinding } from './context.js';
import { discover } from './discover.js';
import { RULES, RULES_BY_ID, docsUrl } from './rules/meta.js';
import { detectEncodedBlobs, detectHtmlComments, detectInvisible } from './rules/hidden.js';
import { detectInjection } from './rules/injection.js';
import { detectCommands } from './rules/commands.js';
import { detectSecrets } from './rules/secrets.js';
import { detectMcp, mcpRegions } from './rules/mcp.js';
import { detectClaudeSettings, detectCodexConfig } from './rules/settings.js';
import { detectSkillMeta } from './rules/skills.js';
import { maskSecrets, renderVisible, truncate } from './text.js';
import { SEVERITIES, type FileKind, type Finding, type ScanOptions, type ScanResult, type Severity } from './types.js';
import { VERSION } from './version.js';

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

type Detector = (ctx: FileContext) => RawFinding[];

const DETECTORS: Detector[] = [
  detectInvisible,
  detectHtmlComments,
  detectEncodedBlobs,
  detectInjection,
  detectCommands,
  detectSecrets,
  (ctx) => (ctx.kind === 'mcp-config' || ctx.kind === 'claude-json' || ctx.kind === 'codex-config' ? detectMcp(ctx) : []),
  (ctx) => (ctx.kind === 'claude-settings' || ctx.kind === 'mcp-config' ? detectClaudeSettings(ctx) : []),
  (ctx) => (ctx.kind === 'codex-config' ? detectCodexConfig(ctx) : []),
  (ctx) => (ctx.isMarkdown ? detectSkillMeta(ctx) : []),
];

interface Suppressions {
  file: Set<string> | 'all' | null;
  /** line -> rule ids ('all' = every rule) */
  lines: Map<number, Set<string> | 'all'>;
}

const DIRECTIVE = /promptwarden-ignore(-file|-next-line|-line)?\b([^\n]*)/g;

export function parseSuppressions(ctx: FileContext): Suppressions {
  const res: Suppressions = { file: null, lines: new Map() };
  for (const m of ctx.content.matchAll(DIRECTIVE)) {
    const ids = new Set((m[2]!.split(/-->|\*\//)[0]!.match(/\bPW\d{3}\b/gi) ?? []).map((s) => s.toUpperCase()));
    const target: Set<string> | 'all' = ids.size ? ids : 'all';
    if (m[1] === '-file') {
      if (target === 'all' || res.file === 'all') res.file = 'all';
      else res.file = new Set([...(res.file ?? []), ...target]);
      continue;
    }
    const { line } = ctx.lines.position(m.index!);
    // A directive covers its own line and the next line.
    for (const l of [line, line + 1]) {
      const prev = res.lines.get(l);
      if (target === 'all' || prev === 'all') res.lines.set(l, 'all');
      else res.lines.set(l, new Set([...(prev ?? []), ...target]));
    }
  }
  return res;
}

function isSuppressed(s: Suppressions, ruleId: string, line: number): boolean {
  if (s.file === 'all' || s.file?.has(ruleId)) return true;
  const l = s.lines.get(line);
  return l === 'all' || (l?.has(ruleId) ?? false);
}

export function displayPath(abs: string, cwd: string): string {
  const rel = relative(cwd, abs);
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) return abs.split(sep).join('/');
  return rel.split(sep).join('/');
}

export interface ScanContentOptions {
  /** Path used for display and classification. */
  path: string;
  kind: FileKind;
  absolutePath?: string;
  disableRules?: string[];
  minSeverity?: Severity;
}

/** Scan a single in-memory file. */
export function scanContent(content: string, opts: ScanContentOptions): Finding[] {
  const absolutePath = opts.absolutePath ?? resolve(opts.path);
  const ctx = createContext({ path: opts.path, absolutePath, kind: opts.kind, content });
  if (ctx.kind === 'claude-json') ctx.regions = mcpRegions(ctx);
  const disabled = new Set((opts.disableRules ?? []).map((r) => r.toUpperCase()));
  const minRank = SEVERITY_RANK[opts.minSeverity ?? 'low'];

  let raw: RawFinding[] = [];
  for (const d of DETECTORS) raw.push(...d(ctx));

  raw = raw.filter((f) => {
    const rule = RULES_BY_ID.get(f.ruleId);
    if (!rule || disabled.has(rule.id)) return false;
    if (!rule.appliesTo.includes(ctx.kind)) return false;
    if (ctx.regions && !ctx.regions.some(([a, b]) => f.start >= a && f.start < b)) return false;
    return true;
  });

  // Escalation: injection text in a file that also hides content is much more likely malicious.
  const hides = raw.some((f) => ['PW001', 'PW002', 'PW004'].includes(f.ruleId));
  if (hides) {
    for (const f of raw) {
      if (f.ruleId === 'PW006' && f.severity !== 'low') f.severity = 'critical';
      if (f.ruleId === 'PW007') f.severity = 'high';
    }
  }

  const sup = parseSuppressions(ctx);
  const seen = new Map<string, number>();
  const findings: Finding[] = [];
  for (const f of raw) {
    const rule = RULES_BY_ID.get(f.ruleId)!;
    const pos = ctx.lines.position(f.start);
    const endPos = ctx.lines.position(Math.max(f.start, f.end));
    if (isSuppressed(sup, rule.id, pos.line)) continue;
    const severity = f.severity ?? rule.severity;
    if (SEVERITY_RANK[severity] < minRank) continue;
    const mask = f.mask ?? [];
    const lineText = ctx.lines.lineText(pos.line);
    const snippet = makeSnippet(lineText, pos.column - 1, f.end - f.start, mask);
    const matchRaw = ctx.content.slice(f.start, Math.min(f.end, f.start + 300));
    const match = truncate(renderVisible(maskSecrets(matchRaw, mask)), 160);
    const key = `${rule.id}|${opts.path}|${lineText.trim()}`;
    const n = seen.get(key) ?? 0;
    seen.set(key, n + 1);
    findings.push({
      ruleId: rule.id,
      ruleName: rule.name,
      title: rule.title,
      severity,
      category: rule.category,
      message: maskSecrets(f.message, mask).replace(/\s*\n\s*/g, ' '),
      file: opts.path,
      absolutePath,
      fileKind: ctx.kind,
      line: pos.line,
      column: pos.column,
      endLine: endPos.line,
      endColumn: endPos.column,
      snippet,
      match,
      remediation: rule.remediation,
      docsUrl: docsUrl(rule),
      fingerprint: createHash('sha256').update(`${key}|${n}`).digest('hex').slice(0, 32),
    });
  }
  return sortFindings(findings);
}

function makeSnippet(lineText: string, col: number, len: number, mask: string[]): string {
  // Render first (so hidden characters become visible tokens), then window around the match by code points.
  const before = renderVisible(maskSecrets(lineText.slice(0, col), mask));
  const hit = renderVisible(maskSecrets(lineText.slice(col, col + len), mask));
  const full = Array.from(renderVisible(maskSecrets(lineText, mask)).trimEnd());
  const MAX = 200;
  if (full.length <= MAX) return full.join('');
  const b = Array.from(before).length;
  const h = Array.from(hit).length;
  let start = Math.max(0, b - 50);
  let end = Math.min(full.length, Math.max(start + MAX, b + Math.min(h, MAX - 50)));
  if (end - start > MAX + 100) end = start + MAX + 100;
  if (end === full.length) start = Math.max(0, end - MAX);
  return (start > 0 ? '…' : '') + full.slice(start, end).join('') + (end < full.length ? '…' : '');
}

export function sortFindings(findings: Finding[]): Finding[] {
  return findings.sort(
    (a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.column - b.column || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.ruleId.localeCompare(b.ruleId),
  );
}

const CONFIG_KINDS = new Set<FileKind>(['claude-json', 'mcp-config', 'claude-settings', 'codex-config']);

function isProbablyBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

/** Scan files and directories for risky agent configuration. */
export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const t0 = performance.now();
  const cwd = options.cwd ?? process.cwd();
  const paths = options.paths?.length ? options.paths.map((p) => resolve(cwd, p)) : options.home ? [] : [cwd];
  const files = await discover({
    paths,
    home: options.home,
    homeDir: options.homeDir,
    allMarkdown: options.allMarkdown,
    ignore: options.ignore,
  });
  const maxSize = options.maxFileSize ?? 1024 * 1024;
  const findings: Finding[] = [];
  const errors: { file: string; error: string }[] = [];
  const scanned: { path: string; kind: FileKind }[] = [];
  let skipped = 0;

  await Promise.all(
    files.map(async (f) => {
      const display = displayPath(f.absolutePath, cwd);
      try {
        const st = await stat(f.absolutePath);
        const limit = CONFIG_KINDS.has(f.kind) ? Math.max(maxSize, 16 * 1024 * 1024) : maxSize;
        if (st.size > limit) {
          skipped++;
          return;
        }
        const buf = await readFile(f.absolutePath);
        if (isProbablyBinary(buf)) {
          skipped++;
          return;
        }
        const content = buf.toString('utf8');
        scanned.push({ path: display, kind: f.kind });
        findings.push(
          ...scanContent(content, {
            path: display,
            absolutePath: f.absolutePath,
            kind: f.kind,
            disableRules: options.disableRules,
            minSeverity: options.minSeverity,
          }),
        );
      } catch (e) {
        errors.push({ file: display, error: (e as Error).message });
      }
    }),
  );

  const summary = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) summary[f.severity]++;
  scanned.sort((a, b) => a.path.localeCompare(b.path));
  return {
    version: VERSION,
    findings: sortFindings(findings),
    files: scanned,
    stats: { filesScanned: scanned.length, filesSkipped: skipped, durationMs: Math.round(performance.now() - t0) },
    summary,
    errors,
  };
}

export { RULES };
