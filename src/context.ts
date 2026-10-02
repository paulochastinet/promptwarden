import { parseTree, type Node as JsonNode } from 'jsonc-parser';
import { parse as parseYaml } from 'yaml';
import { parse as parseToml } from 'smol-toml';
import type { FileKind, Severity } from './types.js';
import { LineIndex } from './text.js';

export interface Frontmatter {
  data: Record<string, unknown> | null;
  /** offset of the first char after the opening `---\n` */
  bodyStart: number;
  /** offset of the closing `---` */
  bodyEnd: number;
  error?: string;
}

export interface FileContext {
  /** display path */
  path: string;
  absolutePath: string;
  kind: FileKind;
  content: string;
  lines: LineIndex;
  isMarkdown: boolean;
  /** Fenced code block ranges [start, end) in markdown files. */
  codeRanges: [number, number][];
  frontmatter?: Frontmatter;
  json?: JsonNode;
  toml?: Record<string, unknown>;
  /** If set, findings outside these ranges are dropped (used for ~/.claude.json). */
  regions?: [number, number][];
}

export interface RawFinding {
  ruleId: string;
  start: number;
  end: number;
  message: string;
  severity?: Severity;
  /** Literal secret values to mask in snippet/match. */
  mask?: string[];
}

const MD_KINDS = new Set<FileKind>(['skill', 'skill-doc', 'instructions', 'markdown']);

export function createContext(opts: { path: string; absolutePath: string; kind: FileKind; content: string }): FileContext {
  const { content, kind } = opts;
  const ctx: FileContext = {
    ...opts,
    lines: new LineIndex(content),
    isMarkdown: MD_KINDS.has(kind) && !/\.(?:txt)$/i.test(opts.path),
    codeRanges: [],
  };
  if (ctx.isMarkdown) {
    ctx.codeRanges = fencedCodeRanges(content);
    ctx.frontmatter = parseFrontmatter(content);
  }
  if (kind === 'claude-settings' || kind === 'mcp-config' || kind === 'claude-json') {
    ctx.json = parseTree(content, [], { allowTrailingComma: true, disallowComments: false });
  }
  if (kind === 'codex-config') {
    try {
      ctx.toml = parseToml(content) as Record<string, unknown>;
    } catch {
      ctx.toml = undefined;
    }
  }
  return ctx;
}

export function parseFrontmatter(content: string): Frontmatter | undefined {
  const m = /^﻿?---[ \t]*\r?\n/.exec(content);
  if (!m) return undefined;
  const bodyStart = m[0].length;
  const close = /^---[ \t]*$/m;
  close.lastIndex = 0;
  const rest = content.slice(bodyStart);
  const c = close.exec(rest);
  if (!c) return undefined;
  const bodyEnd = bodyStart + c.index;
  const raw = content.slice(bodyStart, bodyEnd);
  try {
    const data = parseYaml(raw);
    return {
      data: data && typeof data === 'object' && !Array.isArray(data) ? (data as Record<string, unknown>) : null,
      bodyStart,
      bodyEnd,
    };
  } catch (e) {
    return { data: null, bodyStart, bodyEnd, error: (e as Error).message };
  }
}

export function fencedCodeRanges(content: string): [number, number][] {
  const ranges: [number, number][] = [];
  const re = /^[ \t]{0,3}(`{3,}|~{3,})[^\n]*$/gm;
  let open: { fence: string; start: number } | null = null;
  for (const m of content.matchAll(re)) {
    const fence = m[1]!;
    if (!open) {
      open = { fence, start: m.index! };
    } else if (fence[0] === open.fence[0] && fence.length >= open.fence.length && m[0].trim() === fence) {
      ranges.push([open.start, m.index! + m[0].length]);
      open = null;
    }
  }
  if (open) ranges.push([open.start, content.length]);
  return ranges;
}

export function inCode(ctx: FileContext, offset: number): boolean {
  return ctx.codeRanges.some(([a, b]) => offset >= a && offset < b);
}

const NEGATION = /\b(?:never|don['’]?t|do not|must not|mustn['’]?t|should not|shouldn['’]?t|avoid|forbid(?:den)?|prohibit(?:ed)?|disallow(?:ed)?|refuse|block(?:s|ed)?|reject|deny|not allowed|warn(?:s|ing)?|beware|detect(?:s|ed|ion)?|flag(?:s|ged)?|e\.g\.|such as|for example|example of|malicious|attack(?:er|s)?)\b/i;

/**
 * True when the match sits in a markdown prose line that negates / warns about it
 * ("Never run `rm -rf ~`", "detects phrases such as ...").
 */
export function negatedInProse(ctx: FileContext, offset: number): boolean {
  if (!ctx.isMarkdown || inCode(ctx, offset)) return false;
  const { line } = ctx.lines.position(offset);
  const lineStart = ctx.lines.lineStart(line);
  const before = ctx.content.slice(lineStart, offset);
  if (NEGATION.test(before)) return true;
  // table rows / list items describing rules often put the verb after
  const lineText = ctx.lines.lineText(line);
  return /^\s*\|/.test(lineText) && NEGATION.test(lineText);
}
