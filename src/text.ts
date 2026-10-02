/** Text helpers: positions, invisible-character rendering, secret masking. */

export class LineIndex {
  private readonly starts: number[];
  constructor(private readonly text: string) {
    const starts = [0];
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10) starts.push(i + 1);
    }
    this.starts = starts;
  }

  get lineCount(): number {
    return this.starts.length;
  }

  /** 1-based line and column (column counted in UTF-16 code units, like editors / SARIF default). */
  position(offset: number): { line: number; column: number } {
    let lo = 0;
    let hi = this.starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.starts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - this.starts[lo]! + 1 };
  }

  lineStart(line: number): number {
    return this.starts[line - 1] ?? this.text.length;
  }

  lineText(line: number): string {
    const start = this.lineStart(line);
    const next = this.starts[line];
    let end = next === undefined ? this.text.length : next - 1;
    if (end > start && this.text.charCodeAt(end - 1) === 13) end--;
    return this.text.slice(start, end);
  }
}

export function isTagChar(cp: number): boolean {
  return cp >= 0xe0000 && cp <= 0xe007f;
}

export function isVariationSelectorSupplement(cp: number): boolean {
  return cp >= 0xe0100 && cp <= 0xe01ef;
}

export const ZERO_WIDTH = new Set([0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x180e, 0x2061, 0x2062, 0x2063, 0x2064]);
export const BIDI = new Set([0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]);

function isInvisible(cp: number): boolean {
  return (
    isTagChar(cp) ||
    isVariationSelectorSupplement(cp) ||
    ZERO_WIDTH.has(cp) ||
    BIDI.has(cp) ||
    cp === 0x200e ||
    cp === 0x200f ||
    cp === 0x00ad ||
    (cp < 0x20 && cp !== 9 && cp !== 10 && cp !== 13) ||
    cp === 0x7f
  );
}

const hex = (cp: number) => cp.toString(16).toUpperCase().padStart(4, '0');

/** Decode a run of Unicode tag characters into the ASCII they smuggle. */
export function decodeTagChars(s: string): string {
  let out = '';
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  }
  return out;
}

/**
 * Render invisible / control characters visibly, e.g. `<U+200B>`.
 * Runs of Unicode tag characters are collapsed and decoded: `<TAG×12 "hello">`.
 */
export function renderVisible(s: string): string {
  let out = '';
  const chars = Array.from(s);
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i]!;
    const cp = ch.codePointAt(0)!;
    if (isTagChar(cp)) {
      let j = i;
      while (j < chars.length && isTagChar(chars[j]!.codePointAt(0)!)) j++;
      const run = chars.slice(i, j).join('');
      const decoded = decodeTagChars(run);
      out += `<U+E00xx×${j - i} tags${decoded ? ` "${truncate(decoded, 60)}"` : ''}>`;
      i = j - 1;
    } else if (isVariationSelectorSupplement(cp)) {
      let j = i;
      while (j < chars.length && isVariationSelectorSupplement(chars[j]!.codePointAt(0)!)) j++;
      out += j - i > 1 ? `<U+${hex(cp)}…×${j - i} variation selectors>` : `<U+${hex(cp)}>`;
      i = j - 1;
    } else if (isInvisible(cp)) {
      out += `<U+${hex(cp)}>`;
    } else if (cp === 9) {
      out += '  ';
    } else {
      out += ch;
    }
  }
  return out;
}

export function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 1) + '…';
}

/** Shannon entropy in bits per char. */
export function entropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let e = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

export interface SecretPattern {
  name: string;
  re: RegExp;
  /** Number of leading chars that are a public prefix (kept when masking). */
  prefix: number;
}

/** Known credential formats. Each regex must be global. */
export const SECRET_PATTERNS: SecretPattern[] = [
  { name: 'Anthropic API key', re: /\bsk-ant-(?:api|admin|oat)\d{2}-[A-Za-z0-9_-]{40,}/g, prefix: 7 },
  { name: 'OpenAI API key', re: /\bsk-(?:proj-|svcacct-|admin-)?(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])/g, prefix: 3 },
  { name: 'GitHub token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/g, prefix: 4 },
  { name: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{50,255}\b/g, prefix: 11 },
  { name: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g, prefix: 6 },
  { name: 'AWS access key id', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, prefix: 4 },
  { name: 'Slack token', re: /\bxox[abposr]-[0-9A-Za-z-]{10,}\b/g, prefix: 5 },
  { name: 'Slack webhook', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g, prefix: 30 },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, prefix: 4 },
  { name: 'Stripe live key', re: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/g, prefix: 8 },
  { name: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/g, prefix: 4 },
  { name: 'Hugging Face token', re: /\bhf_[A-Za-z]{34,}\b/g, prefix: 3 },
  { name: 'Private key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g, prefix: 0 },
];

const PLACEHOLDER = /(x{4,}|\.\.\.|<|>|your[_-]?|example|placeholder|dummy|redacted|changeme|0{8,}|1234567890|abcdef(?:ghij)?)/i;
const AWS_DOC_KEYS = new Set(['AKIAIOSFODNN7EXAMPLE', 'AKIAI44QH8DHBEXAMPLE']);

/** Heuristic: is this match a real-looking secret rather than a placeholder? */
export function looksLikeRealSecret(value: string, pattern: SecretPattern): boolean {
  if (pattern.name === 'Private key') return true;
  if (AWS_DOC_KEYS.has(value)) return false;
  const body = value.slice(pattern.prefix);
  if (PLACEHOLDER.test(body)) return false;
  if (/(.)\1{7,}/.test(body)) return false;
  return entropy(body) >= 3.0;
}

export interface SecretMatch {
  name: string;
  start: number;
  end: number;
  value: string;
}

export function findSecrets(text: string): SecretMatch[] {
  const out: SecretMatch[] = [];
  const taken: [number, number][] = [];
  for (const p of SECRET_PATTERNS) {
    p.re.lastIndex = 0;
    for (const m of text.matchAll(p.re)) {
      const start = m.index!;
      const end = start + m[0].length;
      if (taken.some(([a, b]) => start < b && end > a)) continue;
      if (!looksLikeRealSecret(m[0], p)) continue;
      taken.push([start, end]);
      out.push({ name: p.name, start, end, value: m[0] });
    }
  }
  return out;
}

export function maskValue(value: string, keep = 4): string {
  if (value.startsWith('-----BEGIN')) return value;
  const k = Math.min(keep, Math.max(0, Math.floor(value.length / 3)));
  return value.slice(0, k) + '*'.repeat(Math.min(12, Math.max(4, value.length - k)));
}

/** Mask every known secret format in a string. */
export function maskSecrets(text: string, extra: string[] = []): string {
  let out = text;
  for (const p of SECRET_PATTERNS) {
    if (p.name === 'Private key') continue;
    out = out.replace(p.re, (m) => (looksLikeRealSecret(m, p) ? maskValue(m, p.prefix) : m));
  }
  for (const v of extra) {
    if (v.length >= 4) out = out.split(v).join(maskValue(v));
  }
  return out;
}
