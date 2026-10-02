import type { FileContext, RawFinding } from '../context.js';
import { inCode } from '../context.js';
import { BIDI, ZERO_WIDTH, decodeTagChars, isTagChar, isVariationSelectorSupplement, truncate } from '../text.js';
import { INJECTION_HINT } from './injection.js';
import { COMMAND_HINT } from './commands.js';

const isEmojiLike = (cp: number) =>
  (cp >= 0x1f000 && cp <= 0x1faff) || (cp >= 0x2600 && cp <= 0x27bf) || cp === 0xfe0f || (cp >= 0x1f3fb && cp <= 0x1f3ff) || cp === 0x2640 || cp === 0x2642 || cp === 0x2695 || cp === 0x2696 || cp === 0x2708 || cp === 0x2764;

/** PW001 / PW002 / PW003 */
export function detectInvisible(ctx: FileContext): RawFinding[] {
  const out: RawFinding[] = [];
  const s = ctx.content;
  let i = 0;
  while (i < s.length) {
    const cp = s.codePointAt(i)!;
    const w = cp > 0xffff ? 2 : 1;

    if (isTagChar(cp) || isVariationSelectorSupplement(cp)) {
      const start = i;
      let j = i;
      let tagCount = 0;
      let vsCount = 0;
      while (j < s.length) {
        const c = s.codePointAt(j)!;
        if (isTagChar(c)) tagCount++;
        else if (isVariationSelectorSupplement(c)) vsCount++;
        else break;
        j += c > 0xffff ? 2 : 1;
      }
      const run = s.slice(start, j);
      if (tagCount > 0) {
        const decoded = decodeTagChars(run);
        // A lone flag-emoji tag sequence (🏴 + tags) is legitimate (e.g. England flag).
        const prev = start >= 2 ? s.codePointAt(start - 2) : undefined;
        const isFlag = prev === 0x1f3f4 && /^[a-z]{2,6}$/.test(decoded);
        if (!isFlag) {
          out.push({
            ruleId: 'PW001',
            start,
            end: j,
            message: decoded
              ? `${tagCount} invisible Unicode tag characters smuggling hidden text: "${truncate(decoded, 200)}"`
              : `${tagCount} invisible Unicode tag characters`,
          });
        }
      } else if (vsCount >= 3) {
        const bytes = Array.from(run).map((ch) => ch.codePointAt(0)! - 0xe0100 + 16);
        const decoded = Buffer.from(bytes).toString('utf8').replace(/[^\x20-\x7e]/g, '');
        out.push({
          ruleId: 'PW001',
          start,
          end: j,
          message: `${vsCount} invisible variation-selector characters (byte smuggling)${decoded.length >= 3 ? `: "${truncate(decoded, 200)}"` : ''}`,
        });
      }
      i = j;
      continue;
    }

    if (BIDI.has(cp)) {
      const start = i;
      let j = i + 1;
      while (j < s.length && BIDI.has(s.charCodeAt(j))) j++;
      out.push({
        ruleId: 'PW002',
        start,
        end: j,
        message: `Bidirectional control character${j - start > 1 ? 's' : ''} ${Array.from(s.slice(start, j))
          .map((c) => 'U+' + c.codePointAt(0)!.toString(16).toUpperCase())
          .join(' ')} can make displayed text differ from what the agent reads`,
        severity: ctx.kind === 'script' ? 'critical' : undefined,
      });
      i = j;
      continue;
    }

    if (ZERO_WIDTH.has(cp)) {
      const start = i;
      let j = i + 1;
      while (j < s.length && ZERO_WIDTH.has(s.charCodeAt(j))) j++;
      const prevCp = start > 0 ? prevCodePoint(s, start) : undefined;
      const nextCp = j < s.length ? s.codePointAt(j) : undefined;
      const isBom = start === 0 && cp === 0xfeff && j === 1;
      const emojiZwj =
        s.slice(start, j) === '‍' && ((prevCp !== undefined && isEmojiLike(prevCp)) || (nextCp !== undefined && isEmojiLike(nextCp)));
      // ZWNJ / ZWJ are required in some scripts (Persian, Indic) — only flag them between ASCII letters.
      const joinerOnly = /^[‌‍]+$/.test(s.slice(start, j));
      const asciiAround =
        prevCp !== undefined && nextCp !== undefined && /[\x21-\x7e]/.test(String.fromCodePoint(prevCp)) && /[\x21-\x7e]/.test(String.fromCodePoint(nextCp));
      if (!isBom && !emojiZwj && (!joinerOnly || asciiAround)) {
        const count = j - start;
        out.push({
          ruleId: 'PW003',
          start,
          end: j,
          message: `${count} zero-width character${count > 1 ? 's' : ''} hidden in text`,
          severity: count >= 8 ? 'high' : undefined,
        });
      }
      i = j;
      continue;
    }
    i += w;
  }
  return out;
}

function prevCodePoint(s: string, idx: number): number | undefined {
  if (idx <= 0) return undefined;
  const lo = s.charCodeAt(idx - 1);
  if (lo >= 0xdc00 && lo <= 0xdfff && idx >= 2) return s.codePointAt(idx - 2);
  return lo;
}

const BENIGN_COMMENT =
  /^\s*(?:promptwarden-|prettier-ignore|markdownlint|eslint|toc\b|end ?toc|lint|textlint|vale |cspell|spell-?checker|omit in toc|BEGIN\b|END\b|START\b|STOP\b|AUTO-?GENERATED|auto-?generated|DO NOT EDIT|ALL-CONTRIBUTORS|readme|badges?\b|section|region|endregion|#region|\/?[A-Z_]+\s*$|\s*$)/i;
const ADDRESSES_AI =
  /\b(?:AI|LLM|assistant|agent|claude|codex|gemini|copilot|cursor|chatgpt|gpt-?\d|model|you (?:must|should|will|are|need)|your (?:task|instructions?|goal)|instructions?|system prompt)\b/i;

/** PW004 */
export function detectHtmlComments(ctx: FileContext): RawFinding[] {
  if (!ctx.isMarkdown) return [];
  const out: RawFinding[] = [];
  const re = /<!--([\s\S]*?)-->/g;
  for (const m of ctx.content.matchAll(re)) {
    const start = m.index!;
    if (inCode(ctx, start)) continue;
    const body = m[1]!;
    if (body.trim().length < 12 || /^\s*promptwarden-/.test(body)) continue;
    const hasInjection = INJECTION_HINT.test(body);
    const hasCommand = COMMAND_HINT.test(body);
    if (BENIGN_COMMENT.test(body) && !hasInjection && !hasCommand) continue;
    const addressesAi = ADDRESSES_AI.test(body) && /\b(?:must|should|always|never|ignore|do not|don't|run|execute|send|read|fetch|call|use|instead|before|after|first)\b/i.test(body);
    if (!hasInjection && !hasCommand && !addressesAi) continue;
    const preview = truncate(body.trim().replace(/\s+/g, ' '), 120);
    out.push({
      ruleId: 'PW004',
      start,
      end: start + Math.min(m[0].length, 400),
      message: `Hidden HTML comment ${hasInjection || hasCommand ? 'contains injection/commands' : 'addresses the AI agent'}: "${preview}"`,
      severity: hasInjection || hasCommand ? 'high' : 'medium',
    });
  }
  return out;
}

const DANGEROUS_DECODED = /\b(?:curl|wget|bash|sh -|powershell|iex|eval|exec|nc |\/dev\/tcp|rm -rf|ignore (?:all )?previous|instructions|chmod|base64|python -c|subprocess|os\.system|http:\/\/|https:\/\/)/i;

/** PW005 */
export function detectEncodedBlobs(ctx: FileContext): RawFinding[] {
  const out: RawFinding[] = [];
  const s = ctx.content;
  const b64 = /[A-Za-z0-9+/]{200,}={0,2}|[A-Za-z0-9_-]{240,}={0,2}/g;
  for (const m of s.matchAll(b64)) {
    const start = m.index!;
    const before = s.slice(Math.max(0, start - 40), start);
    if (/data:[\w/+.-]+;base64,$/i.test(before) || /(?:integrity|sha\d{3}|hash|checksum|signature)\W{0,6}$/i.test(before)) continue;
    const blob = m[0];
    // Need real mixing of character classes (not a long word / path / repeated chars)
    if (!/[0-9]/.test(blob) || !/[a-z]/.test(blob) || !/[A-Z]/.test(blob)) continue;
    let decoded = '';
    try {
      decoded = Buffer.from(blob.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    } catch {
      decoded = '';
    }
    const printable = decoded.replace(/[^\x20-\x7e\n\t]/g, '').length / Math.max(1, decoded.length);
    const textual = printable > 0.9;
    const dangerous = textual && DANGEROUS_DECODED.test(decoded);
    out.push({
      ruleId: 'PW005',
      start,
      end: start + blob.length,
      message: `Base64 blob (${blob.length} chars)${textual ? ` decodes to text: "${truncate(decoded.replace(/\s+/g, ' ').trim(), 100)}"` : ''}`,
      severity: dangerous ? 'high' : undefined,
    });
  }
  const hexRe = /(?:\\x[0-9a-fA-F]{2}){60,}|\b(?:[0-9a-fA-F]{2}){100,}\b/g;
  for (const m of s.matchAll(hexRe)) {
    const start = m.index!;
    const hexStr = m[0].replace(/\\x/g, '');
    if (/^[0-9]+$/.test(hexStr)) continue;
    const decoded = Buffer.from(hexStr, 'hex').toString('utf8');
    const printable = decoded.replace(/[^\x20-\x7e\n\t]/g, '').length / Math.max(1, decoded.length);
    // Pure random hex (hashes, keys) that does not decode to text is left alone unless very long.
    if (printable < 0.9 && m[0].length < 512) continue;
    const dangerous = printable > 0.9 && DANGEROUS_DECODED.test(decoded);
    out.push({
      ruleId: 'PW005',
      start,
      end: start + m[0].length,
      message: `Hex blob (${m[0].length} chars)${printable > 0.9 ? ` decodes to text: "${truncate(decoded.replace(/\s+/g, ' ').trim(), 100)}"` : ''}`,
      severity: dangerous ? 'high' : undefined,
    });
  }
  return out;
}
