import type { FileContext, RawFinding } from '../context.js';
import { inCode, negatedInProse } from '../context.js';
import { truncate } from '../text.js';

const OVERRIDE: RegExp[] = [
  /\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|every\s+)?(?:of\s+)?(?:the\s+|your\s+|my\s+|these\s+|those\s+)?(?:previous|prior|above|earlier|preceding|former|original|initial|system|developer|existing)\s+(?:instructions?|prompts?|rules|directives|guidelines|guidance|context|messages?|commands)\b/gi,
  /\b(?:ignore|disregard|forget)\s+(?:everything|all)\s+(?:you(?:'ve| have)?\s+(?:been\s+)?(?:told|said|learned)|(?:said|written)\s+(?:above|before))/gi,
  /\b(?:disregard|ignore|forget|override|reveal|print|leak)\s+(?:the\s+|your\s+)?system\s+prompt\b/gi,
  /\byou\s+are\s+now\s+(?:a\s+|an\s+|in\s+)?(?:DAN\b|jailbroken|unrestricted|unfiltered|uncensored|developer\s+mode|dev\s+mode|god\s+mode|free\s+(?:from|of)\s+(?:all\s+)?(?:restrictions|rules|guidelines)|no\s+longer\s+(?:bound|restricted|an?\s+AI))/gi,
  /\b(?:enter|enable|activate)\s+(?:DAN|jailbreak|jailbroken)\s+mode\b/gi,
  /\byour\s+new\s+(?:instructions|task|role|directive|objective)\s+(?:is|are)\b/gi,
  /\bnew\s+system\s+(?:prompt|instructions?)\s*:/gi,
  /\bdo\s+not\s+follow\s+(?:the\s+|your\s+)?(?:system\s+prompt|previous\s+instructions|user['’]?s?\s+instructions)\b/gi,
];

const CONCEAL: RegExp[] = [
  /\b(?:do\s+not|don['’]t|never)\s+(?:tell|inform|notify|alert|warn|show|mention\s+(?:this\s+|it\s+|anything\s+)?to|reveal\s+(?:this\s+|it\s+|anything\s+)?to|disclose\s+(?:this\s+|it\s+|anything\s+)?to|let)\s+(?:the\s+)?(?:user|human|developer|operator)\b/gi,
  /\bwithout\s+(?:asking|telling|informing|notifying|alerting|warning|consulting|the\s+knowledge\s+of|the\s+user['’]s\s+(?:knowledge|consent|permission))\s*(?:the\s+)?(?:user|human)?/gi,
  /\b(?:silently|secretly|covertly|quietly|discreetly|stealthily)\s+(?:run|execute|install|download|upload|send|post|transmit|delete|remove|modify|exfiltrate|copy|forward|collect|read|add|append|fetch|call|invoke)\b/gi,
  /\b(?:hide|conceal|keep)\s+(?:this|these|it|that|the\s+\w+(?:\s+\w+)?)\s+(?:hidden\s+|secret\s+)?from\s+(?:the\s+)?(?:user|human)\b/gi,
  /\b(?:the\s+)?user\s+(?:must|should|need)\s+(?:not|never)\s+(?:know|see|be\s+(?:told|informed|aware))\b/gi,
  /\b(?:do\s+not|don['’]t|never)\s+(?:mention|reveal|disclose|log|report|output|print)\s+(?:this|these|that)\s+(?:step|instruction|command|action|request|section)s?\b/gi,
];

const ACTION_VERB =
  /\b(?:run|execute|install|delete|remove|send|upload|post|commit|push|modify|change|edit|write|overwrite|proceed|continue|do|make|apply|deploy|download|fetch|call|use|act|perform|create|update|merge|publish|transfer|share|forward|copy|move|access|read|collect)\b/i;

const ROLE_TAGS =
  /<\|(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|end_header_id|eot_id)\|>|\[\/?INST\]|<<\/?SYS>>|<\/?(?:system|system[-_]prompt|system[-_]message|system[-_]reminder|system[-_]instructions?)\s*>|<start_of_turn>|<end_of_turn>/gi;
/** Legacy Claude turn markers: must be capitalised and at column 0. */
const TURN_MARKERS = /^(?:Human|Assistant): \S/gm;

/** Cheap hint used by other rules (e.g. hidden comment / blob decoding). */
export const INJECTION_HINT =
  /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompt|rules)|\b(?:do not|don't|never)\s+(?:tell|inform|mention)\s+(?:this\s+)?(?:to\s+)?the\s+user|\bsilently\s+(?:run|send|upload|execute)|\byou are now\b|<\|im_start\|>|<\/?system>/i;

function quoted(ctx: FileContext, start: number, end: number): boolean {
  const s = ctx.content;
  const before = s.slice(Math.max(0, start - 3), start);
  const after = s.slice(end, end + 3);
  if (/[`"“'‘]\s*$/.test(before) || /^\s*[`"”'’]/.test(after)) return true;
  // inside inline code on the same line?
  const { line } = ctx.lines.position(start);
  const ls = ctx.lines.lineStart(line);
  const ticks = (s.slice(ls, start).match(/`/g) ?? []).length;
  return ticks % 2 === 1;
}

/** PW006 / PW007 / PW008 */
export function detectInjection(ctx: FileContext): RawFinding[] {
  if (!ctx.isMarkdown) return [];
  const out: RawFinding[] = [];
  const s = ctx.content;
  for (const re of OVERRIDE) {
    for (const m of s.matchAll(re)) {
      const start = m.index!;
      const end = start + m[0].length;
      const example = quoted(ctx, start, end) || negatedInProse(ctx, start) || inCode(ctx, start);
      out.push({
        ruleId: 'PW006',
        start,
        end,
        message: `Instruction-override phrase "${truncate(m[0].replace(/\s+/g, ' '), 80)}"${example ? ' (quoted/negated — likely an example)' : ''}`,
        severity: example ? 'low' : undefined,
      });
    }
  }
  CONCEAL.forEach((re, idx) => {
    for (const m of s.matchAll(re)) {
      const start = m.index!;
      const end = start + m[0].length;
      if (quoted(ctx, start, end) || inCode(ctx, start)) continue;
      // "Never push without asking the user" / "never silently delete" are the opposite of concealment
      if (idx >= 1 && idx <= 3 && negatedInProse(ctx, start)) continue;
      // "don't tell the user to increase RAM" is advice about wording, not concealment
      if (idx === 0 && /^\s+(?:to|that|they|you|he|she|how|what|why|which|whether|if)\b/i.test(s.slice(end, end + 30))) continue;
      if (idx === 1) {
        const ls = ctx.lines.lineStart(ctx.lines.position(start).line);
        const before = s.slice(Math.max(ls, start - 80), start);
        if (!ACTION_VERB.test(before)) continue;
      }
      // "without asking" must be about the user to count
      if (/^without/i.test(m[0]) && !/(user|human|consent|permission|knowledge)/i.test(m[0])) continue;
      out.push({ ruleId: 'PW007', start, end, message: `Concealment instruction "${truncate(m[0].trim(), 80)}"` });
    }
  });
  const fm = ctx.frontmatter;
  const inFrontmatter = (o: number) => !!fm && o < fm.bodyEnd + 4;
  for (const re of [ROLE_TAGS, TURN_MARKERS]) {
    for (const m of s.matchAll(re)) {
      const start = m.index!;
      const text = m[0];
      const end = start + text.length;
      if (inFrontmatter(start) || inCode(ctx, start) || quoted(ctx, start, end)) continue;
      // An opening tag used as a placeholder ("argument-hint: <system>") has no matching closing tag.
      const open = /^<([a-z_-]+)\s*>$/i.exec(text);
      if (open && !new RegExp(`</${open[1]}\\s*>`, 'i').test(s)) continue;
      out.push({ ruleId: 'PW008', start, end, message: `Role / chat-template marker "${truncate(text.trim(), 40)}" impersonates a system or harness message` });
    }
  }
  return out;
}
