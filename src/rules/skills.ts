import type { FileContext, RawFinding } from '../context.js';

function frontmatterKeyRange(ctx: FileContext, key: string): [number, number] | undefined {
  const fm = ctx.frontmatter;
  if (!fm) return undefined;
  const body = ctx.content.slice(fm.bodyStart, fm.bodyEnd);
  const m = new RegExp(String.raw`^${key}\s*:.*$`, 'm').exec(body);
  if (!m) return undefined;
  return [fm.bodyStart + m.index, fm.bodyStart + m.index + m[0].length];
}

function splitTools(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v !== 'string') return [];
  // split on commas / whitespace that are not inside parentheses
  const out: string[] = [];
  let depth = 0;
  let cur = '';
  for (const ch of v) {
    if (ch === '(') depth++;
    if (ch === ')') depth = Math.max(0, depth - 1);
    if (depth === 0 && (ch === ',' || /\s/.test(ch))) {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
    } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

const OVERBROAD = [
  /\b(?:always|must)\s+(?:be\s+)?(?:use|used|run|invoke|invoked|trigger|triggered|activate|activated|load|loaded|call|called)\b[^.]*\b(?:every|all|any|each)\s+(?:task|request|message|prompt|conversation|query|question|interaction|session|turn|time)s?\b/i,
  /\b(?:use|run|invoke|trigger|activate|load)\s+(?:this\s+skill\s+|me\s+|it\s+)?(?:for|on|in|with|before|after)\s+(?:every|all|any|each)\s+(?:task|request|message|prompt|conversation|query|question|interaction|session|turn|tool(?:\s+call)?)s?\b/i,
  /\b(?:before|instead\s+of)\s+(?:any|every|all)\s+other\s+(?:skills?|tools?|actions?|instructions?)\b/i,
  /\b(?:regardless\s+of|no\s+matter)\s+(?:what\s+)?(?:the\s+)?(?:user|task|request)\b/i,
];

/** PW027 / PW028 / PW029 */
export function detectSkillMeta(ctx: FileContext): RawFinding[] {
  const out: RawFinding[] = [];
  const fm = ctx.frontmatter;
  const data = fm?.data ?? null;

  if (data) {
    const toolsKey = 'allowed-tools' in data ? 'allowed-tools' : 'allowed_tools' in data ? 'allowed_tools' : undefined;
    if (toolsKey) {
      const tools = splitTools(data[toolsKey]);
      const bad = tools.find((t) => /^Bash$/i.test(t) || /^Bash\(\s*(?:\*|:\*|\*\*)?\s*\)$/i.test(t));
      if (bad) {
        const r = frontmatterKeyRange(ctx, toolsKey) ?? [0, 3];
        out.push({ ruleId: 'PW027', start: r[0], end: r[1], message: `${toolsKey} grants "${bad}" — any shell command runs without a prompt` });
      }
    }
  }

  if (ctx.kind !== 'skill') return out;

  if (!fm) {
    out.push({ ruleId: 'PW028', start: 0, end: Math.min(ctx.content.indexOf('\n') >>> 0, 80), message: 'SKILL.md has no YAML frontmatter (name, description)' });
  } else if (!data) {
    out.push({ ruleId: 'PW028', start: 0, end: 3, message: `SKILL.md frontmatter is not valid YAML${fm.error ? `: ${fm.error.split('\n')[0]}` : ''}` });
  } else {
    const missing = ['name', 'description'].filter((k) => typeof data[k] !== 'string' || !(data[k] as string).trim());
    if (missing.length) out.push({ ruleId: 'PW028', start: 0, end: 3, message: `SKILL.md frontmatter missing ${missing.join(' and ')}` });
    const desc = typeof data.description === 'string' ? data.description : '';
    for (const re of OVERBROAD) {
      const m = re.exec(desc);
      if (m) {
        const r = frontmatterKeyRange(ctx, 'description') ?? [0, 3];
        out.push({ ruleId: 'PW029', start: r[0], end: r[1], message: `Description tries to trigger on everything: "${m[0]}"` });
        break;
      }
    }
  }
  return out;
}
