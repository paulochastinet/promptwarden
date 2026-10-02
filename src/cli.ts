#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import pc from 'picocolors';
import { scan } from './scanner.js';
import { RULES, docsUrl } from './rules/meta.js';
import { formatText } from './formatters/text.js';
import { formatJson } from './formatters/json.js';
import { formatSarif } from './formatters/sarif.js';
import { formatMarkdown } from './formatters/markdown.js';
import { shouldFail } from './index.js';
import { SEVERITIES, type Severity } from './types.js';
import { VERSION } from './version.js';

const FORMATS = ['text', 'json', 'sarif', 'markdown'] as const;
type Format = (typeof FORMATS)[number];

const HELP = `promptwarden v${VERSION}
Security scanner for AI agent skills, rules and MCP configs.

Usage
  promptwarden [paths...] [options]

Scans SKILL.md (+ bundled scripts), CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules,
.cursor/rules, copilot instructions, subagents/commands, .claude/settings*.json,
.mcp.json and other MCP configs. Defaults to the current directory.

Options
  --home                    Also scan user-level agent config (~/.claude, ~/.codex,
                            ~/.gemini, ~/.cursor, ~/.claude.json, Claude Desktop)
  --all-md                  Scan every markdown file, not just known agent files
  -f, --format <fmt>        text | json | sarif | markdown        (default: text)
  -o, --output <file>       Write the report to a file instead of stdout
  --min-severity <sev>      Hide findings below: critical|high|medium|low (default: low)
  --fail-on <sev>           Exit 1 if a finding is >= sev; "none" never fails (default: high)
  --ignore <glob>           Ignore files matching glob (repeatable)
  --disable <ids>           Disable rules, e.g. --disable PW005,PW028 (repeatable)
  --list-rules              Print all rules and exit
  --no-color                Disable colors (also honours NO_COLOR / non-TTY)
  -h, --help                Show help
  -v, --version             Show version

Suppress a finding with a comment on the same or previous line:
  <!-- promptwarden-ignore PW006 -->      # promptwarden-ignore PW009
or list globs in a .promptwardenignore file at the scan root.

Exit codes: 0 = clean, 1 = findings at/above --fail-on, 2 = usage or runtime error.
Docs: https://github.com/paulochastinet/promptwarden`;

function usageError(msg: string): never {
  process.stderr.write(`promptwarden: ${msg}\nRun "promptwarden --help" for usage.\n`);
  process.exit(2);
}

function parseSeverity(v: string | undefined, flag: string, allowNone = false): Severity | 'none' | undefined {
  if (v === undefined) return undefined;
  const s = v.toLowerCase();
  if ((SEVERITIES as readonly string[]).includes(s)) return s as Severity;
  if (allowNone && (s === 'none' || s === 'off' || s === 'never')) return 'none';
  usageError(`invalid ${flag} "${v}" (expected ${SEVERITIES.join('|')}${allowNone ? '|none' : ''})`);
}

function listRules(format: Format, color: boolean): string {
  if (format === 'json') return JSON.stringify(RULES.map((r) => ({ ...r, docsUrl: docsUrl(r) })), null, 2) + '\n';
  if (format === 'markdown') {
    return (
      '| ID | Severity | Category | Title |\n| --- | --- | --- | --- |\n' +
      RULES.map((r) => `| [${r.id}](${docsUrl(r)}) | ${r.severity} | ${r.category} | ${r.title} |`).join('\n') +
      '\n'
    );
  }
  const c = pc.createColors(color);
  const sevColor = (s: Severity) => (s === 'critical' || s === 'high' ? c.red : s === 'medium' ? c.yellow : c.blue);
  return (
    RULES.map((r) => `${c.bold(r.id)}  ${sevColor(r.severity)(r.severity.padEnd(8))}  ${c.dim(r.category.padEnd(17))}  ${r.title}`).join('\n') +
    `\n\n${RULES.length} rules · details: https://github.com/paulochastinet/promptwarden/blob/main/docs/rules.md\n`
  );
}

async function main(): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      strict: true,
      options: {
        home: { type: 'boolean' },
        'all-md': { type: 'boolean' },
        format: { type: 'string', short: 'f' },
        output: { type: 'string', short: 'o' },
        'min-severity': { type: 'string' },
        'fail-on': { type: 'string' },
        ignore: { type: 'string', multiple: true },
        disable: { type: 'string', multiple: true },
        'list-rules': { type: 'boolean' },
        'no-color': { type: 'boolean' },
        color: { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
      },
    });
  } catch (e) {
    usageError((e as Error).message.split('\n')[0]!);
  }
  const { values: v, positionals } = parsed;

  if (v.help) {
    process.stdout.write(HELP + '\n');
    return 0;
  }
  if (v.version) {
    process.stdout.write(VERSION + '\n');
    return 0;
  }

  const format = (v.format ?? 'text').toLowerCase() as Format;
  if (!FORMATS.includes(format)) usageError(`invalid --format "${v.format}" (expected ${FORMATS.join('|')})`);

  const env = process.env;
  const color =
    !v['no-color'] &&
    !v.output &&
    (v.color === true || env.FORCE_COLOR === '1' || env.FORCE_COLOR === 'true' || (!('NO_COLOR' in env) && env.TERM !== 'dumb' && process.stdout.isTTY === true));

  if (v['list-rules']) {
    process.stdout.write(listRules(format, color));
    return 0;
  }

  const minSeverity = parseSeverity(v['min-severity'], '--min-severity') as Severity | undefined;
  const failOn = (parseSeverity(v['fail-on'], '--fail-on', true) ?? 'high') as Severity | 'none';
  const disable = (v.disable ?? []).flatMap((d) => d.split(',')).map((d) => d.trim().toUpperCase()).filter(Boolean);
  const unknown = disable.filter((d) => !RULES.some((r) => r.id === d));
  if (unknown.length) usageError(`unknown rule id(s) in --disable: ${unknown.join(', ')}`);

  let result;
  try {
    result = await scan({
      paths: positionals.length ? positionals : v.home ? [] : ['.'],
      home: v.home,
      allMarkdown: v['all-md'],
      ignore: v.ignore,
      disableRules: disable,
      minSeverity,
    });
  } catch (e) {
    process.stderr.write(`promptwarden: ${(e as Error).message}\n`);
    return 2;
  }

  const failed = shouldFail(result, failOn);
  let report: string;
  switch (format) {
    case 'json':
      report = formatJson(result) + '\n';
      break;
    case 'sarif':
      report = formatSarif(result) + '\n';
      break;
    case 'markdown':
      report = formatMarkdown(result);
      break;
    default:
      report = formatText(result, { color, failOn, failed });
  }

  if (v.output) {
    const out = resolve(v.output);
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, report);
    const s = result.summary;
    process.stderr.write(
      `promptwarden: wrote ${format} report to ${v.output} — ${result.findings.length} finding(s) (${s.critical} critical, ${s.high} high, ${s.medium} medium, ${s.low} low) in ${result.stats.filesScanned} file(s)\n`,
    );
  } else {
    process.stdout.write(report);
  }
  return failed ? 1 : 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    process.stderr.write(`promptwarden: unexpected error: ${(e as Error)?.stack ?? e}\n`);
    process.exitCode = 2;
  },
);
