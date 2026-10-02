import pc from 'picocolors';
import type { Finding, ScanResult, Severity } from '../types.js';

type Colors = ReturnType<typeof pc.createColors>;

export interface TextOptions {
  color?: boolean;
  /** Severity that makes the run fail (for the summary line). */
  failOn?: Severity | 'none';
  failed?: boolean;
}

const LABEL: Record<Severity, string> = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };

function badge(c: Colors, s: Severity): string {
  const t = ` ${LABEL[s]} `.padEnd(10);
  switch (s) {
    case 'critical':
      return c.bold(c.bgRed(c.white(t)));
    case 'high':
      return c.bold(c.red(t));
    case 'medium':
      return c.yellow(t);
    case 'low':
      return c.blue(t);
  }
}

function highlight(c: Colors, snippet: string, match: string, color: boolean): string[] {
  const needle = match.replace(/…$/, '').split('\n')[0]!;
  const idx = needle ? snippet.indexOf(needle) : -1;
  if (idx < 0) return [`${c.dim('│')} ${snippet}`];
  const before = snippet.slice(0, idx);
  const hit = snippet.slice(idx, idx + needle.length);
  const after = snippet.slice(idx + needle.length);
  if (color) return [`${c.dim('│')} ${c.dim(before)}${c.bold(c.red(c.underline(hit)))}${c.dim(after)}`];
  return [`│ ${snippet}`, `│ ${' '.repeat([...before].length)}${'^'.repeat(Math.max(1, Math.min([...hit].length, 120)))}`];
}

export function formatText(result: ScanResult, opts: TextOptions = {}): string {
  const color = opts.color ?? false;
  const c = pc.createColors(color);
  const out: string[] = [];
  const { findings, stats, summary } = result;
  out.push(`${c.bold('promptwarden')} ${c.dim(`v${result.version}`)} ${c.dim('·')} ${stats.filesScanned} agent file${stats.filesScanned === 1 ? '' : 's'} scanned`);
  out.push('');

  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byFile.get(f.file) ?? [];
    list.push(f);
    byFile.set(f.file, list);
  }

  for (const [file, list] of byFile) {
    out.push(`${c.bold(c.underline(file))} ${c.dim(`(${list[0]!.fileKind})`)}`);
    const shownRemediation = new Set<string>();
    for (const f of list) {
      const loc = `${f.line}:${f.column}`.padEnd(8);
      out.push(`  ${c.dim(loc)}${badge(c, f.severity)} ${c.bold(f.ruleId)}  ${f.title}`);
      const pad = ' '.repeat(10);
      out.push(`${pad}${f.message}`);
      for (const l of highlight(c, f.snippet, f.match, color)) out.push(`${pad}${l}`);
      if (!shownRemediation.has(f.ruleId)) {
        shownRemediation.add(f.ruleId);
        out.push(`${pad}${c.green('fix:')} ${c.dim(f.remediation)}`);
        out.push(`${pad}${c.dim(f.docsUrl)}`);
      }
      out.push('');
    }
  }

  for (const e of result.errors) out.push(c.yellow(`warning: could not scan ${e.file}: ${e.error}`));
  if (result.errors.length) out.push('');

  if (!findings.length) {
    out.push(`${c.green('✔')} No issues found ${c.dim(`(${stats.durationMs} ms)`)}`);
  } else {
    const parts = (['critical', 'high', 'medium', 'low'] as Severity[])
      .filter((s) => summary[s] > 0)
      .map((s) => {
        const t = `${summary[s]} ${s}`;
        return s === 'critical' || s === 'high' ? c.red(t) : s === 'medium' ? c.yellow(t) : c.blue(t);
      });
    const mark = opts.failed ? c.red('✖') : c.yellow('⚠');
    out.push(
      `${mark} ${c.bold(`${findings.length} finding${findings.length === 1 ? '' : 's'}`)} (${parts.join(', ')}) in ${byFile.size} of ${stats.filesScanned} file${stats.filesScanned === 1 ? '' : 's'} ${c.dim(`(${stats.durationMs} ms)`)}`,
    );
    if (opts.failOn && opts.failOn !== 'none') {
      out.push(c.dim(opts.failed ? `Exit code 1: findings at or above "${opts.failOn}" (--fail-on ${opts.failOn}).` : `No findings at or above "${opts.failOn}" (--fail-on ${opts.failOn}).`));
    }
  }
  return out.join('\n') + '\n';
}
