import type { ScanResult } from '../types.js';

const ICON = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' } as const;
const esc = (s: string) => s.replace(/\|/g, '\\|').replace(/\n/g, ' ').replace(/</g, '&lt;');

export function formatMarkdown(result: ScanResult): string {
  const { summary, findings, stats } = result;
  const lines: string[] = [];
  lines.push('## promptwarden report', '');
  if (!findings.length) {
    lines.push(`✅ No findings in ${stats.filesScanned} agent file(s).`);
    return lines.join('\n') + '\n';
  }
  lines.push(
    `**${findings.length} finding(s)** in ${new Set(findings.map((f) => f.file)).size} of ${stats.filesScanned} file(s): ` +
      `${summary.critical} critical · ${summary.high} high · ${summary.medium} medium · ${summary.low} low`,
    '',
    '| Severity | Rule | Location | Finding |',
    '| --- | --- | --- | --- |',
  );
  for (const f of findings) {
    lines.push(`| ${ICON[f.severity]} ${f.severity} | [${f.ruleId}](${f.docsUrl}) | \`${esc(f.file)}:${f.line}:${f.column}\` | ${esc(f.message)} |`);
  }
  lines.push('', `<sub>promptwarden v${result.version} · ${stats.durationMs} ms</sub>`);
  return lines.join('\n') + '\n';
}
