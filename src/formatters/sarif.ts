import { pathToFileURL } from 'node:url';
import { RULES, docsUrl } from '../rules/meta.js';
import type { ScanResult, Severity } from '../types.js';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note' };
/** GitHub code scanning maps security-severity to critical (>=9), high (7–8.9), medium (4–6.9), low. */
const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0' };

export interface SarifOptions {
  /** Directory relative paths are resolved against (becomes %SRCROOT%). */
  cwd?: string;
}

export function toSarif(result: ScanResult, opts: SarifOptions = {}) {
  const cwd = opts.cwd ?? process.cwd();
  const ruleIndex = new Map(RULES.map((r, i) => [r.id, i]));
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'promptwarden',
            semanticVersion: result.version,
            version: result.version,
            informationUri: 'https://github.com/paulochastinet/promptwarden',
            rules: RULES.map((r) => ({
              id: r.id,
              name: r.name.replace(/(^|-)([a-z])/g, (_m, _d, c: string) => c.toUpperCase()),
              shortDescription: { text: r.title },
              fullDescription: { text: r.description },
              helpUri: docsUrl(r),
              help: {
                text: `${r.description}\n\nRemediation: ${r.remediation}`,
                markdown: `**${r.title}**\n\n${r.description}\n\n**Remediation:** ${r.remediation}\n\n[Rule documentation](${docsUrl(r)})`,
              },
              defaultConfiguration: { level: LEVEL[r.severity] },
              properties: {
                tags: ['security', 'ai-agents', r.category],
                precision: r.severity === 'low' ? 'medium' : 'high',
                'problem.severity': r.severity === 'critical' || r.severity === 'high' ? 'error' : r.severity === 'medium' ? 'warning' : 'recommendation',
                'security-severity': SECURITY_SEVERITY[r.severity],
              },
            })),
          },
        },
        originalUriBaseIds: {
          '%SRCROOT%': { uri: pathToFileURL(cwd.endsWith('/') ? cwd : cwd + '/').href },
        },
        results: result.findings.map((f) => {
          const outside = f.file.startsWith('/') || /^[A-Za-z]:/.test(f.file);
          return {
            ruleId: f.ruleId,
            ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
            level: LEVEL[f.severity],
            message: { text: `${f.message}\n${f.remediation}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: outside ? { uri: pathToFileURL(f.absolutePath).href } : { uri: encodeURI(f.file), uriBaseId: '%SRCROOT%' },
                  region: {
                    startLine: f.line,
                    startColumn: f.column,
                    endLine: f.endLine,
                    endColumn: Math.max(f.endColumn, f.endLine === f.line ? f.column + 1 : 1),
                    snippet: { text: f.snippet },
                  },
                },
              },
            ],
            partialFingerprints: { 'promptwarden/v1': f.fingerprint },
            properties: { severity: f.severity, category: f.category, 'security-severity': SECURITY_SEVERITY[f.severity] },
          };
        }),
        invocations: [{ executionSuccessful: result.errors.length === 0, toolExecutionNotifications: result.errors.map((e) => ({ level: 'warning', message: { text: `${e.file}: ${e.error}` } })) }],
      },
    ],
  };
}

export function formatSarif(result: ScanResult, opts: SarifOptions = {}): string {
  return JSON.stringify(toSarif(result, opts), null, 2);
}
