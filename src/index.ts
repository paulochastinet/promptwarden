export { scan, scanContent, SEVERITY_RANK, type ScanContentOptions } from './scanner.js';
export { discover, classify, PROJECT_PATTERNS, HOME_PATTERNS } from './discover.js';
export { RULES, RULES_BY_ID, docsUrl } from './rules/meta.js';
export { formatText, type TextOptions } from './formatters/text.js';
export { formatJson } from './formatters/json.js';
export { formatSarif, toSarif, type SarifOptions } from './formatters/sarif.js';
export { formatMarkdown } from './formatters/markdown.js';
export { VERSION } from './version.js';
export { SEVERITIES } from './types.js';
export type { Category, FileKind, Finding, RuleMeta, ScanOptions, ScanResult, ScanStats, Severity } from './types.js';

import { SEVERITY_RANK } from './scanner.js';
import type { ScanResult, Severity } from './types.js';

/** True when the result contains a finding at or above `failOn`. */
export function shouldFail(result: ScanResult, failOn: Severity | 'none' = 'high'): boolean {
  if (failOn === 'none') return false;
  return result.findings.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK[failOn]);
}
