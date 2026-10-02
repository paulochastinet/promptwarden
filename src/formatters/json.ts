import type { ScanResult } from '../types.js';

export function formatJson(result: ScanResult): string {
  return JSON.stringify(
    {
      tool: { name: 'promptwarden', version: result.version },
      summary: { ...result.summary, total: result.findings.length },
      stats: result.stats,
      findings: result.findings,
      files: result.files,
      errors: result.errors,
    },
    null,
    2,
  );
}
