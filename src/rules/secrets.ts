import type { FileContext, RawFinding } from '../context.js';
import { findSecrets } from '../text.js';

/** PW017 */
export function detectSecrets(ctx: FileContext): RawFinding[] {
  return findSecrets(ctx.content).map((m) => ({
    ruleId: 'PW017',
    start: m.start,
    end: m.end,
    message: `${m.name} hard-coded in ${ctx.kind === 'mcp-config' || ctx.kind === 'claude-json' || ctx.kind === 'codex-config' ? 'MCP config' : 'agent file'}`,
    mask: [m.value],
  }));
}
