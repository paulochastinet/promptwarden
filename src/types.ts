export type Severity = 'critical' | 'high' | 'medium' | 'low';

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low'] as const;

export type Category =
  | 'hidden-content'
  | 'prompt-injection'
  | 'dangerous-command'
  | 'exfiltration'
  | 'secrets'
  | 'mcp'
  | 'permissions'
  | 'skill-metadata';

/**
 * What kind of agent-facing file this is. Determines which rules run.
 */
export type FileKind =
  /** SKILL.md */
  | 'skill'
  /** Markdown or text that lives inside a skill directory (references, templates). */
  | 'skill-doc'
  /** Executable script inside a skill / plugin directory (.sh, .py, .js, ...). */
  | 'script'
  /** CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, copilot instructions, subagents, commands... */
  | 'instructions'
  /** .claude/settings*.json and plugin hooks.json */
  | 'claude-settings'
  /** .mcp.json, .cursor/mcp.json, .vscode/mcp.json, claude_desktop_config.json, .gemini/settings.json, plugin manifests */
  | 'mcp-config'
  /** ~/.claude.json (only mcpServers sub-trees are inspected) */
  | 'claude-json'
  /** ~/.codex/config.toml */
  | 'codex-config'
  /** Any other markdown (only with --all-md) */
  | 'markdown';

export interface RuleMeta {
  id: string;
  /** kebab-case short name (used in SARIF `name`). */
  name: string;
  title: string;
  severity: Severity;
  category: Category;
  description: string;
  remediation: string;
  /** File kinds this rule applies to. */
  appliesTo: readonly FileKind[];
  /** Short examples of what triggers the rule (used in docs). */
  examples?: readonly string[];
}

export interface Finding {
  ruleId: string;
  ruleName: string;
  title: string;
  severity: Severity;
  category: Category;
  message: string;
  /** Path relative to the current working directory when possible (posix separators). */
  file: string;
  /** Absolute path. */
  absolutePath: string;
  fileKind: FileKind;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  /** The offending line, secrets masked, invisible characters rendered visibly. */
  snippet: string;
  /** The matched text, secrets masked, invisible characters rendered visibly. */
  match: string;
  remediation: string;
  docsUrl: string;
  /** Stable fingerprint (rule + file + normalized line content). */
  fingerprint: string;
}

export interface ScanOptions {
  /** Files or directories to scan. Defaults to [cwd]. */
  paths?: string[];
  /** Also scan user-level agent dirs (~/.claude, ~/.codex, ~/.gemini, ~/.cursor, ~/.claude.json ...). */
  home?: boolean;
  /** Override the home directory used for `home` (mostly for tests). */
  homeDir?: string;
  /** Scan every markdown file, not only known agent files. */
  allMarkdown?: boolean;
  /** Extra ignore globs (fast-glob syntax), relative to each scan root. */
  ignore?: string[];
  /** Rule ids to disable. */
  disableRules?: string[];
  /** Drop findings below this severity. Default: 'low' (keep all). */
  minSeverity?: Severity;
  /** Max file size in bytes. Default 1 MiB (config JSON files get 16 MiB). */
  maxFileSize?: number;
  /** Base directory for relative paths in output. Default process.cwd(). */
  cwd?: string;
}

export interface ScanStats {
  filesScanned: number;
  filesSkipped: number;
  durationMs: number;
}

export interface ScanResult {
  version: string;
  findings: Finding[];
  files: { path: string; kind: FileKind }[];
  stats: ScanStats;
  summary: Record<Severity, number>;
  errors: { file: string; error: string }[];
}
