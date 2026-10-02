import fg from 'fast-glob';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve, sep } from 'node:path';
import type { FileKind } from './types.js';

export const DEFAULT_IGNORES = [
  '**/node_modules/**',
  '**/.git/**',
  '**/.hg/**',
  '**/.svn/**',
  '**/dist/**',
  '**/build/**',
  '**/.next/**',
  '**/.venv/**',
  '**/venv/**',
  '**/__pycache__/**',
  '**/.cache/**',
  '**/.turbo/**',
  '**/coverage/**',
  '**/vendor/**',
  '**/target/**',
  '**/.pnpm-store/**',
  '**/.yarn/**',
];

/** Patterns (relative to a project root) for files agents load. */
export const PROJECT_PATTERNS = [
  '**/SKILL.md',
  '**/CLAUDE.md',
  '**/CLAUDE.local.md',
  '**/AGENTS.md',
  '**/AGENTS.override.md',
  '**/GEMINI.md',
  '**/.cursorrules',
  '**/.windsurfrules',
  '**/.clinerules',
  '**/.cursor/rules/**/*.{md,mdc,txt}',
  '**/.windsurf/rules/**/*.md',
  '**/.clinerules/**/*.md',
  '**/.github/copilot-instructions.md',
  '**/.github/instructions/**/*.md',
  '**/.github/prompts/**/*.md',
  '**/.github/chatmodes/**/*.md',
  '**/.claude/agents/**/*.md',
  '**/.claude/commands/**/*.md',
  '**/.claude/output-styles/**/*.md',
  '**/.claude/settings.json',
  '**/.claude/settings.local.json',
  '**/.claude/hooks/**/*.{sh,bash,zsh,py,js,mjs,cjs,ts,ps1,rb}',
  '**/.mcp.json',
  '**/.cursor/mcp.json',
  '**/.vscode/mcp.json',
  '**/.gemini/settings.json',
  '**/.codex/config.toml',
  '**/.codex/prompts/**/*.md',
  '**/claude_desktop_config.json',
  '**/.claude-plugin/*.json',
  '**/gemini-extension.json',
];

/** Patterns relative to $HOME for --home. */
export const HOME_PATTERNS = [
  '.claude/CLAUDE.md',
  '.claude/settings.json',
  '.claude/settings.local.json',
  '.claude/agents/**/*.md',
  '.claude/commands/**/*.md',
  '.claude/output-styles/**/*.md',
  '.claude/skills/**/SKILL.md',
  '.claude/hooks/**/*.{sh,bash,zsh,py,js,mjs,cjs,ts,ps1,rb}',
  '.claude/plugins/**/SKILL.md',
  '.claude/plugins/**/.claude-plugin/*.json',
  '.claude/plugins/**/hooks/hooks.json',
  '.claude/plugins/**/.mcp.json',
  '.claude/plugins/**/{commands,agents}/**/*.md',
  '.claude.json',
  '.mcp.json',
  '.codex/AGENTS.md',
  '.codex/AGENTS.override.md',
  '.codex/config.toml',
  '.codex/prompts/**/*.md',
  '.codex/skills/**/SKILL.md',
  '.gemini/GEMINI.md',
  '.gemini/settings.json',
  '.gemini/extensions/**/{GEMINI.md,gemini-extension.json}',
  '.gemini/commands/**/*.toml',
  '.cursor/mcp.json',
  '.cursor/rules/**/*.{md,mdc}',
  '.agents/skills/**/SKILL.md',
  '.config/agents/skills/**/SKILL.md',
  '.codeium/windsurf/mcp_config.json',
  '.codeium/windsurf/memories/global_rules.md',
  'Library/Application Support/Claude/claude_desktop_config.json',
  '.config/Claude/claude_desktop_config.json',
  'AppData/Roaming/Claude/claude_desktop_config.json',
];

const HOME_IGNORES = [
  '**/node_modules/**',
  '**/.git/**',
  '.claude/projects/**',
  '.claude/todos/**',
  '.claude/shell-snapshots/**',
  '.claude/statsig/**',
  '.claude/file-history/**',
  '.claude/debug/**',
  '.claude/ide/**',
  '.codex/sessions/**',
  '.codex/log/**',
  '.gemini/tmp/**',
];

const SCRIPT_EXT = /\.(?:sh|bash|zsh|fish|py|js|mjs|cjs|ts|mts|cts|ps1|psm1|bat|cmd|rb|pl|php|lua)$/i;
const DOC_EXT = /\.(?:md|mdx|mdc|txt)$/i;

const posix = (p: string) => p.split(sep).join('/');

/** Classify a path by name/location. Returns undefined for files we do not know. */
export function classify(absPath: string, allMarkdown = false): FileKind | undefined {
  const p = posix(absPath);
  const name = basename(p);
  if (name === 'SKILL.md') return 'skill';
  if (name === '.claude.json') return 'claude-json';
  if (/\/\.claude\/settings(?:\.local)?\.json$/.test(p) || /\/hooks\/hooks\.json$/.test(p)) return 'claude-settings';
  if (/\/\.codex\/config\.toml$/.test(p)) return 'codex-config';
  if (
    name === '.mcp.json' ||
    name === 'claude_desktop_config.json' ||
    name === 'mcp_config.json' ||
    name === 'gemini-extension.json' ||
    /\/\.(?:cursor|vscode)\/mcp\.json$/.test(p) ||
    /\/\.gemini\/settings\.json$/.test(p) ||
    /\/\.claude-plugin\/[^/]+\.json$/.test(p)
  )
    return 'mcp-config';
  if (/\/\.claude\/hooks\//.test(p) && SCRIPT_EXT.test(name)) return 'script';
  if (
    /^(?:CLAUDE|CLAUDE\.local|AGENTS|AGENTS\.override|GEMINI)\.md$/.test(name) ||
    /^\.(?:cursorrules|windsurfrules|clinerules)$/.test(name) ||
    /\/\.cursor\/rules\//.test(p) ||
    /\/\.windsurf\/rules\//.test(p) ||
    /\/\.clinerules\//.test(p) ||
    /\/\.github\/(?:copilot-instructions\.md$|instructions\/|prompts\/|chatmodes\/)/.test(p) ||
    /\/\.claude\/(?:agents|commands|output-styles)\//.test(p) ||
    /\/\.codex\/prompts\//.test(p) ||
    /\/\.gemini\/commands\//.test(p) ||
    /\/plugins\/.+\/(?:commands|agents)\/[^/]+\.md$/.test(p) ||
    /\/windsurf\/memories\/global_rules\.md$/.test(p)
  )
    return 'instructions';
  if (allMarkdown && /\.(?:md|mdx|mdc)$/i.test(name)) return 'markdown';
  return undefined;
}

export interface DiscoverOptions {
  paths: string[];
  home?: boolean;
  homeDir?: string;
  allMarkdown?: boolean;
  ignore?: string[];
}

export interface Discovered {
  absolutePath: string;
  kind: FileKind;
  /** root used for ignore matching */
  root: string;
}

export function readIgnoreFile(dir: string): string[] {
  const f = join(dir, '.promptwardenignore');
  if (!existsSync(f)) return [];
  return readFileSync(f, 'utf8')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => (l.endsWith('/') ? `${l}**` : l))
    .flatMap((l) => (l.includes('/') || l.startsWith('**') ? [l.replace(/^\//, '')] : [`**/${l}`, `**/${l}/**`]));
}

function expandSkillDir(dir: string, ignore: string[]): string[] {
  return fg.sync('**/*', {
    cwd: dir,
    absolute: true,
    dot: true,
    onlyFiles: true,
    followSymbolicLinks: false,
    deep: 4,
    ignore: [...DEFAULT_IGNORES, ...ignore],
    suppressErrors: true,
  });
}

function skillMember(abs: string): FileKind | undefined {
  const name = basename(abs);
  if (name === 'SKILL.md') return 'skill';
  if (SCRIPT_EXT.test(name)) return 'script';
  if (DOC_EXT.test(name)) return 'skill-doc';
  if (!name.includes('.')) {
    // extension-less executable with a shebang
    try {
      const fd = readFileSync(abs, { encoding: 'utf8', flag: 'r' }).slice(0, 64);
      if (fd.startsWith('#!')) return 'script';
    } catch {
      /* ignore */
    }
  }
  return undefined;
}

export async function discover(opts: DiscoverOptions): Promise<Discovered[]> {
  const found = new Map<string, Discovered>();
  const add = (abs: string, kind: FileKind, root: string) => {
    if (!found.has(abs)) found.set(abs, { absolutePath: abs, kind, root });
  };
  const userIgnore = opts.ignore ?? [];

  const handleSkillDirs = (root: string, ignore: string[]) => {
    for (const d of [...found.values()]) {
      if (d.kind !== 'skill' || d.root !== root) continue;
      const dir = dirname(d.absolutePath);
      // A SKILL.md at the very root of a big repo: only take scripts/ and references/ style children
      for (const f of expandSkillDir(dir, ignore)) {
        const k = skillMember(f);
        if (k && k !== 'skill') add(f, k, root);
      }
    }
  };

  for (const input of opts.paths) {
    const abs = resolve(input);
    if (!existsSync(abs)) throw new Error(`Path not found: ${input}`);
    const st = statSync(abs);
    if (st.isFile()) {
      const k = classify(abs, true) ?? (SCRIPT_EXT.test(abs) ? 'script' : DOC_EXT.test(abs) ? 'markdown' : abs.endsWith('.json') ? 'mcp-config' : 'markdown');
      add(abs, k, dirname(abs));
      continue;
    }
    const ignore = [...readIgnoreFile(abs), ...userIgnore];
    // If the user points directly at an agent dir (e.g. ~/.claude), scan it like --home does.
    const base = basename(abs);
    let patterns = PROJECT_PATTERNS;
    let cwd = abs;
    if (['.claude', '.codex', '.gemini', '.cursor', '.agents', '.codeium'].includes(base)) {
      cwd = dirname(abs);
      patterns = HOME_PATTERNS.filter((p) => p.startsWith(base + '/'));
    }
    if (opts.allMarkdown) patterns = [...patterns, '**/*.{md,mdx,mdc}'];
    const files = await fg(patterns, {
      cwd,
      absolute: true,
      dot: true,
      onlyFiles: true,
      followSymbolicLinks: false,
      ignore: [...DEFAULT_IGNORES, ...(cwd === abs ? ignore : []), ...(cwd !== abs ? HOME_IGNORES : [])],
      suppressErrors: true,
      caseSensitiveMatch: true,
    });
    for (const f of files) {
      const k = classify(f, opts.allMarkdown);
      if (k) add(f, k, abs);
    }
    handleSkillDirs(abs, ignore);
  }

  if (opts.home) {
    const home = opts.homeDir ?? homedir();
    const files = await fg(HOME_PATTERNS, {
      cwd: home,
      absolute: true,
      dot: true,
      onlyFiles: true,
      followSymbolicLinks: true,
      ignore: [...HOME_IGNORES, ...userIgnore],
      suppressErrors: true,
    });
    for (const f of files) {
      const k = classify(f, false) ?? (basename(f) === 'SKILL.md' ? 'skill' : f.endsWith('.json') ? 'mcp-config' : 'instructions');
      add(f, k, home);
    }
    handleSkillDirs(home, userIgnore);
  }

  return [...found.values()].sort((a, b) => a.absolutePath.localeCompare(b.absolutePath));
}
