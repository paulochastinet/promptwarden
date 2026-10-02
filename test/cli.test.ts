import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { RULES } from '../src/index.js';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));

const ROOT = join(HERE, '..');
const CLI = join(ROOT, 'dist', 'cli.js');
const EXAMPLES = join(ROOT, 'examples');
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));

function run(args: string[], env: Record<string, string> = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], { cwd: ROOT, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '', ...env } });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

beforeAll(() => {
  if (!existsSync(CLI)) execFileSync('npx', ['tsup'], { cwd: ROOT, stdio: 'ignore' });
});

describe('cli (dist)', () => {
  it('--version matches package.json', () => {
    expect(run(['--version']).stdout.trim()).toBe(pkg.version);
  });

  it('--help exits 0', () => {
    const r = run(['--help']);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('Usage');
  });

  it('exits 1 on malicious examples and prints grouped findings', () => {
    const r = run(['examples']);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain('examples/malicious-skill/SKILL.md');
    expect(r.stdout).toContain('PW001');
    expect(r.stdout).toContain('<U+E00xx×');
    expect(r.stdout).not.toMatch(/\x1b\[/); // NO_COLOR
  });

  it('exits 0 on a clean directory', () => {
    const dir = mkdtempSync(join(tmpdir(), 'pw-clean-'));
    writeFileSync(join(dir, 'CLAUDE.md'), '# Project\n\nUse pnpm. Run `pnpm test` before committing.\n');
    const r = run([dir]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('No issues found');
  });

  it('--fail-on controls the exit code', () => {
    expect(run(['examples', '--fail-on', 'none']).code).toBe(0);
    expect(run(['examples/risky-project/.claude', '--fail-on', 'critical']).code).toBe(0);
    expect(run(['examples/risky-project/.claude', '--fail-on', 'high']).code).toBe(1);
  });

  it('exits 2 on usage errors', () => {
    expect(run(['--format', 'xml']).code).toBe(2);
    expect(run(['--fail-on', 'severe']).code).toBe(2);
    expect(run(['--bogus']).code).toBe(2);
    expect(run(['--disable', 'PW999']).code).toBe(2);
    expect(run(['does/not/exist']).code).toBe(2);
  });

  it('--format json is parseable', () => {
    const r = run(['examples', '--format', 'json', '--fail-on', 'none']);
    const j = JSON.parse(r.stdout);
    expect(j.tool.name).toBe('promptwarden');
    expect(j.summary.total).toBe(j.findings.length);
    expect(j.findings[0]).toHaveProperty('ruleId');
  });

  it('--format sarif --output writes a file', () => {
    const out = join(mkdtempSync(join(tmpdir(), 'pw-sarif-')), 'r.sarif');
    const r = run(['examples', '-f', 'sarif', '-o', out]);
    expect(r.code).toBe(1);
    expect(r.stdout).toBe('');
    expect(r.stderr).toContain('wrote sarif report');
    const s = JSON.parse(readFileSync(out, 'utf8'));
    expect(s.version).toBe('2.1.0');
  });

  it('--min-severity filters output', () => {
    const j = JSON.parse(run(['examples', '-f', 'json', '--min-severity', 'critical']).stdout);
    expect(j.findings.every((f: { severity: string }) => f.severity === 'critical')).toBe(true);
  });

  it('--list-rules prints every rule', () => {
    const r = run(['--list-rules']);
    for (const rule of RULES) expect(r.stdout).toContain(rule.id);
    const j = JSON.parse(run(['--list-rules', '-f', 'json']).stdout);
    expect(j).toHaveLength(RULES.length);
  });

  it('--format markdown', () => {
    const r = run(['examples', '-f', 'markdown']);
    expect(r.stdout).toContain('| Severity | Rule | Location | Finding |');
  });
});

describe('docs', () => {
  it('docs/rules.md documents every rule (run `npm run docs`)', () => {
    const md = readFileSync(join(ROOT, 'docs', 'rules.md'), 'utf8');
    for (const r of RULES) expect(md).toContain(`## ${r.id} ${r.name}`);
  });
});
