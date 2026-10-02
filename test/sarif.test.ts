import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { RULES, scan, toSarif } from '../src/index.js';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));

const EXAMPLES = join(HERE, '..', 'examples');

describe('SARIF 2.1.0 output', () => {
  it('has a valid structure for GitHub code scanning', async () => {
    const res = await scan({ paths: [EXAMPLES], cwd: join(EXAMPLES, '..') });
    expect(res.findings.length).toBeGreaterThan(10);
    const sarif = toSarif(res, { cwd: join(EXAMPLES, '..') });
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toMatch(/sarif-2\.1\.0/);
    expect(sarif.runs).toHaveLength(1);
    const run = sarif.runs[0]!;
    const driver = run.tool.driver;
    expect(driver.name).toBe('promptwarden');
    expect(driver.informationUri).toMatch(/^https:\/\//);
    expect(driver.rules.map((r) => r.id)).toEqual(RULES.map((r) => r.id));
    for (const r of driver.rules) {
      expect(r.shortDescription.text).toBeTruthy();
      expect(r.fullDescription.text).toBeTruthy();
      expect(r.helpUri).toMatch(/^https:\/\/.*#pw\d{3}-/);
      expect(['error', 'warning', 'note']).toContain(r.defaultConfiguration.level);
      expect(Number(r.properties['security-severity'])).toBeGreaterThan(0);
      expect(r.name).toMatch(/^[A-Z][A-Za-z0-9]+$/);
    }
    expect(run.originalUriBaseIds['%SRCROOT%'].uri).toMatch(/^file:\/\/.*\/$/);
    const fps = new Set<string>();
    for (const r of run.results) {
      expect(driver.rules[r.ruleIndex]!.id).toBe(r.ruleId);
      expect(['error', 'warning', 'note']).toContain(r.level);
      expect(r.message.text.length).toBeGreaterThan(0);
      const loc = r.locations[0]!.physicalLocation;
      expect(loc.artifactLocation.uri).not.toMatch(/^\//);
      expect(loc.artifactLocation.uriBaseId).toBe('%SRCROOT%');
      expect(loc.region.startLine).toBeGreaterThanOrEqual(1);
      expect(loc.region.startColumn).toBeGreaterThanOrEqual(1);
      expect(loc.region.endLine).toBeGreaterThanOrEqual(loc.region.startLine);
      const fp = r.partialFingerprints['promptwarden/v1'];
      expect(fp).toMatch(/^[0-9a-f]{32}$/);
      expect(fps.has(fp)).toBe(false);
      fps.add(fp);
    }
    // round-trips through JSON
    expect(JSON.parse(JSON.stringify(sarif))).toEqual(sarif);
  });

  it('produces stable fingerprints across runs', async () => {
    const a = await scan({ paths: [EXAMPLES], cwd: join(EXAMPLES, '..') });
    const b = await scan({ paths: [EXAMPLES], cwd: join(EXAMPLES, '..') });
    expect(a.findings.map((f) => f.fingerprint)).toEqual(b.findings.map((f) => f.fingerprint));
  });
});
