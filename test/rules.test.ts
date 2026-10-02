import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { RULES, scan } from '../src/index.js';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));

const FIXTURES = join(HERE, 'fixtures', 'rules');

describe('rule fixtures', () => {
  it('has rule metadata that is complete and unique', () => {
    const ids = new Set<string>();
    for (const r of RULES) {
      expect(r.id).toMatch(/^PW\d{3}$/);
      expect(ids.has(r.id)).toBe(false);
      ids.add(r.id);
      expect(r.name).toMatch(/^[a-z0-9-]+$/);
      expect(r.title.length).toBeGreaterThan(5);
      expect(r.description.length).toBeGreaterThan(30);
      expect(r.remediation.length).toBeGreaterThan(10);
      expect(r.appliesTo.length).toBeGreaterThan(0);
    }
    expect(RULES.length).toBeGreaterThanOrEqual(25);
  });

  for (const rule of RULES) {
    describe(`${rule.id} ${rule.name}`, () => {
      const bad = join(FIXTURES, rule.id, 'bad');
      const good = join(FIXTURES, rule.id, 'good');

      it('has fixtures', () => {
        expect(existsSync(bad), `missing ${bad}`).toBe(true);
        expect(existsSync(good), `missing ${good}`).toBe(true);
      });

      it('detects the malicious fixture (true positive)', async () => {
        const res = await scan({ paths: [bad], cwd: bad });
        const hits = res.findings.filter((f) => f.ruleId === rule.id);
        expect(hits.length, JSON.stringify(res.findings.map((f) => [f.ruleId, f.message]), null, 1)).toBeGreaterThan(0);
        for (const h of hits) {
          expect(h.line).toBeGreaterThan(0);
          expect(h.column).toBeGreaterThan(0);
          expect(h.docsUrl).toContain(rule.id.toLowerCase());
        }
      });

      it('stays quiet on the clean fixture (no false positive)', async () => {
        const res = await scan({ paths: [good], cwd: good });
        expect(res.files.length).toBeGreaterThan(0);
        const hits = res.findings.filter((f) => f.ruleId === rule.id);
        expect(hits.map((f) => `${f.file}:${f.line} ${f.message}`)).toEqual([]);
      });
    });
  }
});
