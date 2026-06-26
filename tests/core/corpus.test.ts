import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { importVulnerabilityCorpusFromFiles, summarizeVulnerabilityCorpus } from '../../src/agents/vulnerability-corpus.js';

const corpusRoot = path.resolve('tests/fixtures/corpus');

describe('vulnerability intelligence corpus', () => {
  test('normalizes OSV, CVE/NVD, GitHub advisory, KEV, EPSS, and local rule data', async () => {
    const corpus = await importVulnerabilityCorpusFromFiles([
      path.join(corpusRoot, 'osv-next.json'),
      path.join(corpusRoot, 'nvd-next.json'),
      path.join(corpusRoot, 'github-advisory-next.json'),
      path.join(corpusRoot, 'kev.json'),
      path.join(corpusRoot, 'epss.csv'),
      path.join(corpusRoot, 'local-rules.json')
    ]);
    const summary = summarizeVulnerabilityCorpus(corpus);
    const next = corpus.records.find((record) => record.id === 'CVE-2024-0001');

    expect(summary.recordsLoaded).toBe(3);
    expect(summary.sources).toEqual(expect.arrayContaining(['osv', 'nvd', 'github-advisory', 'cisa-kev', 'epss', 'local-rule-pack']));
    expect(next?.aliases).toEqual(expect.arrayContaining(['GHSA-xxxx-yyyy-zzzz']));
    expect(next?.affectedPackages[0]).toMatchObject({ ecosystem: 'npm', name: 'next', range: '<14.1.1' });
    expect(next?.kev).toBe(true);
    expect(next?.epss?.score).toBe(0.92);
    expect(next?.cwe).toContain('CWE-863');
    expect(next?.remediation).toContain('Upgrade Next.js');
  });
});
