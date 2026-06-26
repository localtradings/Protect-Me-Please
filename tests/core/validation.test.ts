import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { buildAttackGraph } from '../../src/agents/attack-graph.js';
import { createValidationPlan } from '../../src/agents/attack-planner.js';
import { mapRepository } from '../../src/agents/repo-mapper.js';
import { buildReachabilityGraph, matchReachableVulnerabilities } from '../../src/agents/reachability.js';
import { buildLocalVulnerabilityCorpus } from '../../src/agents/vulnerability-corpus.js';
import { validateSystemMap } from '../../src/agents/safe-validation.js';

const fixtureRoot = path.resolve('tests/fixtures/sample-next-express');

describe('attack graph and validation', () => {
  test('turns mapped routes into realistic attack paths and safe findings', async () => {
    const systemMap = await mapRepository(fixtureRoot);
    const corpus = buildLocalVulnerabilityCorpus();
    const reachabilityGraph = await buildReachabilityGraph(fixtureRoot, systemMap);
    const graph = buildAttackGraph(systemMap, corpus, reachabilityGraph);
    const findings = validateSystemMap(systemMap, graph, corpus, reachabilityGraph);
    const plan = createValidationPlan(findings, reachabilityGraph);

    expect(graph.edges.some((edge) => edge.label.includes('missing ownership'))).toBe(true);
    expect(findings.map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining([
        'BP-AUTHZ-001',
        'BP-BODY-001',
        'BP-WEBHOOK-001',
        'BP-UPLOAD-001',
        'BP-AI-001',
        'BP-CI-001',
        'BP-DEP-001'
      ])
    );
    expect(findings.every((finding) => finding.validation.destructive === false)).toBe(true);
    expect(findings.find((finding) => finding.ruleId === 'BP-AUTHZ-001')?.status).toBe('validated');
    expect(findings.find((finding) => finding.ruleId === 'BP-AUTHZ-001')?.proofMode).toBe('local_fixture');
    expect(plan.items.some((item) => item.proofMode === 'local_fixture')).toBe(true);
    expect(matchReachableVulnerabilities(systemMap, reachabilityGraph, corpus).length).toBeGreaterThan(0);
  });
});
