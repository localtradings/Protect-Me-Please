import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { mapRepository } from '../../src/agents/repo-mapper.js';
import { buildReachabilityGraph } from '../../src/agents/reachability.js';

const fixtureRoot = path.resolve('tests/fixtures/sample-next-express');

describe('reachability engine', () => {
  test('connects routes to request fields, Prisma calls, dependencies, auth, ownership, and AI tools', async () => {
    const systemMap = await mapRepository(fixtureRoot);
    const graph = await buildReachabilityGraph(fixtureRoot, systemMap);

    expect(graph.nodes.some((node) => node.type === 'route' && node.label.includes('/api/invoices/[id]'))).toBe(true);
    expect(graph.edges.some((edge) => edge.kind === 'prisma_model' && edge.to === 'model:Invoice')).toBe(true);
    expect(graph.edges.some((edge) => edge.kind === 'request_body_field' && edge.to === 'field:tenantId')).toBe(true);
    expect(graph.edges.some((edge) => edge.kind === 'dependency_call' && edge.to === 'package:next')).toBe(true);
    expect(graph.edges.some((edge) => edge.kind === 'ai_tool' && edge.to.includes('deleteUser'))).toBe(true);
    expect(graph.summary.reachableRoutes).toBeGreaterThan(0);
    expect(graph.summary.reachableDependencies).toContain('next');
  });
});
