import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { buildVaultHistoryDemo } from '../helpers/vault-demo.js';

const fixtureDirectory = path.resolve('tests/fixtures/vault-history');

describe('Vault history demo', () => {
  test('tells the Day 1 bug, Day 2 fix, Day 5 similar and reopened story', async () => {
    const result = await buildVaultHistoryDemo(fixtureDirectory);

    expect(result.timeline.map((event) => `${event.runId}:${event.lifecycle}`)).toEqual([
      'day-1:new',
      'day-2:fixed',
      'day-5:reopened',
      'day-5:new'
    ]);
    expect(
      result.graph.edges.some(
        (edge) => edge.type === 'similar_to' && edge.score >= 0.75
      )
    ).toBe(true);
    expect(result.patchMemory).toHaveLength(1);
    expect(result.patchMemory.every((pattern) => pattern.outcome === 'verified_fixed')).toBe(true);
  });
});
