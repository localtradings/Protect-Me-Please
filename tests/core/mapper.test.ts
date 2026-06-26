import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { mapRepository } from '../../src/agents/repo-mapper.js';

const fixtureRoot = path.resolve('tests/fixtures/sample-next-express');

describe('repo mapper', () => {
  test('detects the v1 JavaScript stack, routes, Prisma models, AI tools, Docker, and CI', async () => {
    const map = await mapRepository(fixtureRoot);

    expect(map.frameworks).toContain('nextjs');
    expect(map.frameworks).toContain('express');
    expect(map.languages).toContain('typescript');
    expect(map.routes.map((route) => route.path)).toEqual(
      expect.arrayContaining(['/api/invoices/[id]', '/api/ai-agent', '/api/webhooks/stripe', '/api/upload', '/api/admin/users'])
    );
    expect(map.routes.find((route) => route.path === '/api/invoices/[id]')?.authDetected).toBe(true);
    expect(map.routes.find((route) => route.path === '/api/invoices/[id]')?.ownershipCheckDetected).toBe(false);
    expect(map.dataModels.map((model) => model.name)).toEqual(expect.arrayContaining(['Invoice', 'Organization', 'User']));
    expect(map.aiToolCalls.map((tool) => tool.name)).toEqual(expect.arrayContaining(['deleteUser', 'refundPayment']));
    expect(map.docker.files).toContain('docker-compose.yml');
    expect(map.ci.workflows).toContain('.github/workflows/deploy.yml');
  });
});
