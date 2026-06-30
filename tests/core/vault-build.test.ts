import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'vitest';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));

type PackageManifest = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  scripts?: Record<string, string>;
};

describe('Vault UI build pipeline', () => {
  test('declares the offline renderer dependencies and build command', async () => {
    const manifest = JSON.parse(
      await readFile(path.join(repositoryRoot, 'package.json'), 'utf8')
    ) as PackageManifest;

    expect(manifest.dependencies).toMatchObject({
      '3d-force-graph': '^1.80.0',
      lucide: '^1.21.0',
      three: '^0.185.0'
    });
    expect(manifest.devDependencies).toMatchObject({
      '@playwright/test': '^1.61.1',
      '@types/three': '^0.185.0',
      esbuild: '^0.28.1'
    });
    expect(manifest.scripts?.['build:vault-ui']).toBe('node scripts/build-vault-ui.mjs');
    expect(manifest.scripts?.pretest).toBe('npm run build:vault-ui');
    expect(manifest.scripts?.['pretest:watch']).toBe('npm run build:vault-ui');
    expect(manifest.scripts?.build).toBe(
      'tsc -p tsconfig.build.json && npm run build:vault-ui'
    );
    expect(manifest.scripts?.['test:browser']).toBe(
      'playwright test tests/browser --pass-with-no-tests'
    );
  });

  test('emits the distributable Vault UI assets', async () => {
    await expect(access(path.join(repositoryRoot, 'dist/vault-ui/vault-graph.js'))).resolves.toBeUndefined();
    await expect(access(path.join(repositoryRoot, 'dist/vault-ui/vault.css'))).resolves.toBeUndefined();
  });

  test('keeps Vitest scoped away from Playwright browser specs', async () => {
    const config = await readFile(path.join(repositoryRoot, 'vitest.config.ts'), 'utf8');

    expect(config).toContain("include: ['tests/core/**/*.test.ts']");
    expect(config).not.toContain("include: ['tests/**/*.test.ts']");
  });

  test('documents renderer licenses and uploads the local Vault report', async () => {
    const notices = await readFile(
      path.join(repositoryRoot, 'THIRD_PARTY_NOTICES.md'),
      'utf8'
    );
    const workflow = await readFile(
      path.join(repositoryRoot, '.github/workflows/ci.yml'),
      'utf8'
    );

    expect(notices).toContain('three');
    expect(notices).toContain('3d-force-graph');
    expect(notices).toContain('MIT');
    expect(workflow).toContain('reports/vault/');
    expect(workflow).toContain('npx playwright install --with-deps chromium');
  });
});
