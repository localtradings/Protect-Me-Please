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
    expect(manifest.scripts?.build).toBe(
      'tsc -p tsconfig.build.json && npm run build:vault-ui'
    );
    expect(manifest.scripts?.['test:browser']).toBe('playwright test');
  });

  test('emits the distributable Vault UI assets', async () => {
    await expect(access(path.join(repositoryRoot, 'dist/vault-ui/vault-graph.js'))).resolves.toBeUndefined();
    await expect(access(path.join(repositoryRoot, 'dist/vault-ui/vault.css'))).resolves.toBeUndefined();
  });
});
