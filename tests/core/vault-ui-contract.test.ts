import { readFile } from 'node:fs/promises';
import { describe, expect, test } from 'vitest';

const nodeTypes = [
  'route',
  'finding',
  'invariant',
  'patch',
  'replay',
  'test',
  'asset',
  'run'
] as const;

describe('Vault 3D renderer contract', () => {
  test('defines a distinct procedural asset for every Vault node type', async () => {
    const source = await readFile('src/vault/ui/node-assets.ts', 'utf8');

    for (const type of nodeTypes) {
      expect(source).toContain(`case '${type}'`);
    }
    expect(source).toContain('CanvasTexture');
    expect(source).toContain('MeshStandardMaterial');
    expect(source).toContain('EdgesGeometry');
    expect(source).toContain('LineSegments');
    expect(source).not.toContain('TextureLoader');
  });

  test('boots from the validated embedded graph with only approved active particles', async () => {
    const source = await readFile('src/vault/ui/entry.ts', 'utf8');
    const styles = await readFile('src/vault/ui/graph-style.ts', 'utf8');

    expect(source).toContain('vaultGraphSchema.parse');
    expect(source).toContain('new ForceGraph3D');
    expect(source).toContain('.nodeThreeObject(');
    expect(source).toContain('createVaultNodeObject(node)');
    expect(source).toContain('.linkDirectionalParticles(');
    expect(source).toContain('postProcessingComposer().addPass');
    expect(styles).toContain("'reaches'");
    expect(styles).toContain("'violates'");
    expect(styles).toContain("'fixed_by'");
    expect(styles).toContain("'similar_to'");
  });

  test('keeps renderer assets procedural and offline', async () => {
    const files = await Promise.all(
      ['src/vault/ui/entry.ts', 'src/vault/ui/node-assets.ts', 'src/vault/ui/graph-style.ts'].map(
        (file) => readFile(file, 'utf8')
      )
    );
    const source = files.join('\n');

    expect(source).not.toMatch(/https?:\/\//i);
    expect(source).not.toContain('fetch(');
    expect(source).not.toContain('TextureLoader');
  });
});
