import { copyFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outputDirectory = path.join(repositoryRoot, 'dist/vault-ui');

await mkdir(outputDirectory, { recursive: true });

await build({
  absWorkingDir: repositoryRoot,
  entryPoints: ['src/vault/ui/entry.ts'],
  outfile: 'dist/vault-ui/vault-graph.js',
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: 'es2022',
  minify: true,
  sourcemap: false,
  legalComments: 'eof'
});

await copyFile(
  path.join(repositoryRoot, 'src/vault/ui/vault.css'),
  path.join(outputDirectory, 'vault.css')
);
