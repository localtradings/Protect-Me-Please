import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const ignoredDirectories = new Set(['.git', 'node_modules', 'dist', 'coverage', '.breachproof', '.next']);

export async function walkFiles(root: string): Promise<string[]> {
  const files: string[] = [];

  async function visit(directory: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory() && ignoredDirectories.has(entry.name)) {
        continue;
      }
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(fullPath);
      } else if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  }

  await visit(root);
  return files;
}

export function toRelative(root: string, file: string): string {
  return path.relative(root, file).split(path.sep).join('/');
}

export async function readTextIfSmall(file: string, maxBytes = 1_000_000): Promise<string> {
  const info = await stat(file);
  if (info.size > maxBytes) {
    return '';
  }
  return readFile(file, 'utf8');
}
