import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import YAML from 'yaml';
import { productName, type ScopeConfig, scopeConfigSchema } from './types.js';

export const scopeConfigFile = 'breachproof.scope.yml';

export function createDefaultScopeConfig(workspace: string): ScopeConfig {
  return {
    version: 1,
    product: productName,
    mode: 'local',
    workspace: path.resolve(workspace),
    allowedPaths: ['.'],
    stagingTargets: [],
    reportsDir: 'reports',
    stateDir: '.breachproof',
    autofix: {
      enabled: false,
      apply: false,
      createPrReadyPatch: true
    },
    ci: {
      failOnSeverity: 'critical',
      uploadSarif: true
    },
    plugins: {
      enabled: true,
      directories: ['plugins']
    }
  };
}

export async function writeScopeConfig(workspace: string, config: ScopeConfig): Promise<void> {
  await mkdir(workspace, { recursive: true });
  const parsed = scopeConfigSchema.parse({ ...config, workspace: path.resolve(config.workspace) });
  await writeFile(path.join(workspace, scopeConfigFile), YAML.stringify(parsed), 'utf8');
}

export async function loadScopeConfig(workspace: string, explicitPath?: string): Promise<ScopeConfig> {
  const configPath = explicitPath ? path.resolve(workspace, explicitPath) : path.join(workspace, scopeConfigFile);
  try {
    const raw = await readFile(configPath, 'utf8');
    return scopeConfigSchema.parse(YAML.parse(raw));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return createDefaultScopeConfig(workspace);
    }
    throw error;
  }
}
