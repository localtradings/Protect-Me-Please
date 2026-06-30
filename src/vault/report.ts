import { access, copyFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { safeSlug } from './redaction.js';
import { vaultGraphSchema, type VaultGraph } from './types.js';

const UI_ASSET_NAMES = ['vault-graph.js', 'vault.css'] as const;

export interface VaultRouteProfile {
  routeId: string;
  html: string;
}

export interface WriteVaultReportInput {
  workspace: string;
  reportsDir: string;
  graph: VaultGraph;
  routeProfiles: readonly VaultRouteProfile[];
  uiAssetsDir?: string;
}

export interface VaultReportOutput {
  indexFile: string;
  graphFile: string;
  timelineFile: string;
  routeProfileFiles: string[];
  assetFiles: string[];
}

export function serializeEmbeddedJson(value: unknown): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw new TypeError('Embedded value must be JSON-serializable.');
  }
  return serialized.replace(/[<>&\u2028\u2029]/g, (character) => {
    switch (character) {
      case '<':
        return '\\u003c';
      case '>':
        return '\\u003e';
      case '&':
        return '\\u0026';
      case '\u2028':
        return '\\u2028';
      case '\u2029':
        return '\\u2029';
      default:
        return character;
    }
  });
}

function stableJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableJsonValue);
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, stableJsonValue(item)])
  );
}

function stableReadableJson(value: unknown): string {
  return `${JSON.stringify(stableJsonValue(value), null, 2)}\n`;
}

async function missingUiAssets(directory: string): Promise<string[]> {
  const results = await Promise.all(
    UI_ASSET_NAMES.map(async (assetName) => {
      try {
        await access(path.join(directory, assetName));
        return undefined;
      } catch {
        return assetName;
      }
    })
  );
  return results.filter((assetName): assetName is (typeof UI_ASSET_NAMES)[number] =>
    Boolean(assetName)
  );
}

async function resolveUiAssetsDirectory(override?: string): Promise<string> {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  const candidates = override
    ? [path.resolve(override)]
    : [
        path.resolve(moduleDirectory, '../vault-ui'),
        path.resolve(moduleDirectory, '../../dist/vault-ui')
      ];
  const checked: Array<{ directory: string; missing: string[] }> = [];

  for (const candidate of candidates) {
    const missing = await missingUiAssets(candidate);
    if (missing.length === 0) return candidate;
    checked.push({ directory: candidate, missing });
  }

  const details = checked
    .map(({ directory, missing }) => `${missing.join(', ')} in ${directory}`)
    .join('; ');
  throw new Error(
    `Vault UI bundle is incomplete: missing ${details}. Run "npm run build:vault-ui" before packaging the Vault report.`
  );
}

function renderIndex(graph: VaultGraph): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self' data: blob:; script-src 'self'; style-src 'self'; style-src-elem 'self' 'unsafe-inline'; style-src-attr 'unsafe-inline'; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'">
  <title>BreachProof Vault</title>
  <link rel="stylesheet" href="./assets/vault.css">
</head>
<body>
  <main id="breachproof-vault"></main>
  <script type="application/json" id="breachproof-vault-data">${serializeEmbeddedJson(graph)}</script>
  <script src="./assets/vault-graph.js" defer></script>
</body>
</html>
`;
}

export async function writeVaultReport(
  input: WriteVaultReportInput
): Promise<VaultReportOutput> {
  const graph = vaultGraphSchema.parse(input.graph);
  const reportDirectory = path.join(path.resolve(input.workspace), input.reportsDir, 'vault');
  const assetsDirectory = path.join(reportDirectory, 'assets');
  const routeProfilesDirectory = path.join(reportDirectory, 'route-profiles');
  const indexFile = path.join(reportDirectory, 'index.html');
  const graphFile = path.join(reportDirectory, 'graph.json');
  const timelineFile = path.join(reportDirectory, 'timeline.json');
  const uiAssetsDirectory = await resolveUiAssetsDirectory(input.uiAssetsDir);

  await Promise.all([
    mkdir(assetsDirectory, { recursive: true }),
    mkdir(routeProfilesDirectory, { recursive: true })
  ]);

  const assetFiles = UI_ASSET_NAMES.map((assetName) =>
    path.join(assetsDirectory, assetName)
  );
  const usedProfileNames = new Set<string>();
  const profiles = input.routeProfiles
    .map((profile) => ({ profile, slug: safeSlug(profile.routeId) }))
    .sort(
      (left, right) =>
        left.slug.localeCompare(right.slug) ||
        left.profile.routeId.localeCompare(right.profile.routeId) ||
        left.profile.html.localeCompare(right.profile.html)
    );
  const writtenProfileFiles: string[] = [];

  for (const { profile, slug } of profiles) {
    let suffix = 1;
    let fileName = `${slug}.html`;
    while (usedProfileNames.has(fileName)) {
      suffix += 1;
      fileName = `${slug}-${suffix}.html`;
    }
    usedProfileNames.add(fileName);
    const profileFile = path.join(routeProfilesDirectory, fileName);
    await writeFile(profileFile, profile.html, 'utf8');
    writtenProfileFiles.push(profileFile);
  }
  const routeProfileFiles = writtenProfileFiles.sort((left, right) =>
    left.localeCompare(right)
  );

  await Promise.all([
    writeFile(indexFile, renderIndex(graph), 'utf8'),
    writeFile(graphFile, stableReadableJson(graph), 'utf8'),
    writeFile(timelineFile, stableReadableJson(graph.timeline), 'utf8'),
    ...UI_ASSET_NAMES.map((assetName) =>
      copyFile(
        path.join(uiAssetsDirectory, assetName),
        path.join(assetsDirectory, assetName)
      )
    )
  ]);

  return {
    indexFile,
    graphFile,
    timelineFile,
    routeProfileFiles,
    assetFiles
  };
}
