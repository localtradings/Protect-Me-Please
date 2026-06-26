import path from 'node:path';
import YAML from 'yaml';
import { readTextIfSmall, toRelative, walkFiles } from '../core/files.js';
import { productName, systemMapSchema, type AiToolCall, type DataModel, type RouteNode, type SystemMap } from '../core/types.js';

const codeExtensions = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);
const dangerousBodyFields = new Set(['role', 'isAdmin', 'status', 'plan', 'price', 'tenantId', 'organizationId']);
const dangerousToolWords = ['delete', 'transfer', 'refund', 'email', 'payment', 'admin', 'deploy', 'database', 'write'];

function detectLanguages(files: string[]): string[] {
  const languages = new Set<string>();
  for (const file of files) {
    if (file.endsWith('.ts') || file.endsWith('.tsx')) languages.add('typescript');
    if (file.endsWith('.js') || file.endsWith('.jsx') || file.endsWith('.mjs') || file.endsWith('.cjs')) languages.add('javascript');
    if (file.endsWith('.prisma')) languages.add('prisma');
    if (file.endsWith('.yml') || file.endsWith('.yaml')) languages.add('yaml');
  }
  return [...languages].sort();
}

function dependencyMap(packageJson: Record<string, unknown>): Record<string, string> {
  const dependencies: Record<string, string> = {};
  for (const key of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const block = packageJson[key];
    if (block && typeof block === 'object' && !Array.isArray(block)) {
      Object.assign(dependencies, block as Record<string, string>);
    }
  }
  return dependencies;
}

function routeId(method: string, routePath: string): string {
  return `${method.toUpperCase()} ${routePath}`;
}

function detectBodyFields(source: string): string[] {
  const fields = new Set<string>();
  for (const match of source.matchAll(/\b(?:body|req\.body)\.([A-Za-z_][A-Za-z0-9_]*)/g)) {
    fields.add(match[1] ?? '');
  }
  for (const match of source.matchAll(/\b(?:body|req\.body)\[['"]([A-Za-z_][A-Za-z0-9_]*)['"]\]/g)) {
    fields.add(match[1] ?? '');
  }
  fields.delete('');
  return [...fields].sort();
}

function detectPrismaModels(source: string, models: DataModel[]): string[] {
  return models
    .filter((model) => new RegExp(`\\bprisma\\.${model.name[0]?.toLowerCase() ?? ''}${model.name.slice(1)}\\b`).test(source))
    .map((model) => model.name);
}

function authDetected(source: string): boolean {
  return /\b(requireUser|getServerSession|auth\s*\(|requireAuth|verifySession|currentUser)\b/i.test(source);
}

function ownershipDetected(source: string): boolean {
  return /\b(?:organizationId|tenantId|ownerId)\s*:\s*(?:user|session|auth|ctx|currentUser)\./i.test(source);
}

function webhookSignatureDetected(source: string): boolean {
  return /\b(signature|constructEvent|verifyWebhook|webhookSecret|stripe-signature)\b/i.test(source);
}

function uploadValidationDetected(source: string): boolean {
  return /\b(file\.size|content-type|mime|mimetype|allowedTypes|maxSize|bytes)\b/i.test(source);
}

function nextRoutePath(relativeFile: string): string {
  const withoutRoute = relativeFile.replace(/^app\/api\//, '/api/').replace(/\/route\.[jt]sx?$/, '');
  return withoutRoute.replace(/\\/g, '/');
}

function detectNextRoutes(root: string, files: string[], sources: Map<string, string>, models: DataModel[]): RouteNode[] {
  const routes: RouteNode[] = [];
  for (const file of files) {
    const relative = toRelative(root, file);
    if (!/^app\/api\/.*\/route\.[jt]sx?$/.test(relative)) {
      continue;
    }
    const source = sources.get(file) ?? '';
    const methods = [...source.matchAll(/export\s+async\s+function\s+(GET|POST|PUT|PATCH|DELETE)/g)].map((match) => match[1] ?? 'GET');
    for (const method of methods.length > 0 ? methods : ['GET']) {
      const bodyFields = detectBodyFields(source);
      routes.push({
        id: routeId(method, nextRoutePath(relative)),
        path: nextRoutePath(relative),
        method,
        file: relative,
        framework: 'nextjs',
        authDetected: authDetected(source),
        ownershipCheckDetected: ownershipDetected(source),
        bodyFields,
        dangerousBodyFields: bodyFields.filter((field) => dangerousBodyFields.has(field)),
        prismaModels: detectPrismaModels(source, models),
        webhookSignatureDetected: webhookSignatureDetected(source),
        uploadValidationDetected: uploadValidationDetected(source),
        sourceSummary: source.slice(0, 240)
      });
    }
  }
  return routes;
}

function detectExpressRoutes(root: string, files: string[], sources: Map<string, string>, models: DataModel[]): RouteNode[] {
  const routes: RouteNode[] = [];
  for (const file of files) {
    if (!codeExtensions.has(path.extname(file))) {
      continue;
    }
    const source = sources.get(file) ?? '';
    for (const match of source.matchAll(/\b(?:app|router)\.(get|post|put|patch|delete)\(\s*['"`]([^'"`]+)['"`]/gi)) {
      const method = (match[1] ?? 'get').toUpperCase();
      const routePath = match[2] ?? '/';
      const bodyFields = detectBodyFields(source);
      routes.push({
        id: routeId(method, routePath),
        path: routePath,
        method,
        file: toRelative(root, file),
        framework: 'express',
        authDetected: authDetected(source),
        ownershipCheckDetected: ownershipDetected(source),
        bodyFields,
        dangerousBodyFields: bodyFields.filter((field) => dangerousBodyFields.has(field)),
        prismaModels: detectPrismaModels(source, models),
        webhookSignatureDetected: webhookSignatureDetected(source),
        uploadValidationDetected: uploadValidationDetected(source),
        sourceSummary: source.slice(0, 240)
      });
    }
  }
  return routes;
}

function parsePrismaModels(root: string, files: string[], sources: Map<string, string>): DataModel[] {
  const models: DataModel[] = [];
  for (const file of files) {
    if (!file.endsWith('schema.prisma')) {
      continue;
    }
    const source = sources.get(file) ?? '';
    for (const match of source.matchAll(/model\s+(\w+)\s*\{([\s\S]*?)\n\}/g)) {
      const fields = (match[2] ?? '')
        .split('\n')
        .map((line) => line.trim().split(/\s+/)[0])
        .filter((field) => field && !field.startsWith('//'));
      models.push({ name: match[1] ?? 'Model', fields, file: toRelative(root, file) });
    }
  }
  return models;
}

function detectAiToolCalls(root: string, files: string[], sources: Map<string, string>, routes: RouteNode[]): AiToolCall[] {
  const calls: AiToolCall[] = [];
  for (const file of files) {
    if (!codeExtensions.has(path.extname(file))) {
      continue;
    }
    const source = sources.get(file) ?? '';
    const relative = toRelative(root, file);
    const routePath = routes.find((route) => route.file === relative)?.path;
    for (const match of source.matchAll(/\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?:async\s*)?\(/g)) {
      const name = match[1] ?? '';
      const dangerous = dangerousToolWords.some((word) => name.toLowerCase().includes(word));
      if (dangerous) {
        calls.push({
          name,
          file: relative,
          routePath,
          dangerous,
          guardrailsDetected: /\b(allowlist|approval|guardrail|humanApproval|toolPolicy)\b/i.test(source)
        });
      }
    }
  }
  return calls;
}

function detectDocker(files: string[], sources: Map<string, string>, root: string): { files: string[]; services: string[] } {
  const dockerFiles = files.filter((file) => /(^|\/)(docker-compose\.ya?ml|Dockerfile)$/.test(toRelative(root, file)));
  const services = new Set<string>();
  for (const file of dockerFiles) {
    const relative = toRelative(root, file);
    if (!relative.includes('docker-compose')) continue;
    const parsed = YAML.parse(sources.get(file) ?? '') as { services?: Record<string, unknown> } | undefined;
    Object.keys(parsed?.services ?? {}).forEach((service) => services.add(service));
  }
  return { files: dockerFiles.map((file) => toRelative(root, file)).sort(), services: [...services].sort() };
}

function detectCi(files: string[], sources: Map<string, string>, root: string): { workflows: string[]; unsafeTriggers: string[] } {
  const workflows = files.filter((file) => toRelative(root, file).startsWith('.github/workflows/'));
  const unsafeTriggers: string[] = [];
  for (const file of workflows) {
    const relative = toRelative(root, file);
    const source = sources.get(file) ?? '';
    if (/pull_request_target/.test(source) && /\bdeploy\b/i.test(source)) {
      unsafeTriggers.push(`${relative}: pull_request_target can reach deployment behavior`);
    }
  }
  return { workflows: workflows.map((file) => toRelative(root, file)).sort(), unsafeTriggers };
}

export async function mapRepository(workspace: string): Promise<SystemMap> {
  const root = path.resolve(workspace);
  const files = await walkFiles(root);
  const sources = new Map<string, string>();
  for (const file of files) {
    const extension = path.extname(file);
    if (codeExtensions.has(extension) || ['.json', '.yml', '.yaml', '.prisma'].includes(extension) || path.basename(file) === 'Dockerfile') {
      sources.set(file, await readTextIfSmall(file));
    }
  }

  const packageManifests = files.filter((file) => path.basename(file) === 'package.json').map((file) => toRelative(root, file));
  const rootPackage = files.find((file) => toRelative(root, file) === 'package.json');
  const packageJson = rootPackage ? (JSON.parse(sources.get(rootPackage) ?? '{}') as Record<string, unknown>) : {};
  const dependencies = dependencyMap(packageJson);
  const frameworks = new Set<string>();
  if ('next' in dependencies || files.some((file) => toRelative(root, file).startsWith('app/'))) frameworks.add('nextjs');
  if ('express' in dependencies || [...sources.values()].some((source) => /\bexpress\(/.test(source))) frameworks.add('express');
  if ('prisma' in dependencies || '@prisma/client' in dependencies || files.some((file) => file.endsWith('schema.prisma'))) frameworks.add('prisma');

  const dataModels = parsePrismaModels(root, files, sources);
  const routes = [...detectNextRoutes(root, files, sources, dataModels), ...detectExpressRoutes(root, files, sources, dataModels)];
  const aiToolCalls = detectAiToolCalls(root, files, sources, routes);
  const authBoundaries = routes
    .filter((route) => route.authDetected)
    .map((route) => ({ routeId: route.id, mechanism: 'detected-auth-helper', file: route.file }));
  const docker = detectDocker(files, sources, root);
  const ci = detectCi(files, sources, root);

  return systemMapSchema.parse({
    product: productName,
    projectName: typeof packageJson.name === 'string' ? packageJson.name : path.basename(root),
    workspace: root,
    generatedAt: new Date().toISOString(),
    languages: detectLanguages(files),
    frameworks: [...frameworks].sort(),
    packageManifests,
    dependencies,
    routes,
    dataModels,
    authBoundaries,
    aiToolCalls,
    docker,
    ci,
    filesScanned: files.length
  });
}
