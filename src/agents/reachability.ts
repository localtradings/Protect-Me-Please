import path from 'node:path';
import { parse } from '@babel/parser';
import traverse, { type NodePath, type TraverseOptions } from '@babel/traverse';
import * as t from '@babel/types';
import { readTextIfSmall, toRelative, walkFiles } from '../core/files.js';
import {
  type NormalizedVulnerability,
  type ReachabilityGraph,
  type ReachabilityNode,
  type SystemMap,
  reachabilityGraphSchema
} from '../core/types.js';
import { matchRelevantVulnerabilities } from './vulnerability-corpus.js';

const traverseAst = ((traverse as unknown as { default?: (node: t.Node, opts: TraverseOptions) => void }).default ??
  (traverse as unknown as (node: t.Node, opts: TraverseOptions) => void));

const codeExtensions = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);

function addNode(nodes: Map<string, ReachabilityNode>, node: ReachabilityNode): void {
  if (!nodes.has(node.id)) nodes.set(node.id, node);
}

function addEdge(edges: ReachabilityGraph['edges'], edge: ReachabilityGraph['edges'][number]): void {
  if (!edges.some((existing) => existing.from === edge.from && existing.to === edge.to && existing.kind === edge.kind && existing.file === edge.file)) {
    edges.push(edge);
  }
}

function parserPlugins(file: string): Array<'typescript' | 'jsx'> {
  const plugins: Array<'typescript' | 'jsx'> = [];
  if (/\.[cm]?tsx?$/.test(file)) plugins.push('typescript');
  if (/\.[jt]sx$/.test(file)) plugins.push('jsx');
  return plugins;
}

function packageNameFromImport(source: string): string | undefined {
  if (source.startsWith('.') || source.startsWith('/')) return undefined;
  if (source.startsWith('@')) return source.split('/').slice(0, 2).join('/');
  return source.split('/')[0];
}

function calleeName(callee: t.Expression | t.V8IntrinsicIdentifier | t.Super): string {
  if (t.isIdentifier(callee)) return callee.name;
  if (t.isMemberExpression(callee)) {
    const object = calleeName(callee.object as t.Expression);
    const property = t.isIdentifier(callee.property) ? callee.property.name : t.isStringLiteral(callee.property) ? callee.property.value : 'unknown';
    return `${object}.${property}`;
  }
  return 'unknown';
}

export async function buildReachabilityGraph(workspace: string, systemMap: SystemMap): Promise<ReachabilityGraph> {
  const root = path.resolve(workspace);
  const files = (await walkFiles(root)).filter((file) => codeExtensions.has(path.extname(file)));
  const nodes = new Map<string, ReachabilityNode>();
  const edges: ReachabilityGraph['edges'] = [];
  const reachableDependencies = new Set<string>();
  const reachableModels = new Set<string>();

  for (const route of systemMap.routes) {
    const routeId = `route:${route.id}`;
    const fileId = `file:${route.file}`;
    addNode(nodes, { id: routeId, type: 'route', label: `${route.method} ${route.path}`, file: route.file, metadata: { framework: route.framework } });
    addNode(nodes, { id: fileId, type: 'file', label: route.file, file: route.file, metadata: {} });
    addEdge(edges, { from: routeId, to: fileId, kind: 'route_file', evidence: `${route.path} is implemented by ${route.file}`, file: route.file });

    const routePackage = route.framework === 'nextjs' ? 'next' : route.framework === 'express' ? 'express' : undefined;
    if (routePackage) {
      const packageId = `package:${routePackage}`;
      reachableDependencies.add(routePackage);
      addNode(nodes, { id: packageId, type: 'package', label: routePackage, metadata: {} });
      addEdge(edges, { from: routeId, to: packageId, kind: 'dependency_call', evidence: `${route.path} is reachable through ${route.framework}`, file: route.file });
    }

    for (const field of route.bodyFields) {
      const fieldId = `field:${field}`;
      addNode(nodes, { id: fieldId, type: 'field', label: field, file: route.file, metadata: { source: 'request-body' } });
      addEdge(edges, { from: routeId, to: fieldId, kind: 'request_body_field', evidence: `${route.file} reads request body field ${field}`, file: route.file });
    }

    for (const model of route.prismaModels) {
      const modelId = `model:${model}`;
      reachableModels.add(model);
      addNode(nodes, { id: modelId, type: 'model', label: model, file: route.file, metadata: { orm: 'prisma' } });
      addEdge(edges, { from: routeId, to: modelId, kind: 'prisma_model', evidence: `${route.file} calls Prisma model ${model}`, file: route.file });
    }

    if (route.authDetected) {
      const authId = `auth:${route.id}`;
      addNode(nodes, { id: authId, type: 'auth', label: 'Detected auth boundary', file: route.file, metadata: {} });
      addEdge(edges, { from: routeId, to: authId, kind: 'auth_check', evidence: `${route.file} contains an auth helper call`, file: route.file });
    }

    if (route.ownershipCheckDetected) {
      const ownershipId = `ownership:${route.id}`;
      addNode(nodes, { id: ownershipId, type: 'ownership', label: 'Detected ownership check', file: route.file, metadata: {} });
      addEdge(edges, { from: routeId, to: ownershipId, kind: 'ownership_check', evidence: `${route.file} contains tenant or owner scoping`, file: route.file });
    }

    if (route.path.includes('/webhooks')) {
      const webhookId = `webhook:${route.id}`;
      addNode(nodes, { id: webhookId, type: 'webhook', label: route.path, file: route.file, metadata: {} });
      addEdge(edges, { from: routeId, to: webhookId, kind: 'webhook_flow', evidence: `${route.path} is a webhook route`, file: route.file });
    }

    if (/upload/i.test(route.path)) {
      const uploadId = `upload:${route.id}`;
      addNode(nodes, { id: uploadId, type: 'upload', label: route.path, file: route.file, metadata: {} });
      addEdge(edges, { from: routeId, to: uploadId, kind: 'upload_flow', evidence: `${route.path} is a file upload route`, file: route.file });
    }
  }

  for (const tool of systemMap.aiToolCalls) {
    const route = systemMap.routes.find((candidate) => candidate.file === tool.file);
    const routeId = route ? `route:${route.id}` : `file:${tool.file}`;
    const toolId = `ai_tool:${tool.name}:${tool.file}`;
    addNode(nodes, { id: toolId, type: 'ai_tool', label: tool.name, file: tool.file, metadata: { dangerous: String(tool.dangerous) } });
    addEdge(edges, { from: routeId, to: toolId, kind: 'ai_tool', evidence: `${tool.name} is reachable from ${tool.file}`, file: tool.file });
  }

  for (const file of files) {
    const relative = toRelative(root, file);
    const source = await readTextIfSmall(file);
    if (!source.trim()) continue;
    let ast: t.File;
    try {
      ast = parse(source, {
        sourceType: 'unambiguous',
        plugins: parserPlugins(file)
      });
    } catch {
      continue;
    }

    const fileId = `file:${relative}`;
    addNode(nodes, { id: fileId, type: 'file', label: relative, file: relative, metadata: {} });
    traverseAst(ast, {
      ImportDeclaration(pathRef: NodePath<t.ImportDeclaration>) {
        const packageName = packageNameFromImport(pathRef.node.source.value);
        if (!packageName) return;
        const packageId = `package:${packageName}`;
        reachableDependencies.add(packageName);
        addNode(nodes, { id: packageId, type: 'package', label: packageName, file: relative, metadata: {} });
        addEdge(edges, { from: fileId, to: packageId, kind: 'dependency_call', evidence: `${relative} imports ${packageName}`, file: relative });
      },
      CallExpression(pathRef: NodePath<t.CallExpression>) {
        const name = calleeName(pathRef.node.callee);
        if (name.includes('prisma.')) {
          const model = name.split('.')[1];
          if (model) {
            const modelName = model.charAt(0).toUpperCase() + model.slice(1);
            reachableModels.add(modelName);
            const modelId = `model:${modelName}`;
            addNode(nodes, { id: modelId, type: 'model', label: modelName, file: relative, metadata: { orm: 'prisma' } });
            addEdge(edges, { from: fileId, to: modelId, kind: 'prisma_model', evidence: `${relative} calls ${name}`, file: relative });
          }
        }
        if (/\b(requireUser|getServerSession|requireAuth|auth)\b/i.test(name)) {
          const authId = `auth:${relative}:${name}`;
          addNode(nodes, { id: authId, type: 'auth', label: name, file: relative, metadata: {} });
          addEdge(edges, { from: fileId, to: authId, kind: 'auth_check', evidence: `${relative} calls ${name}`, file: relative });
        }
      }
    });
  }

  return reachabilityGraphSchema.parse({
    generatedAt: new Date().toISOString(),
    nodes: [...nodes.values()],
    edges,
    summary: {
      reachableRoutes: systemMap.routes.length,
      reachableDependencies: [...reachableDependencies].sort(),
      reachableModels: [...reachableModels].sort(),
      aiToolFlows: systemMap.aiToolCalls.length
    }
  });
}

export function matchReachableVulnerabilities(
  systemMap: SystemMap,
  reachabilityGraph: ReachabilityGraph,
  corpus: NormalizedVulnerability[]
): NormalizedVulnerability[] {
  const relevant = matchRelevantVulnerabilities(systemMap, corpus);
  const reachable = new Set(reachabilityGraph.summary.reachableDependencies);
  return relevant.filter((record) => record.affectedPackages.some((affected) => reachable.has(affected.name)));
}
