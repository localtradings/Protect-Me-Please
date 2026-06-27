import crypto from 'node:crypto';
import path from 'node:path';
import { readTextIfSmall } from '../core/files.js';
import type { Finding, ProofMode, ReachabilityGraph, RouteNode, SystemMap } from '../core/types.js';

export interface BolaRouteMap {
  routeId: string;
  method: string;
  path: string;
  file: string;
  params: string[];
  prismaModels: string[];
  prismaOperations: string[];
  producer: boolean;
  consumer: boolean;
  authDetected: boolean;
  ownershipCheckDetected: boolean;
  missingOwnershipFilter: boolean;
  trustedClientFields: string[];
}

export interface BolaMap {
  generatedAt: string;
  routes: BolaRouteMap[];
  summary: {
    routesWithObjectIds: number;
    routesMissingOwnership: number;
    routesTrustingClientIdentity: number;
  };
}

export interface OwnershipTrace {
  findingId: string;
  routeId: string;
  route: string;
  source: string;
  sink: string;
  missingPredicate: string;
  trace: string[];
  proofMode: ProofMode;
}

export interface BolaAnalysis {
  bolaMap: BolaMap;
  ownershipTraces: OwnershipTrace[];
  findings: Finding[];
}

const identityFields = new Set(['tenantId', 'organizationId', 'orgId', 'userId', 'ownerId', 'role', 'isAdmin']);
const objectParamPattern = /(?:^|[_-])?(id|userId|invoiceId|projectId|fileId|orgId|organizationId|tenantId)(?:$|[_-])?/i;

function stableId(ruleId: string, key: string): string {
  return crypto.createHash('sha1').update(`${ruleId}:${key}`).digest('hex').slice(0, 12);
}

function routeParams(routePath: string): string[] {
  const params = new Set<string>();
  for (const match of routePath.matchAll(/:([A-Za-z_][A-Za-z0-9_]*)/g)) params.add(match[1] ?? 'id');
  for (const match of routePath.matchAll(/\[([A-Za-z_][A-Za-z0-9_]*)\]/g)) params.add(match[1] ?? 'id');
  return [...params].sort();
}

function prismaOperations(source: string): string[] {
  const operations = new Set<string>();
  for (const match of source.matchAll(/\bprisma\.([A-Za-z_][A-Za-z0-9_]*)\.(findUnique|findFirst|findMany|update|delete|deleteMany|updateMany)\b/g)) {
    operations.add(`${match[1] ?? 'model'}.${match[2] ?? 'query'}`);
  }
  return [...operations].sort();
}

function hasOwnershipPredicate(source: string): boolean {
  return /\b(?:tenantId|organizationId|orgId|ownerId|userId)\s*:\s*(?:user|session|auth|ctx|currentUser|principal)\./i.test(source);
}

function mapRoute(route: RouteNode, source: string): BolaRouteMap {
  const params = routeParams(route.path);
  const operations = prismaOperations(source);
  const trustedClientFields = route.dangerousBodyFields.filter((field) => identityFields.has(field));
  const method = route.method.toUpperCase();
  const consumer = ['GET', 'PUT', 'PATCH', 'DELETE'].includes(method) || operations.some((operation) => /\.(findUnique|findFirst|findMany|update|delete)/.test(operation));
  const producer = method === 'POST' || operations.some((operation) => /\.(create|upsert)/.test(operation));
  const missingOwnershipFilter =
    route.authDetected &&
    !route.ownershipCheckDetected &&
    !hasOwnershipPredicate(source) &&
    (params.some((param) => objectParamPattern.test(param)) || route.prismaModels.length > 0 || operations.length > 0);

  return {
    routeId: route.id,
    method: route.method,
    path: route.path,
    file: route.file,
    params,
    prismaModels: route.prismaModels,
    prismaOperations: operations,
    producer,
    consumer,
    authDetected: route.authDetected,
    ownershipCheckDetected: route.ownershipCheckDetected || hasOwnershipPredicate(source),
    missingOwnershipFilter,
    trustedClientFields
  };
}

function bolaFinding(route: RouteNode, mapped: BolaRouteMap, source: string): Finding | undefined {
  if (!mapped.missingOwnershipFilter || !mapped.consumer) return undefined;
  const firstParam = mapped.params.find((param) => objectParamPattern.test(param)) ?? 'id';
  const sink = mapped.prismaOperations[0] ?? (mapped.prismaModels[0] ? `${mapped.prismaModels[0]}.query` : 'data access');
  const id = stableId('BP-BOLA-001', `${route.id}:${sink}:${firstParam}`);
  return {
    id,
    ruleId: 'BP-BOLA-001',
    title: 'Broken object-level authorization path is reachable',
    severity: 'high',
    status: 'validated',
    fixStatus: 'suggested',
    proofMode: route.authDetected ? 'local_fixture' : 'static_trace',
    affectedFiles: [route.file],
    affectedRoutes: [route.path],
    attackPath: [`user-controlled ${firstParam}`, `${route.method} ${route.path}`, sink, 'missing tenant or owner predicate'],
    evidence: `User-controlled ${firstParam} reaches Prisma/data access in ${route.file} without a detected tenantId, ownerId, or userId ownership filter. Route has authentication but no object ownership check. ${source.slice(0, 180)}`,
    exploitabilityReasoning: 'A fake local tenant A user can attempt to request a tenant B object identifier through this route path.',
    recommendation: 'Constrain object lookups and mutations by both object id and the authenticated principal tenant/user, then add a cross-tenant regression test.',
    patchStatus: 'suggested',
    verificationStatus: 'not_run',
    validation: {
      mode: 'local',
      destructive: false,
      productionTouched: false,
      summary: 'BOLA proof uses static trace plus fake local tenant fixtures only.'
    }
  };
}

function clientIdentityFinding(route: RouteNode, mapped: BolaRouteMap): Finding | undefined {
  if (mapped.trustedClientFields.length === 0) return undefined;
  const id = stableId('BP-BOLA-002', `${route.id}:${mapped.trustedClientFields.join(',')}`);
  return {
    id,
    ruleId: 'BP-BOLA-002',
    title: 'Client-controlled identity or authorization fields reach a route',
    severity: 'high',
    status: 'validated',
    fixStatus: 'suggested',
    proofMode: 'static_trace',
    affectedFiles: [route.file],
    affectedRoutes: [route.path],
    attackPath: ['request body', mapped.trustedClientFields.join(', '), `${route.method} ${route.path}`, 'authorization decision risk'],
    evidence: `${route.file} reads client-controlled identity fields: ${mapped.trustedClientFields.join(', ')}.`,
    exploitabilityReasoning: 'Authorization and tenant identity must be derived from authenticated server-side context, not request body fields.',
    recommendation: 'Reject client-provided tenant/user/role/admin fields and derive them from the authenticated principal.',
    patchStatus: 'suggested',
    verificationStatus: 'not_run',
    validation: {
      mode: 'local',
      destructive: false,
      productionTouched: false,
      summary: 'Static local validation only; no external systems touched.'
    }
  };
}

export async function analyzeBola(workspace: string, systemMap: SystemMap, _reachabilityGraph?: ReachabilityGraph): Promise<BolaAnalysis> {
  void _reachabilityGraph;
  const routes: BolaRouteMap[] = [];
  const ownershipTraces: OwnershipTrace[] = [];
  const findings: Finding[] = [];

  for (const route of systemMap.routes) {
    const source = await readTextIfSmall(path.join(workspace, route.file)).catch(() => '');
    const mapped = mapRoute(route, source);
    routes.push(mapped);

    const routeFinding = bolaFinding(route, mapped, source);
    if (routeFinding) {
      findings.push(routeFinding);
      ownershipTraces.push({
        findingId: routeFinding.id,
        routeId: route.id,
        route: `${route.method} ${route.path}`,
        source: mapped.params.length > 0 ? `route params: ${mapped.params.join(', ')}` : 'request-controlled object identifier',
        sink: mapped.prismaOperations[0] ?? (mapped.prismaModels.join(', ') || 'data access'),
        missingPredicate: 'tenantId/ownerId/userId scoped to authenticated principal',
        trace: routeFinding.attackPath,
        proofMode: routeFinding.proofMode
      });
    }

    const identityFinding = clientIdentityFinding(route, mapped);
    if (identityFinding) findings.push(identityFinding);
  }

  return {
    bolaMap: {
      generatedAt: new Date().toISOString(),
      routes,
      summary: {
        routesWithObjectIds: routes.filter((route) => route.params.some((param) => objectParamPattern.test(param))).length,
        routesMissingOwnership: routes.filter((route) => route.missingOwnershipFilter).length,
        routesTrustingClientIdentity: routes.filter((route) => route.trustedClientFields.length > 0).length
      }
    },
    ownershipTraces,
    findings
  };
}
