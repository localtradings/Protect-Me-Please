import { createHash } from 'node:crypto';
import type { Finding } from '../core/types.js';

const httpMethodPattern = /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s?#]+)/i;
const dynamicSegmentPattern = /^(?:\[[^\]]+\]|:[A-Za-z_][A-Za-z0-9_]*|\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{24})$/i;
const nextRouteFilePattern = /^(?:app\/api\/(?:.*\/)?route\.[cm]?[jt]sx?|pages\/api\/)/i;

const controlTokens: Record<string, readonly string[]> = {
  AI: ['ai_guardrails'],
  AUTH: ['authentication'],
  AUTHZ: ['authorization'],
  BODY: ['input_integrity'],
  BOLA: ['authorization', 'tenant_isolation'],
  CI: ['ci_trust'],
  DEP: ['dependency_integrity'],
  OWNER: ['tenant_isolation'],
  OWNERSHIP: ['tenant_isolation'],
  TENANT: ['tenant_isolation'],
  TOOL: ['tool_safety'],
  UPLOAD: ['upload_validation'],
  WEBHOOK: ['webhook_integrity']
};

const qualifiedSinkPattern = /\b(?:prisma\.)?([A-Za-z_$][A-Za-z0-9_$]*\.(?:create|delete|deleteMany|execute|findFirst|findMany|findUnique|insert|invoke|query|read|remove|save|update|updateMany|upsert|write))\b/gi;
const commandSinkPattern = /\b((?:approve|create|delete|deploy|disable|execute|fetch|get|insert|invoke|list|read|refund|remove|revoke|run|save|send|transfer|update|write)[A-Z][A-Za-z0-9_$]*)\b/g;
const explicitToolPattern = /\b([A-Z][A-Za-z0-9_$]*(?:Action|Handler|Repository|Service|Sink|Tool))\b/g;
const assetTokenSet = new Set([
  'asset',
  'attachment',
  'avatar',
  'blob',
  'bucket',
  'document',
  'file',
  'image',
  'media',
  'object',
  'photo',
  'picture',
  'storage',
  'upload',
  'video'
]);

const evidenceStopWords = new Set([
  'and',
  'for',
  'from',
  'has',
  'into',
  'lacks',
  'lookup',
  'missing',
  'not',
  'the',
  'this',
  'through',
  'with',
  'without'
]);

export interface FindingIdentityTraits {
  ruleId: string;
  method: string;
  route: string;
  routeTokens: string[];
  framework: string;
  sink: string;
  controlTags: string[];
  fileRole: string;
  evidenceTags: string[];
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export function normalizeRoutePath(route: string): string {
  const withoutMethod = route.trim().replace(httpMethodPattern, '$2');
  const withoutOrigin = withoutMethod.replace(/^https?:\/\/[^/]+/i, '');
  const pathOnly = withoutOrigin.split(/[?#]/, 1)[0]?.replace(/\\/g, '/') ?? '/';
  const segments = pathOnly
    .split('/')
    .filter(Boolean)
    .map((segment) => (dynamicSegmentPattern.test(segment) ? ':param' : segment.toLowerCase()));

  return segments.length === 0 ? '/' : `/${segments.join('/')}`;
}

interface RouteCandidate {
  method: string;
  route: string;
  score: number;
}

function routeSpecificity(route: string, methodKnown: boolean): number {
  const segments = route.split('/').filter(Boolean);
  const staticSegments = segments.filter((segment) => segment !== ':param').length;
  return (methodKnown ? 100 : 0) + staticSegments * 10 + segments.length;
}

function routeCandidateFrom(value: string): RouteCandidate | undefined {
  const trimmed = value.trim();
  const match = trimmed.match(httpMethodPattern);
  if (match) {
    const route = normalizeRoutePath(match[2] ?? '/');
    return {
      method: (match[1] ?? 'UNKNOWN').toUpperCase(),
      route,
      score: routeSpecificity(route, true)
    };
  }

  if (!trimmed.startsWith('/')) return undefined;
  const route = normalizeRoutePath(trimmed);
  return {
    method: 'UNKNOWN',
    route,
    score: routeSpecificity(route, false)
  };
}

function pickPrimaryRoute(values: string[]): RouteCandidate | undefined {
  const candidates = values
    .map(routeCandidateFrom)
    .filter((candidate): candidate is RouteCandidate => candidate !== undefined);
  if (candidates.length === 0) return undefined;
  candidates.sort(
    (left, right) =>
      right.score - left.score || right.route.localeCompare(left.route) || right.method.localeCompare(left.method)
  );
  return candidates[0];
}

function routeParts(finding: Finding): {
  method: string;
  route: string;
  routeTokens: string[];
} {
  const primary = pickPrimaryRoute(finding.affectedRoutes) ?? pickPrimaryRoute([...finding.attackPath, finding.evidence]);
  const route = primary?.route ?? '/';
  const method = primary?.method ?? 'UNKNOWN';
  return { method, route, routeTokens: route.split('/').filter(Boolean) };
}

function normalizedFile(file: string): string {
  const normalized = file
    .replace(/\\/g, '/')
    .replace(/:\d+(?::\d+)?$/, '')
    .replace(/^[A-Za-z]:/, '');
  const repositoryAnchorPattern = /(?:^|\/)(?=(?:app\/api\/(?:.*\/)?route\.[cm]?[jt]sx?$|pages\/api\/|src\/(?:routes?|routers?)\/|src\/(?:app|index|server)\.[cm]?[jt]sx?$|routes?\/|routers?\/|prisma\/|tests?\/|\.github\/))/gi;
  let rootIndex: number | undefined;
  for (const match of normalized.matchAll(repositoryAnchorPattern)) {
    const matchIndex = match.index;
    rootIndex = normalized[matchIndex] === '/' ? matchIndex + 1 : matchIndex;
  }
  return rootIndex === undefined ? normalized.replace(/^\/+/, '') : normalized.slice(rootIndex);
}

function inferFramework(files: string[]): string {
  const normalized = files.map(normalizedFile);
  if (normalized.some((file) => nextRouteFilePattern.test(file))) {
    return 'nextjs';
  }
  if (normalized.some((file) => /(?:^|\/)(?:routes?|routers?|server)(?:\/|\.|$)/i.test(file))) {
    return 'express';
  }
  return 'unknown';
}

function fileRoleFor(file: string): string {
  const normalized = normalizedFile(file).toLowerCase();
  if (nextRouteFilePattern.test(normalized)) return 'api_route';
  if (/(?:^|\/)(?:tests?|__tests__)(?:\/|$)|\.(?:test|spec)\.[cm]?[jt]sx?$/.test(normalized)) return 'test';
  if (/(?:^|\/)(?:routes?|routers?)(?:\/|\.|$)/.test(normalized)) return 'route_handler';
  if (/(?:^|\/)(?:server|app|index)\.[cm]?[jt]sx?$/.test(normalized)) return 'server_entry';
  if (/(?:^|\/)(?:middleware|guard|auth)(?:\/|\.|$)/.test(normalized)) return 'security_middleware';
  if (/schema\.prisma$|(?:^|\/)(?:models?|schemas?)(?:\/|\.|$)/.test(normalized)) return 'data_model';
  if (/\.github\/workflows\//.test(normalized)) return 'ci_workflow';
  return 'source_file';
}

function normalizedFileRole(files: string[]): string {
  const roles = [...new Set(files.map(fileRoleFor))].sort();
  return roles.length === 0 ? 'unknown' : roles.join('+');
}

function normalizeRuleId(ruleId: string): string {
  return ruleId.trim().toUpperCase().replace(/[^A-Z0-9]+/g, '-').replace(/^-|-$/g, '');
}

function controlTagsFor(ruleId: string): string[] {
  const tags = new Set<string>();
  for (const token of normalizeRuleId(ruleId).split('-')) {
    for (const tag of controlTokens[token] ?? []) tags.add(tag);
  }
  return [...tags].sort();
}

function normalizeSinkValue(value: string): string {
  return value
    .trim()
    .replace(/\\/g, '/')
    .replace(/\b[A-Za-z]:?\/[^\s]+\//g, '')
    .toLowerCase()
    .replace(/[^a-z0-9._:-]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

interface SinkCandidate {
  value: string;
  score: number;
}

function splitTokenCandidates(value: string): string[] {
  return value
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function collectSinkCandidates(values: string[]): SinkCandidate[] {
  const candidates = new Map<string, SinkCandidate>();
  for (const rawValue of values) {
    const value = rawValue.trim();
    if (!value) continue;

    for (const match of value.matchAll(qualifiedSinkPattern)) {
      const sink = match[1];
      if (!sink) continue;
      const normalized = normalizeSinkValue(sink);
      const score = 300 + normalized.length;
      const current = candidates.get(normalized);
      if (!current || score > current.score) candidates.set(normalized, { value: normalized, score });
    }

    for (const match of value.matchAll(commandSinkPattern)) {
      const sink = match[1];
      if (!sink) continue;
      const normalized = normalizeSinkValue(sink);
      const score = 200 + normalized.length;
      const current = candidates.get(normalized);
      if (!current || score > current.score) candidates.set(normalized, { value: normalized, score });
    }

    for (const match of value.matchAll(explicitToolPattern)) {
      const sink = match[1];
      if (!sink) continue;
      const normalized = normalizeSinkValue(sink);
      const score = 200 + normalized.length - 1;
      const current = candidates.get(normalized);
      if (!current || score > current.score) candidates.set(normalized, { value: normalized, score });
    }

    for (const token of splitTokenCandidates(value)) {
      if (!assetTokenSet.has(token)) continue;
      const normalized = normalizeSinkValue(token);
      const score = 100 + normalized.length;
      const current = candidates.get(normalized);
      if (!current || score > current.score) candidates.set(normalized, { value: normalized, score });
    }
  }

  return [...candidates.values()].sort(
    (left, right) => right.score - left.score || left.value.localeCompare(right.value)
  );
}

function pickPrimarySink(values: string[]): string | undefined {
  return collectSinkCandidates(values)[0]?.value;
}

function sinkForFinding(attackPath: string[], evidence: string): string {
  return pickPrimarySink(attackPath) ?? pickPrimarySink([evidence]) ?? 'unknown';
}

function evidenceControlTags(evidence: string): string[] {
  const tags = new Set<string>();
  const normalized = evidence.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toUpperCase();
  for (const token of normalized.split(/[^A-Z0-9]+/)) {
    for (const tag of controlTokens[token] ?? []) tags.add(tag);
  }
  if (/\b(?:ORGANIZATION|OWNER|OWNERSHIP|TENANT)(?:\s+ID)?\b/.test(normalized)) {
    tags.add('tenant_isolation');
  }
  if (/\bWEBHOOK\b.*\bSIGNATURE\b|\bSIGNATURE\b.*\bWEBHOOK\b/.test(normalized)) {
    tags.add('webhook_integrity');
  }
  return [...tags].sort();
}

function evidenceTagsFor(evidence: string): string[] {
  const expanded = evidence.replace(/([a-z0-9])([A-Z])/g, '$1 $2').toLowerCase();
  const tags = expanded
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length >= 3 && !evidenceStopWords.has(token))
    .map((token) => {
      if (token === 'tenantid' || token === 'tenants') return 'tenant';
      if (token === 'invoices') return 'invoice';
      return token;
    });
  return [...new Set(tags)].sort();
}

export function findingIdentityTraits(finding: Finding): FindingIdentityTraits {
  const { method, route, routeTokens } = routeParts(finding);
  const controlTags = new Set([
    ...controlTagsFor(finding.ruleId),
    ...evidenceControlTags(finding.evidence)
  ]);
  return {
    ruleId: normalizeRuleId(finding.ruleId),
    method,
    route,
    routeTokens,
    framework: inferFramework(finding.affectedFiles),
    sink: sinkForFinding(finding.attackPath, finding.evidence),
    controlTags: [...controlTags].sort(),
    fileRole: normalizedFileRole(finding.affectedFiles),
    evidenceTags: evidenceTagsFor(finding.evidence)
  };
}

export function routeFingerprint(method: string, route: string): string {
  return sha256(`${method.trim().toUpperCase()} ${normalizeRoutePath(route)}`);
}

export function findingFingerprint(finding: Finding): string {
  const traits = findingIdentityTraits(finding);
  return sha256(
    JSON.stringify({
      ruleId: traits.ruleId,
      method: traits.method,
      route: traits.route,
      framework: traits.framework,
      sink: traits.sink,
      controlTags: traits.controlTags,
      fileRole: traits.fileRole
    })
  );
}
