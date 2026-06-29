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

const genericSinkDescriptionPattern = /\b(?:authorization decision|control|destructive|guardrail|missing|predicate|privileged action|request body|risk|untrusted|user-controlled|without)\b/i;
const qualifiedSinkPattern = /\b(?:prisma\.)?([A-Za-z_$][A-Za-z0-9_$]*\.(?:create|delete|deleteMany|execute|findFirst|findMany|findUnique|insert|invoke|query|read|remove|save|update|updateMany|upsert|write))\b/gi;
const commandSinkPattern = /\b((?:approve|create|delete|deploy|disable|execute|fetch|get|insert|invoke|list|read|refund|remove|revoke|run|save|send|transfer|update|write)[A-Z][A-Za-z0-9_$]*)\b/g;
const namedSinkPattern = /\b([A-Z][A-Za-z0-9]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)?|[a-z][A-Za-z0-9]*(?:Action|Handler|Model|Repository|Service|Sink|Tool))\b/g;

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
  routes: string[];
  routeTokens: string[];
  framework: string;
  sink: string;
  sinks: string[];
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

function collectRouteLabels(candidates: string[]): string[] {
  const routes = new Map<string, Set<string>>();
  for (const candidate of candidates) {
    const trimmed = candidate.trim();
    const match = trimmed.match(httpMethodPattern);
    if (match) {
      const route = normalizeRoutePath(match[2] ?? '/');
      const method = (match[1] ?? 'UNKNOWN').toUpperCase();
      const methods = routes.get(route) ?? new Set<string>();
      methods.add(method);
      routes.set(route, methods);
      continue;
    }

    if (!trimmed.startsWith('/')) continue;
    const route = normalizeRoutePath(trimmed);
    const methods = routes.get(route) ?? new Set<string>();
    methods.add('UNKNOWN');
    routes.set(route, methods);
  }

  return [...routes.entries()]
    .sort(([leftRoute], [rightRoute]) => leftRoute.localeCompare(rightRoute))
    .flatMap(([route, methods]) => {
      const knownMethods = [...methods].filter((method) => method !== 'UNKNOWN').sort();
      return knownMethods.length > 0 ? knownMethods.map((method) => `${method} ${route}`) : [`UNKNOWN ${route}`];
    });
}

function routeParts(finding: Finding): {
  method: string;
  route: string;
  routes: string[];
  routeTokens: string[];
} {
  const routes = collectRouteLabels([...finding.affectedRoutes, ...finding.attackPath]);
  const [primaryRoute = 'UNKNOWN /'] = routes;
  const [method = 'UNKNOWN', ...routeSegments] = primaryRoute.split(' ');
  const route = routeSegments.join(' ') || '/';
  const routeTokens = [
    ...new Set(
      routes.flatMap((label) => {
        const path = label.includes(' ') ? label.slice(label.indexOf(' ') + 1) : label;
        return path.split('/').filter(Boolean);
      })
    )
  ].sort();

  return { method, route, routes, routeTokens };
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

function collectSinkLabels(values: string[], pattern: RegExp, rejectGenericDescriptions = false): string[] {
  const sinks = new Set<string>();
  for (const value of values) {
    if (
      httpMethodPattern.test(value) ||
      (rejectGenericDescriptions && genericSinkDescriptionPattern.test(value))
    ) {
      continue;
    }
    pattern.lastIndex = 0;
    for (let match = pattern.exec(value); match !== null; match = pattern.exec(value)) {
      if (match[1]) sinks.add(normalizeSinkValue(match[1]));
    }
  }
  return [...sinks].sort();
}

function collectSinkLabelsForFinding(attackPath: string[], evidence: string): string[] {
  const attackTokens = attackPath.map((part) => part.trim()).filter(Boolean);
  const evidenceTokens = [evidence];
  const prioritizedMatches = [
    collectSinkLabels(attackTokens, qualifiedSinkPattern),
    collectSinkLabels(evidenceTokens, qualifiedSinkPattern),
    collectSinkLabels(attackTokens, commandSinkPattern),
    collectSinkLabels(evidenceTokens, commandSinkPattern),
    collectSinkLabels(attackTokens, namedSinkPattern, true),
    collectSinkLabels(evidenceTokens, namedSinkPattern, true)
  ];
  return prioritizedMatches.find((sinks) => sinks.length > 0) ?? [];
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
  const { method, route, routes, routeTokens } = routeParts(finding);
  const sinks = collectSinkLabelsForFinding(finding.attackPath, finding.evidence);
  const controlTags = new Set([
    ...controlTagsFor(finding.ruleId),
    ...evidenceControlTags(finding.evidence)
  ]);
  return {
    ruleId: normalizeRuleId(finding.ruleId),
    method,
    route,
    routes,
    routeTokens,
    framework: inferFramework(finding.affectedFiles),
    sink: sinks[0] ?? 'unknown',
    sinks,
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
      routes: traits.routes,
      framework: traits.framework,
      sink: traits.sink,
      sinks: traits.sinks,
      controlTags: traits.controlTags,
      fileRole: traits.fileRole
    })
  );
}
