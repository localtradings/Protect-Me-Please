import { createHash } from 'node:crypto';
import type { Finding } from '../core/types.js';

const httpMethodPattern = /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s?#]+)/i;
const dynamicSegmentPattern = /^(?:\[[^\]]+\]|:[A-Za-z_][A-Za-z0-9_]*|\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{24})$/i;
const nextRouteFilePattern = /^(?:app\/api\/(?:.*\/)?route\.[cm]?[jt]sx?|pages\/api\/)/i;

const controlFamilies: Record<string, readonly string[]> = {
  AI: ['ai_guardrails'],
  AUTH: ['authentication'],
  AUTHZ: ['authorization'],
  BODY: ['input_integrity'],
  BOLA: ['authorization', 'tenant_isolation'],
  CI: ['ci_trust'],
  DEP: ['dependency_integrity'],
  UPLOAD: ['upload_validation'],
  WEBHOOK: ['webhook_integrity']
};

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

function routeParts(finding: Finding): { method: string; route: string } {
  const candidates = [...finding.affectedRoutes, ...finding.attackPath];
  for (const candidate of candidates) {
    const match = candidate.match(httpMethodPattern);
    if (match) {
      return {
        method: (match[1] ?? 'UNKNOWN').toUpperCase(),
        route: normalizeRoutePath(match[2] ?? '/')
      };
    }
  }

  const route = finding.affectedRoutes.find((candidate) => candidate.trim().startsWith('/'));
  return { method: 'UNKNOWN', route: normalizeRoutePath(route ?? '/') };
}

function normalizedFile(file: string): string {
  const normalized = file
    .replace(/\\/g, '/')
    .replace(/:\d+(?::\d+)?$/, '')
    .replace(/^[A-Za-z]:/, '');
  const sourceRoot = normalized.match(/(?:^|\/)(app|pages|src|routes?|api|prisma|tests?|\.github)\//);
  if (sourceRoot?.index === undefined) return normalized.replace(/^\/+/, '');
  const rootIndex = normalized[sourceRoot.index] === '/' ? sourceRoot.index + 1 : sourceRoot.index;
  return normalized.slice(rootIndex);
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
  if (/(?:^|\/)(?:routes?|routers?)(?:\/|\.|$)/.test(normalized)) return 'route_handler';
  if (/(?:^|\/)(?:server|app|index)\.[cm]?[jt]sx?$/.test(normalized)) return 'server_entry';
  if (/(?:^|\/)(?:middleware|guard|auth)(?:\/|\.|$)/.test(normalized)) return 'security_middleware';
  if (/(?:^|\/)(?:tests?|__tests__)(?:\/|$)|\.(?:test|spec)\.[cm]?[jt]sx?$/.test(normalized)) return 'test';
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
  const family = normalizeRuleId(ruleId).split('-')[1] ?? '';
  return [...(controlFamilies[family] ?? [`rule_${family.toLowerCase() || 'unknown'}`])].sort();
}

function normalizeSink(attackPath: string[]): string {
  const terminal = [...attackPath].reverse().find((part) => part.trim().length > 0) ?? 'unknown';
  return terminal
    .trim()
    .replace(/\\/g, '/')
    .replace(/\b[A-Za-z]:?\/[^\s]+\//g, '')
    .toLowerCase()
    .replace(/[^a-z0-9._:-]+/g, '_')
    .replace(/^_+|_+$/g, '');
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
  const { method, route } = routeParts(finding);
  return {
    ruleId: normalizeRuleId(finding.ruleId),
    method,
    route,
    routeTokens: route.split('/').filter(Boolean),
    framework: inferFramework(finding.affectedFiles),
    sink: normalizeSink(finding.attackPath),
    controlTags: controlTagsFor(finding.ruleId),
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
