import crypto from 'node:crypto';
import type { AttackGraph, Finding, ProofMode, ReachabilityGraph, RouteNode, SystemMap, VulnerabilityRecord } from '../core/types.js';
import { matchReachableVulnerabilities } from './reachability.js';
import { matchRelevantVulnerabilities } from './vulnerability-corpus.js';

function findingId(ruleId: string, key: string): string {
  return crypto.createHash('sha1').update(`${ruleId}:${key}`).digest('hex').slice(0, 12);
}

function proofModeForRoute(route: RouteNode): ProofMode {
  if (/invoice|tenant|organization/i.test(route.path) && route.authDetected) return 'local_fixture';
  return 'static_trace';
}

function baseFinding(ruleId: string, title: string, severity: Finding['severity'], route: RouteNode): Finding {
  const proofMode = proofModeForRoute(route);
  return {
    id: findingId(ruleId, route.id),
    ruleId,
    title,
    severity,
    status: proofMode === 'manual_review' ? 'manual_review' : 'validated',
    fixStatus: 'suggested',
    proofMode,
    affectedFiles: [route.file],
    affectedRoutes: [route.path],
    attackPath: [`public or authenticated user`, `${route.method} ${route.path}`, title],
    evidence: `${route.file} maps ${route.method} ${route.path}. ${route.sourceSummary}`,
    exploitabilityReasoning: 'The condition is reachable from a detected application route and can be tested with local fake data.',
    recommendation: 'Add explicit server-side authorization checks and regression tests for the sensitive path.',
    patchStatus: 'suggested',
    verificationStatus: 'not_run',
    validation: {
      mode: 'local',
      destructive: false,
      productionTouched: false,
      summary: 'Static local validation only; no remote or production data was touched.'
    }
  };
}

export function validateSystemMap(systemMap: SystemMap, _graph: AttackGraph, corpus: VulnerabilityRecord[], reachabilityGraph?: ReachabilityGraph): Finding[] {
  const findings: Finding[] = [];

  for (const route of systemMap.routes) {
    if (!route.authDetected && !route.path.includes('/webhooks')) {
      const finding = baseFinding('BP-AUTH-001', 'Route has no detected authentication middleware', 'medium', route);
      finding.recommendation = 'Require authentication or explicitly document why the route is public.';
      findings.push(finding);
    }

    if (route.authDetected && !route.ownershipCheckDetected && (route.prismaModels.length > 0 || /invoice|admin|user|tenant/i.test(route.path))) {
      findings.push(baseFinding('BP-AUTHZ-001', 'Cross-tenant or ownership check missing', 'high', route));
    }

    if (route.dangerousBodyFields.length > 0) {
      const finding = baseFinding('BP-BODY-001', 'Client-controlled privileged fields accepted', 'high', route);
      finding.evidence = `${route.file} reads privileged request body fields: ${route.dangerousBodyFields.join(', ')}.`;
      finding.recommendation = 'Derive privileged fields server-side and reject client-controlled role, admin, plan, price, status, or tenant identifiers.';
      findings.push(finding);
    }

    if (route.path.includes('/webhooks') && !route.webhookSignatureDetected) {
      const finding = baseFinding('BP-WEBHOOK-001', 'Webhook route missing signature verification', 'high', route);
      finding.recommendation = 'Verify provider signatures before parsing or trusting webhook payloads.';
      findings.push(finding);
    }

    if (/upload/i.test(route.path) && !route.uploadValidationDetected) {
      const finding = baseFinding('BP-UPLOAD-001', 'File upload route missing size or type validation', 'medium', route);
      finding.recommendation = 'Enforce file size limits, allowed MIME types, and storage isolation before accepting uploads.';
      findings.push(finding);
    }
  }

  for (const tool of systemMap.aiToolCalls.filter((candidate) => candidate.dangerous && !candidate.guardrailsDetected)) {
    findings.push({
      id: findingId('BP-AI-001', `${tool.name}:${tool.file}`),
      ruleId: 'BP-AI-001',
      title: 'Dangerous AI tool call lacks guardrails',
      severity: 'critical',
      status: 'validated',
      fixStatus: 'suggested',
      proofMode: 'static_trace',
      affectedFiles: [tool.file],
      affectedRoutes: tool.routePath ? [tool.routePath] : [],
      attackPath: ['untrusted user input', tool.name, 'destructive or privileged action'],
      evidence: `${tool.name} appears in ${tool.file} without detected allowlist, approval, or tool policy guardrails.`,
      exploitabilityReasoning: 'User-controlled model or tool input may select a privileged tool in an application route.',
      recommendation: 'Add a tool allowlist, argument validation, audit logging, and human approval for destructive or privileged actions.',
      patchStatus: 'suggested',
      verificationStatus: 'not_run',
      validation: { mode: 'local', destructive: false, productionTouched: false, summary: 'Static local validation only.' }
    });
  }

  for (const trigger of systemMap.ci.unsafeTriggers) {
    findings.push({
      id: findingId('BP-CI-001', trigger),
      ruleId: 'BP-CI-001',
      title: 'CI workflow exposes deployment behavior from unsafe trigger',
      severity: 'high',
      status: 'validated',
      fixStatus: 'suggested',
      proofMode: 'static_trace',
      affectedFiles: [trigger.split(':')[0] ?? '.github/workflows'],
      affectedRoutes: [],
      attackPath: ['pull request event', 'privileged CI workflow', 'deployment behavior'],
      evidence: trigger,
      exploitabilityReasoning: 'A privileged pull_request_target workflow can expose deployment steps to untrusted pull request input.',
      recommendation: 'Move deployment to trusted branch events or separate untrusted PR checks from privileged deployment jobs.',
      patchStatus: 'suggested',
      verificationStatus: 'not_run',
      validation: { mode: 'local', destructive: false, productionTouched: false, summary: 'Static CI workflow validation only.' }
    });
  }

  const vulnerabilities = reachabilityGraph ? matchReachableVulnerabilities(systemMap, reachabilityGraph, corpus) : matchRelevantVulnerabilities(systemMap, corpus);
  for (const vulnerability of vulnerabilities) {
    const packages = vulnerability.affectedPackages.map((affected) => `${affected.name}${affected.range ? ` ${affected.range}` : ''}`).join(', ');
    findings.push({
      id: findingId('BP-DEP-001', vulnerability.id),
      ruleId: 'BP-DEP-001',
      title: 'Reachable dependency vulnerability intelligence match',
      severity: vulnerability.severity,
      status: 'manual_review',
      fixStatus: 'needs_human_review',
      proofMode: 'manual_review',
      affectedFiles: systemMap.packageManifests,
      affectedRoutes: systemMap.routes.map((route) => route.path),
      attackPath: ['installed dependency', packages || vulnerability.id, 'reachable application stack'],
      evidence: `${packages || vulnerability.id}: ${vulnerability.summary}`,
      exploitabilityReasoning: 'The package is installed and the related framework is detected in the mapped application stack.',
      recommendation: vulnerability.remediation,
      patchStatus: 'needs_human_review',
      verificationStatus: 'manual_review',
      validation: {
        mode: 'local',
        destructive: false,
        productionTouched: false,
        summary: 'Dependency match only; no exploit payloads were run.'
      }
    });
  }

  return findings;
}
