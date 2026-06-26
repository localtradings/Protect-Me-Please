import { type EvidenceBundle, type Finding, type ReachabilityGraph, type ValidationPlan, evidenceBundleSchema, validationPlanSchema } from '../core/types.js';

function stepsForFinding(finding: Finding): string[] {
  if (finding.proofMode === 'local_fixture') {
    return [
      'Create two fake tenants, two fake users, and one fake sensitive resource in local fixture data.',
      'Model the vulnerable request as User A attempting to access Tenant B data.',
      'Record the expected breach path and safe local proof without touching production.'
    ];
  }
  if (finding.proofMode === 'manual_review') {
    return ['Do not exploit automatically.', 'Present reachability and remediation evidence for human review.'];
  }
  return ['Trace the route, code path, and data/control-flow evidence statically.', 'Record the proof as static_trace evidence.'];
}

export function createValidationPlan(findings: Finding[], _reachabilityGraph: ReachabilityGraph): ValidationPlan {
  void _reachabilityGraph;
  return validationPlanSchema.parse({
    generatedAt: new Date().toISOString(),
    items: findings.map((finding) => ({
      findingId: finding.id,
      ruleId: finding.ruleId,
      proofMode: finding.proofMode,
      safe: finding.proofMode !== 'manual_review',
      destructive: false,
      steps: stepsForFinding(finding),
      expectedEvidence: finding.evidence
    }))
  });
}

export function createEvidenceBundle(findings: Finding[]): EvidenceBundle {
  return evidenceBundleSchema.parse({
    generatedAt: new Date().toISOString(),
    items: findings.map((finding) => ({
      findingId: finding.id,
      proofMode: finding.proofMode,
      before:
        finding.proofMode === 'local_fixture'
          ? `Local fixture proof: ${finding.attackPath.join(' -> ')}. No production data was used.`
          : finding.evidence,
      after: finding.verificationStatus === 'passed' ? 'The same validation no longer reproduces after the proposed fix.' : undefined,
      productionTouched: false,
      destructive: false
    }))
  });
}
