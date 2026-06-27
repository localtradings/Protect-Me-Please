import { type Finding, type PatchSummary, type Verification, verificationSchema } from '../core/types.js';

export function createVerification(findings: Finding[], patchSummary: PatchSummary): Verification {
  return verificationSchema.parse({
    generatedAt: new Date().toISOString(),
    items: findings.map((finding) => {
      const patch = patchSummary.items.find((item) => item.findingId === finding.id);
      const status =
        patch?.status === 'verified_fixed'
          ? 'verified_fixed'
          : patch?.status === 'patch_created' || patch?.status === 'test_added'
            ? 'patch_created'
            : finding.proofMode === 'local_fixture'
              ? 'simulated'
              : patch?.status === 'needs_human_review' || finding.proofMode === 'manual_review'
                ? 'needs_human_review'
                : 'unverified';
      const before = `Before patch: ${finding.attackPath.join(' -> ')}. Evidence: ${finding.evidence}`;
      const after =
        status === 'verified_fixed'
          ? 'After patch: the same replay was blocked by local verification.'
          : status === 'patch_created'
            ? 'After patch: not measured yet because BreachProof wrote patch artifacts only and did not modify source files.'
            : status === 'simulated'
              ? 'After patch: not measured yet; local fixture proof is simulated until an explicit patch replay runs.'
              : 'After patch: not measured.';
      return {
        findingId: finding.id,
        status,
        proofMode: finding.proofMode,
        productionTouched: false,
        destructive: false,
        summary:
          status === 'needs_human_review'
            ? 'Verification requires human review; no unsafe exploitation was attempted.'
            : `${before} ${after} Status: ${status}.`
      };
    })
  });
}

export function markVerificationPending(findings: Finding[]): Finding[] {
  return findings.map((finding) => ({ ...finding, verificationStatus: finding.verificationStatus === 'manual_review' ? 'manual_review' : 'not_run' }));
}
