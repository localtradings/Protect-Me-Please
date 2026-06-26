import { type Finding, type PatchSummary, type Verification, verificationSchema } from '../core/types.js';

export function createVerification(findings: Finding[], patchSummary: PatchSummary): Verification {
  return verificationSchema.parse({
    generatedAt: new Date().toISOString(),
    items: findings.map((finding) => {
      const patch = patchSummary.items.find((item) => item.findingId === finding.id);
      const status = patch?.status === 'needs_human_review' || finding.proofMode === 'manual_review' ? 'manual_review' : 'not_run';
      return {
        findingId: finding.id,
        status,
        proofMode: finding.proofMode,
        productionTouched: false,
        destructive: false,
        summary:
          status === 'manual_review'
            ? 'Verification requires human review; no unsafe exploitation was attempted.'
            : 'Patch artifact generated. Verification will run after the patch is explicitly applied.'
      };
    })
  });
}

export function markVerificationPending(findings: Finding[]): Finding[] {
  return findings.map((finding) => ({ ...finding, verificationStatus: finding.verificationStatus === 'manual_review' ? 'manual_review' : 'not_run' }));
}
