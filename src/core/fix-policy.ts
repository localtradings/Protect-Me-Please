import type { Finding, FixDisposition, PatchSummary } from './types.js';

export interface FindingFixDisposition {
  findingId: string;
  disposition: FixDisposition;
}

export function classifyFixDispositions(
  findings: Finding[],
  patchSummary: PatchSummary
): FindingFixDisposition[] {
  const patches = new Map(patchSummary.items.map((item) => [item.findingId, item]));
  return findings.map((finding) => {
    const patch = patches.get(finding.id);
    const disposition: FixDisposition =
      patch?.patchFile || patch?.testFile
        ? 'review_patch'
        : 'manual_review';
    return { findingId: finding.id, disposition };
  });
}
