import type { Finding } from '../core/types.js';
import { findingFingerprint, findingIdentityTraits } from './fingerprint.js';
import type { FindingSimilarity, FindingSimilarityComponents } from './types.js';

function intersectionSize(left: string[], right: string[]): number {
  const rightSet = new Set(right);
  return new Set(left.filter((value) => rightSet.has(value))).size;
}

function jaccard(left: string[], right: string[]): number {
  const union = new Set([...left, ...right]);
  if (union.size === 0) return 0;
  return intersectionSize(left, right) / union.size;
}

function roundedScore(score: number): number {
  return Number(score.toFixed(6));
}

export function compareFindingSimilarity(current: Finding, previous: Finding): FindingSimilarity {
  const currentFingerprint = findingFingerprint(current);
  const previousFingerprint = findingFingerprint(previous);
  const currentTraits = findingIdentityTraits(current);
  const previousTraits = findingIdentityTraits(previous);
  const routeSimilarity = jaccard(currentTraits.routeTokens, previousTraits.routeTokens);
  const evidenceSimilarity = jaccard(currentTraits.evidenceTags, previousTraits.evidenceTags);
  const components: FindingSimilarityComponents = {
    same_rule: currentTraits.ruleId === previousTraits.ruleId ? 0.3 : 0,
    same_control_family:
      intersectionSize(currentTraits.controlTags, previousTraits.controlTags) > 0 ? 0.2 : 0,
    same_sink:
      currentTraits.sink !== 'unknown' && currentTraits.sink === previousTraits.sink ? 0.2 : 0,
    route_tokens: roundedScore(routeSimilarity * 0.15),
    same_framework_file_role:
      currentTraits.framework !== 'unknown' &&
      currentTraits.framework === previousTraits.framework &&
      currentTraits.fileRole === previousTraits.fileRole
        ? 0.1
        : 0,
    evidence_tags: roundedScore(evidenceSimilarity * 0.05)
  };
  const signals = (Object.keys(components) as Array<keyof FindingSimilarityComponents>)
    .filter((signal) => components[signal] > 0)
    .sort();
  const score = Object.values(components).reduce((total, component) => total + component, 0);

  return {
    currentFingerprint,
    previousFingerprint,
    score: roundedScore(score),
    signals,
    exactMatch: currentFingerprint === previousFingerprint,
    components
  };
}

export function findSimilarFindings(
  current: Finding,
  previous: Finding[],
  threshold = 0.75
): FindingSimilarity[] {
  return previous
    .map((candidate) => compareFindingSimilarity(current, candidate))
    .filter((similarity) => !similarity.exactMatch && similarity.score >= threshold)
    .sort(
      (left, right) =>
        right.score - left.score || left.previousFingerprint.localeCompare(right.previousFingerprint)
    );
}
