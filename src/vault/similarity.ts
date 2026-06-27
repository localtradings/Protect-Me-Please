import type { Finding } from '../core/types.js';
import { findingFingerprint, findingIdentityTraits } from './fingerprint.js';
import type { FindingSimilarity } from './types.js';

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
  const signals: string[] = [];
  let score = 0;

  if (currentTraits.ruleId === previousTraits.ruleId) {
    score += 0.3;
    signals.push('same_rule');
  }

  if (intersectionSize(currentTraits.controlTags, previousTraits.controlTags) > 0) {
    score += 0.2;
    signals.push('same_control_family');
  }

  if (currentTraits.sink !== 'unknown' && currentTraits.sink === previousTraits.sink) {
    score += 0.2;
    signals.push('same_sink');
  }

  const routeSimilarity = jaccard(currentTraits.routeTokens, previousTraits.routeTokens);
  if (routeSimilarity > 0) {
    score += routeSimilarity * 0.15;
    signals.push('route_tokens');
  }

  if (
    currentTraits.framework !== 'unknown' &&
    currentTraits.framework === previousTraits.framework &&
    currentTraits.fileRole === previousTraits.fileRole
  ) {
    score += 0.1;
    signals.push('same_framework_file_role');
  }

  const evidenceSimilarity = jaccard(currentTraits.evidenceTags, previousTraits.evidenceTags);
  if (evidenceSimilarity > 0) {
    score += evidenceSimilarity * 0.05;
    signals.push('evidence_tags');
  }

  return {
    currentFingerprint,
    previousFingerprint,
    score: roundedScore(score),
    signals: signals.sort(),
    exactMatch: currentFingerprint === previousFingerprint
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
