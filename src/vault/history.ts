import { vaultTimelineEventSchema, type VaultFindingEvent, type VaultHistory, type VaultLifecycle, type VaultTimelineEvent } from './types.js';

interface FingerprintState {
  everFixed: boolean;
  lastFinding: VaultFindingEvent;
  lastLifecycle: VaultLifecycle;
}

function sortByTimestampThenId<T extends { id: string }>(items: T[], getTimestamp: (item: T) => string): T[] {
  return [...items].sort(
    (left, right) => getTimestamp(left).localeCompare(getTimestamp(right)) || left.id.localeCompare(right.id)
  );
}

function timelineEventId(runId: string, fingerprint: string, lifecycle: VaultLifecycle, sourceId: string): string {
  return lifecycle === 'not_observed'
    ? `timeline:${runId}:${fingerprint}:${lifecycle}`
    : `timeline:${sourceId}`;
}

function buildTimelineEvent(
  finding: VaultFindingEvent,
  lifecycle: VaultLifecycle,
  timestamp: string,
  sourceId: string
): VaultTimelineEvent {
  return vaultTimelineEventSchema.parse({
    id: timelineEventId(finding.runId, finding.fingerprint, lifecycle, sourceId),
    runId: finding.runId,
    findingFingerprint: finding.fingerprint,
    lifecycle,
    timestamp,
    ruleId: finding.ruleId,
    title: finding.finding.title,
    evidence: finding.finding.evidence,
    artifactPaths: finding.finding.affectedFiles
  });
}

export function projectLifecycle(history: VaultHistory): VaultTimelineEvent[] {
  const runs = sortByTimestampThenId(history.runs, (run) => run.startedAt);
  const findingsByRun = new Map<string, VaultFindingEvent[]>();
  for (const finding of sortByTimestampThenId(history.findings, (event) => event.observedAt)) {
    const entries = findingsByRun.get(finding.runId);
    if (entries) {
      entries.push(finding);
    } else {
      findingsByRun.set(finding.runId, [finding]);
    }
  }

  const seen = new Map<string, FingerprintState>();
  const timeline: VaultTimelineEvent[] = [];

  for (const run of runs) {
    const currentFindings = [...(findingsByRun.get(run.id) ?? [])].sort(
      (left, right) => left.observedAt.localeCompare(right.observedAt) || left.id.localeCompare(right.id)
    );
    const currentFingerprints = new Set(currentFindings.map((finding) => finding.fingerprint));

    for (const finding of currentFindings) {
      const existing = seen.get(finding.fingerprint);
      const lifecycle: VaultLifecycle =
        finding.lifecycleInput === 'verified_fixed'
          ? 'fixed'
          : existing?.everFixed
            ? 'reopened'
            : existing
              ? 'repeated'
              : 'new';
      timeline.push(buildTimelineEvent(finding, lifecycle, finding.observedAt, finding.id));
      seen.set(finding.fingerprint, {
        everFixed: Boolean(existing?.everFixed || finding.lifecycleInput === 'verified_fixed'),
        lastFinding: finding,
        lastLifecycle: lifecycle
      });
    }

    const absentFingerprints = [...seen.keys()]
      .filter((fingerprint) => !currentFingerprints.has(fingerprint))
      .sort((left, right) => left.localeCompare(right));

    for (const fingerprint of absentFingerprints) {
      const state = seen.get(fingerprint);
      if (!state) continue;
      const timestamp = run.completedAt;
      const absentFinding = state.lastFinding;
      timeline.push(
        vaultTimelineEventSchema.parse({
          id: timelineEventId(run.id, fingerprint, 'not_observed', absentFinding.id),
          runId: run.id,
          findingFingerprint: fingerprint,
          lifecycle: 'not_observed',
          timestamp,
          ruleId: absentFinding.ruleId,
          title: absentFinding.finding.title,
          evidence: absentFinding.finding.evidence,
          artifactPaths: absentFinding.finding.affectedFiles
        })
      );
      seen.set(fingerprint, {
        ...state,
        lastLifecycle: 'not_observed'
      });
    }
  }

  return timeline.sort(
    (left, right) => left.timestamp.localeCompare(right.timestamp) || left.id.localeCompare(right.id)
  );
}

export function currentLifecycleByFingerprint(history: VaultHistory): Map<string, VaultLifecycle> {
  const current = new Map<string, VaultLifecycle>();
  for (const event of projectLifecycle(history)) {
    current.set(event.findingFingerprint, event.lifecycle);
  }
  return current;
}
