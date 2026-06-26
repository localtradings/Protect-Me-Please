import type { AttackGraph, ReachabilityGraph, SystemMap, VulnerabilityRecord } from '../core/types.js';
import { matchReachableVulnerabilities } from './reachability.js';
import { matchRelevantVulnerabilities } from './vulnerability-corpus.js';

export function buildAttackGraph(systemMap: SystemMap, corpus: VulnerabilityRecord[], reachabilityGraph?: ReachabilityGraph): AttackGraph {
  const nodes: AttackGraph['nodes'] = [];
  const edges: AttackGraph['edges'] = [];
  const addNode = (node: AttackGraph['nodes'][number]): void => {
    if (!nodes.some((existing) => existing.id === node.id)) nodes.push(node);
  };

  for (const route of systemMap.routes) {
    addNode({ id: route.id, type: 'route', label: `${route.method} ${route.path}`, metadata: { file: route.file, framework: route.framework } });
    if (route.authDetected) {
      const authId = `auth:${route.id}`;
      addNode({ id: authId, type: 'auth', label: 'Detected authentication boundary', metadata: { file: route.file } });
      edges.push({ from: route.id, to: authId, label: 'requires authentication' });
    }
    if (route.authDetected && !route.ownershipCheckDetected && route.prismaModels.length > 0) {
      const weaknessId = `weakness:ownership:${route.id}`;
      addNode({ id: weaknessId, type: 'weakness', label: 'Missing ownership or tenant check', metadata: { file: route.file } });
      edges.push({ from: route.id, to: weaknessId, label: 'missing ownership/tenant authorization check' });
      for (const model of route.prismaModels) {
        const dataId = `data:${model}`;
        addNode({ id: dataId, type: 'data', label: model, metadata: {} });
        edges.push({ from: weaknessId, to: dataId, label: 'can expose sensitive model' });
      }
    }
    if (route.dangerousBodyFields.length > 0) {
      const weaknessId = `weakness:body:${route.id}`;
      addNode({ id: weaknessId, type: 'weakness', label: 'Client-controlled privileged fields', metadata: { fields: route.dangerousBodyFields.join(',') } });
      edges.push({ from: route.id, to: weaknessId, label: 'accepts privileged fields from request body' });
    }
  }

  for (const tool of systemMap.aiToolCalls) {
    const toolId = `ai:${tool.name}:${tool.file}`;
    addNode({ id: toolId, type: 'ai_tool', label: tool.name, metadata: { file: tool.file } });
    if (tool.dangerous && !tool.guardrailsDetected) {
      const weaknessId = `weakness:ai:${tool.name}`;
      addNode({ id: weaknessId, type: 'weakness', label: 'Dangerous AI tool without guardrails', metadata: { file: tool.file } });
      edges.push({ from: toolId, to: weaknessId, label: 'tool can run without allowlist or approval' });
    }
  }

  const vulnerabilities = reachabilityGraph ? matchReachableVulnerabilities(systemMap, reachabilityGraph, corpus) : matchRelevantVulnerabilities(systemMap, corpus);
  for (const vulnerability of vulnerabilities) {
    const packageLabel = vulnerability.affectedPackages.map((affected) => affected.name).join(',') || vulnerability.id;
    const dependencyId = `dependency:${packageLabel}`;
    addNode({ id: dependencyId, type: 'dependency', label: packageLabel, metadata: { severity: vulnerability.severity } });
    const weaknessId = `weakness:dependency:${vulnerability.id}`;
    addNode({ id: weaknessId, type: 'weakness', label: vulnerability.summary, metadata: { cwe: vulnerability.cwe.join(',') } });
    edges.push({ from: dependencyId, to: weaknessId, label: 'installed vulnerable version is reachable from application flow' });
  }

  for (const trigger of systemMap.ci.unsafeTriggers) {
    const ciId = `ci:${trigger}`;
    addNode({ id: ciId, type: 'ci', label: trigger, metadata: {} });
  }

  return { nodes, edges };
}
