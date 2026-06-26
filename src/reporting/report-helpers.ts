import { type ReachabilityGraph, reachabilityGraphSchema } from '../core/types.js';

export function generateEmptyReachabilityGraph(): ReachabilityGraph {
  return reachabilityGraphSchema.parse({
    generatedAt: new Date().toISOString(),
    nodes: [],
    edges: [],
    summary: {
      reachableRoutes: 0,
      reachableDependencies: [],
      reachableModels: [],
      aiToolFlows: 0
    }
  });
}
