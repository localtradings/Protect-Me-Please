import type { VaultEdge, VaultEdgeType, VaultNodeType } from '../types.js';

export interface VaultNodeVisualStyle {
  color: string;
  emissive: string;
  scale: number;
}

const NODE_STYLES: Record<VaultNodeType, VaultNodeVisualStyle> = {
  route: { color: '#62cfff', emissive: '#0b6f96', scale: 4.4 },
  finding: { color: '#ff5964', emissive: '#a80f24', scale: 5.4 },
  invariant: { color: '#f4bd62', emissive: '#8a510d', scale: 4.2 },
  patch: { color: '#65e6b5', emissive: '#16785d', scale: 3.6 },
  replay: { color: '#b78cff', emissive: '#5d2ca2', scale: 3.4 },
  test: { color: '#d8fff4', emissive: '#247d67', scale: 2.6 },
  asset: { color: '#cceaff', emissive: '#216c9a', scale: 6.8 },
  run: { color: '#89939f', emissive: '#303945', scale: 2.2 }
};

const EDGE_COLORS: Record<VaultEdgeType, string> = {
  observed_in: '#3f4854',
  affects: '#667382',
  violates: '#ff4d5f',
  reaches: '#ff4d5f',
  proved_by: '#9e78dc',
  fixed_by: '#5fe0ad',
  verified_by: '#8ceacb',
  similar_to: '#a86ee8',
  reopened_from: '#c45d77',
  repeated_from: '#68717f',
  protects: '#99cde8'
};

const ACTIVE_EDGE_TYPES = new Set<VaultEdgeType>([
  'reaches',
  'violates',
  'fixed_by',
  'similar_to'
]);

export function nodeVisualStyle(type: VaultNodeType): VaultNodeVisualStyle {
  return NODE_STYLES[type];
}

export function edgeColor(edge: Pick<VaultEdge, 'type'>): string {
  return EDGE_COLORS[edge.type];
}

export function edgeWidth(edge: Pick<VaultEdge, 'type'>): number {
  switch (edge.type) {
    case 'violates':
    case 'reaches':
      return 2.2;
    case 'fixed_by':
    case 'similar_to':
      return 1.6;
    case 'verified_by':
    case 'protects':
      return 1.1;
    default:
      return 0.55;
  }
}

export function edgeCurvature(edge: Pick<VaultEdge, 'type'>): number {
  switch (edge.type) {
    case 'similar_to':
      return 0.22;
    case 'proved_by':
    case 'reopened_from':
    case 'repeated_from':
      return 0.1;
    default:
      return 0;
  }
}

export function edgeParticleCount(edge: Pick<VaultEdge, 'type'>): number {
  return ACTIVE_EDGE_TYPES.has(edge.type) ? 3 : 0;
}

export function edgeParticleSpeed(edge: Pick<VaultEdge, 'type'>): number {
  return edge.type === 'similar_to' ? 0.0025 : 0.0045;
}

export function edgeShowsDirection(edge: Pick<VaultEdge, 'type'>): boolean {
  return ACTIVE_EDGE_TYPES.has(edge.type) || edge.type === 'verified_by';
}
