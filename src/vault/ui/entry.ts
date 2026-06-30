/// <reference lib="dom" />

import ForceGraph3D, {
  type ForceGraph3DInstance,
  type LinkObject,
  type NodeObject
} from '3d-force-graph';
import * as THREE from 'three';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { vaultGraphSchema, type VaultEdge, type VaultGraph, type VaultNode } from '../types.js';
import {
  edgeColor,
  edgeCurvature,
  edgeParticleCount,
  edgeParticleSpeed,
  edgeShowsDirection,
  edgeWidth
} from './graph-style.js';
import { createVaultNodeObject, updateVaultNodeState } from './node-assets.js';

type RenderNode = VaultNode & Omit<NodeObject, 'id'>;

type RenderLink = Omit<LinkObject<RenderNode>, 'source' | 'target'> & {
  id: string;
  source: string | RenderNode;
  target: string | RenderNode;
  edge: VaultEdge;
};

export interface VaultGraphController {
  destroy(): void;
}

function renderData(graph: VaultGraph): { nodes: RenderNode[]; links: RenderLink[] } {
  return {
    nodes: graph.nodes.map((node) => ({ ...node, metadata: { ...node.metadata } })),
    links: graph.edges.map((edge) => ({
      id: edge.id,
      source: edge.from,
      target: edge.to,
      edge
    }))
  };
}

function nodeTooltip(node: RenderNode): HTMLElement {
  const tooltip = document.createElement('div');
  tooltip.className = 'vault-node-tooltip';
  const label = document.createElement('strong');
  label.textContent = node.label;
  const status = document.createElement('span');
  status.textContent = `${node.type} · ${node.status}`;
  tooltip.append(label, status);
  return tooltip;
}

function disposeObject(object: THREE.Object3D): void {
  object.traverse((child) => {
    const candidate = child as THREE.Mesh | THREE.LineSegments;
    candidate.geometry?.dispose();
    const materials = candidate.material
      ? Array.isArray(candidate.material)
        ? candidate.material
        : [candidate.material]
      : [];
    for (const material of materials) {
      if (material instanceof THREE.MeshBasicMaterial && material.map) material.map.dispose();
      material.dispose();
    }
  });
}

export function startVaultGraph(root: HTMLElement, graphInput: VaultGraph): VaultGraphController {
  const graph = vaultGraphSchema.parse(graphInput);
  const objects = new Map<string, THREE.Group>();
  let selectedNodeId: string | undefined;

  const renderer = new ForceGraph3D(root, {
    controlType: 'orbit',
    rendererConfig: { antialias: true, alpha: false, powerPreference: 'high-performance' }
  }) as unknown as ForceGraph3DInstance<RenderNode, RenderLink>;
  renderer.renderer().toneMapping = THREE.ACESFilmicToneMapping;
  renderer.renderer().toneMappingExposure = 0.92;
  renderer.renderer().outputColorSpace = THREE.SRGBColorSpace;
  const nodeObjectFactory = (node: RenderNode): THREE.Group => {
    const object = createVaultNodeObject(node);
    objects.set(node.id, object);
    return object;
  };

  renderer
    .backgroundColor('#030507')
    .showNavInfo(false)
    .nodeId('id')
    .nodeLabel(nodeTooltip)
    .nodeThreeObject(nodeObjectFactory)
    .linkColor((link) => edgeColor(link.edge))
    .linkWidth((link) => edgeWidth(link.edge))
    .linkCurvature((link) => edgeCurvature(link.edge))
    .linkDirectionalParticles((link) => edgeParticleCount(link.edge))
    .linkDirectionalParticleColor((link) => edgeColor(link.edge))
    .linkDirectionalParticleWidth((link) => edgeWidth(link.edge) + 0.65)
    .linkDirectionalParticleSpeed((link) => edgeParticleSpeed(link.edge))
    .linkDirectionalArrowLength((link) => (edgeShowsDirection(link.edge) ? 2.8 : 0))
    .linkDirectionalArrowColor((link) => edgeColor(link.edge))
    .linkDirectionalArrowRelPos(0.72)
    .warmupTicks(80)
    .cooldownTicks(180)
    .onNodeClick((node) => {
      selectedNodeId = node.id;
      for (const [id, object] of objects) {
        updateVaultNodeState(object, { selected: id === selectedNodeId, dimmed: false });
      }
    })
    .graphData(renderData(graph));

  const bloomPass = new UnrealBloomPass(
    new THREE.Vector2(Math.max(root.clientWidth, 1), Math.max(root.clientHeight, 1)),
    0.42,
    0.18,
    0.88
  );
  renderer.postProcessingComposer().addPass(bloomPass);

  const resize = (): void => {
    const width = Math.max(root.clientWidth, 1);
    const height = Math.max(root.clientHeight, 1);
    renderer.width(width).height(height);
    bloomPass.setSize(width, height);
  };
  resize();
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(root);

  return {
    destroy(): void {
      resizeObserver.disconnect();
      bloomPass.dispose();
      for (const object of objects.values()) disposeObject(object);
      objects.clear();
      renderer._destructor();
      root.replaceChildren();
    }
  };
}

function bootEmbeddedVault(): void {
  const root = document.getElementById('breachproof-vault');
  const payload = document.getElementById('breachproof-vault-data');
  if (!(root instanceof HTMLElement) || !payload?.textContent) return;

  try {
    const graph = vaultGraphSchema.parse(JSON.parse(payload.textContent) as unknown);
    startVaultGraph(root, graph);
  } catch (error) {
    root.dataset.vaultBootError = 'true';
    root.textContent = error instanceof Error
      ? `Unable to open BreachProof Vault: ${error.message}`
      : 'Unable to open BreachProof Vault.';
  }
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootEmbeddedVault, { once: true });
  } else {
    bootEmbeddedVault();
  }
}
