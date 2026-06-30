/// <reference lib="dom" />

import ForceGraph3D, {
  type ForceGraph3DInstance,
  type LinkObject,
  type NodeObject
} from '3d-force-graph';
import {
  Box,
  createIcons,
  Filter,
  Focus,
  Fullscreen,
  Layers3,
  Network,
  Orbit,
  Pause,
  Play,
  ScanSearch,
  Search,
  Settings,
  Shield,
  X
} from 'lucide';
import * as THREE from 'three';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import {
  vaultGraphSchema,
  type VaultEdge,
  type VaultEdgeType,
  type VaultGraph,
  type VaultNode,
  type VaultNodeType,
  type VaultTimelineEvent
} from '../types.js';
import { renderVaultFallback } from './fallback.js';
import {
  edgeColor,
  edgeCurvature,
  edgeParticleCount,
  edgeParticleSpeed,
  edgeShowsDirection,
  edgeWidth
} from './graph-style.js';
import { createVaultNodeObject, updateVaultNodeState } from './node-assets.js';

type VaultGraphMode = 'local' | 'global' | 'breach_path';
type RenderNode = VaultNode & Omit<NodeObject, 'id'>;
type RenderLink = Omit<LinkObject<RenderNode>, 'source' | 'target'> & {
  id: string;
  source: string | RenderNode;
  target: string | RenderNode;
  edge: VaultEdge;
};

const NODE_TYPES: VaultNodeType[] = [
  'route',
  'finding',
  'invariant',
  'patch',
  'replay',
  'test',
  'asset',
  'run'
];
const EDGE_TYPES: VaultEdgeType[] = [
  'observed_in',
  'affects',
  'violates',
  'reaches',
  'proved_by',
  'fixed_by',
  'verified_by',
  'similar_to',
  'reopened_from',
  'repeated_from',
  'protects'
];
const BREACH_PATH_EDGE_TYPES = new Set<VaultEdgeType>(['affects', 'violates', 'reaches']);

export interface VaultGraphController {
  selectNode(id: string): void;
  setMode(mode: VaultGraphMode): void;
  setDepth(depth: number): void;
  setRunRange(from: string, to: string): void;
  search(query: string): string[];
  playTimeline(): void;
  pauseTimeline(): void;
  fit(): void;
  destroy(): void;
}

interface VaultShell {
  shell: HTMLDivElement;
  scene: HTMLDivElement;
  inspector: HTMLElement;
  inspectorContent: HTMLDivElement;
  inspectorClose: HTMLButtonElement;
  searchInput: HTMLInputElement;
  searchResults: HTMLDivElement;
  filterPanel: HTMLElement;
  filterButton: HTMLButtonElement;
  modeButtons: Record<VaultGraphMode, HTMLButtonElement>;
  toolButtons: {
    orbit: HTMLButtonElement;
    search: HTMLButtonElement;
    focus: HTMLButtonElement;
    assets: HTMLButtonElement;
    layers: HTMLButtonElement;
    settings: HTMLButtonElement;
    fit: HTMLButtonElement;
    fullscreen: HTMLButtonElement;
  };
  nodeTypeInputs: Map<VaultNodeType, HTMLInputElement>;
  edgeTypeInputs: Map<VaultEdgeType, HTMLInputElement>;
  severitySelect: HTMLSelectElement;
  statusSelect: HTMLSelectElement;
  depthInput: HTMLInputElement;
  fromInput: HTMLInputElement;
  toInput: HTMLInputElement;
  playButton: HTMLButtonElement;
  pauseButton: HTMLButtonElement;
  timelineEventButtons: Map<string, HTMLButtonElement>;
}

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function iconButton(label: string, icon: string, className = 'vault-icon-button'): HTMLButtonElement {
  const button = element('button', className);
  button.type = 'button';
  button.setAttribute('aria-label', label);
  button.title = label;
  const iconElement = element('i');
  iconElement.dataset.lucide = icon;
  iconElement.setAttribute('aria-hidden', 'true');
  button.append(iconElement);
  return button;
}

function modeButton(label: string): HTMLButtonElement {
  const button = element('button', 'vault-mode-button', label);
  button.type = 'button';
  button.setAttribute('aria-pressed', 'false');
  return button;
}

function titleCase(value: string): string {
  return value.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function renderData(graph: VaultGraph): { nodes: RenderNode[]; links: RenderLink[] } {
  const nodes: RenderNode[] = graph.nodes.map((node) => ({
    ...node,
    metadata: { ...node.metadata }
  }));
  const connectedNodeIds = new Set(graph.edges.flatMap((edge) => [edge.from, edge.to]));
  const isolatedNodes = nodes.filter((node) => !connectedNodeIds.has(node.id));
  isolatedNodes.forEach((node, index) => {
    const angle = (Math.PI * 2 * index) / Math.max(isolatedNodes.length, 1) - Math.PI / 4;
    node.fx = Math.cos(angle) * 88;
    node.fy = Math.sin(angle) * 58;
    node.fz = index % 2 === 0 ? -18 : 18;
  });
  return {
    nodes,
    links: graph.edges.map((edge) => ({
      id: edge.id,
      source: edge.from,
      target: edge.to,
      edge
    }))
  };
}

function nodeTooltip(node: RenderNode): HTMLElement {
  const tooltip = element('div', 'vault-node-tooltip');
  tooltip.append(
    element('strong', undefined, node.label),
    element('span', undefined, `${node.type} · ${node.status}`)
  );
  return tooltip;
}

function routeProfileHref(profilePath: string | undefined): string | undefined {
  if (!profilePath) return undefined;
  const normalized = profilePath.replace(/\\/g, '/');
  const prefix = 'reports/vault/';
  if (!normalized.startsWith(`${prefix}route-profiles/`)) return undefined;
  const relative = normalized.slice(prefix.length);
  if (relative.split('/').some((segment) => !segment || segment === '.' || segment === '..')) {
    return undefined;
  }
  return `./${relative}`;
}

function createChoice(
  label: string,
  value: string,
  checked: boolean
): { wrapper: HTMLLabelElement; input: HTMLInputElement } {
  const wrapper = element('label', 'vault-filter-choice');
  const input = element('input');
  input.type = 'checkbox';
  input.value = value;
  input.checked = checked;
  wrapper.append(input, document.createTextNode(label));
  return { wrapper, input };
}

function createSelect(options: string[], label: string): HTMLSelectElement {
  const select = element('select');
  select.setAttribute('aria-label', label);
  for (const optionValue of options) {
    const option = element('option', undefined, titleCase(optionValue));
    option.value = optionValue;
    select.append(option);
  }
  return select;
}

function buildFilterPanel(): Pick<
  VaultShell,
  | 'filterPanel'
  | 'nodeTypeInputs'
  | 'edgeTypeInputs'
  | 'severitySelect'
  | 'statusSelect'
  | 'depthInput'
  | 'fromInput'
  | 'toInput'
> {
  const panel = element('section', 'vault-filter-panel');
  panel.setAttribute('aria-label', 'Graph filters');
  panel.hidden = true;
  panel.append(element('h2', undefined, 'Graph filters'));

  const nodeFieldset = element('fieldset');
  nodeFieldset.append(element('legend', undefined, 'Node types'));
  const nodeGrid = element('div', 'vault-filter-grid');
  const nodeTypeInputs = new Map<VaultNodeType, HTMLInputElement>();
  for (const type of NODE_TYPES) {
    const choice = createChoice(titleCase(type), type, true);
    nodeTypeInputs.set(type, choice.input);
    nodeGrid.append(choice.wrapper);
  }
  nodeFieldset.append(nodeGrid);

  const edgeFieldset = element('fieldset');
  edgeFieldset.dataset.filterGroup = 'edges';
  edgeFieldset.append(element('legend', undefined, 'Edge types'));
  const edgeGrid = element('div', 'vault-filter-grid');
  const edgeTypeInputs = new Map<VaultEdgeType, HTMLInputElement>();
  for (const type of EDGE_TYPES) {
    const choice = createChoice(titleCase(type), type, true);
    edgeTypeInputs.set(type, choice.input);
    edgeGrid.append(choice.wrapper);
  }
  edgeFieldset.append(edgeGrid);

  const severityLabel = element('label', 'vault-filter-field');
  severityLabel.append(element('span', undefined, 'Severity'));
  const severitySelect = createSelect(
    ['all', 'critical', 'high', 'medium', 'low', 'info'],
    'Severity filter'
  );
  severityLabel.append(severitySelect);

  const statusLabel = element('label', 'vault-filter-field');
  statusLabel.append(element('span', undefined, 'Lifecycle'));
  const statusSelect = createSelect(
    ['all', 'new', 'repeated', 'fixed', 'reopened', 'not_observed'],
    'Lifecycle filter'
  );
  statusLabel.append(statusSelect);

  const depthLabel = element('label', 'vault-filter-field');
  depthLabel.append(element('span', undefined, 'Neighborhood depth'));
  const depthInput = element('input');
  depthInput.type = 'range';
  depthInput.min = '1';
  depthInput.max = '4';
  depthInput.value = '2';
  depthInput.setAttribute('aria-label', 'Neighborhood depth');
  depthLabel.append(depthInput);

  const range = element('fieldset', 'vault-run-range');
  range.append(element('legend', undefined, 'Run range'));
  const fromInput = element('input');
  fromInput.type = 'date';
  fromInput.setAttribute('aria-label', 'Run range from');
  const toInput = element('input');
  toInput.type = 'date';
  toInput.setAttribute('aria-label', 'Run range to');
  range.append(fromInput, toInput);

  panel.append(nodeFieldset, edgeFieldset, severityLabel, statusLabel, depthLabel, range);
  return {
    filterPanel: panel,
    nodeTypeInputs,
    edgeTypeInputs,
    severitySelect,
    statusSelect,
    depthInput,
    fromInput,
    toInput
  };
}

function buildShell(root: HTMLElement, graph: VaultGraph): VaultShell {
  const shell = element('div', 'vault-shell');

  const topbar = element('header', 'vault-topbar');
  const brand = element('div', 'vault-brand');
  const brandMark = element('span', 'vault-brand-mark');
  const brandIcon = element('i');
  brandIcon.dataset.lucide = 'shield';
  brandMark.append(brandIcon);
  brand.append(brandMark, element('strong', undefined, 'BREACHPROOF VAULT'));
  const modes = element('div', 'vault-modes');
  modes.setAttribute('aria-label', 'Graph mode');
  const modeButtons: Record<VaultGraphMode, HTMLButtonElement> = {
    global: modeButton('Global graph'),
    local: modeButton('Local neighborhood'),
    breach_path: modeButton('Breach paths')
  };
  modes.append(modeButtons.global, modeButtons.local, modeButtons.breach_path);
  const searchRegion = element('div', 'vault-search');
  const searchIcon = element('i');
  searchIcon.dataset.lucide = 'search';
  const searchInput = element('input');
  searchInput.type = 'search';
  searchInput.autocomplete = 'off';
  searchInput.placeholder = 'Search routes, findings, invariants, patches';
  searchInput.setAttribute('aria-label', 'Search Vault graph');
  const searchResults = element('div', 'vault-search-results');
  searchResults.setAttribute('aria-label', 'Search results');
  searchResults.hidden = true;
  searchRegion.append(searchIcon, searchInput, searchResults);
  const localStatus = element('div', 'vault-local-status');
  localStatus.append(element('span', 'vault-status-dot'), document.createTextNode('LOCAL ONLY'));
  topbar.append(brand, modes, searchRegion, localStatus);

  const tools = element('nav', 'vault-tools');
  tools.setAttribute('aria-label', 'Graph tools');
  const orbitButton = iconButton('Reset orbit', 'orbit');
  const searchButton = iconButton('Search graph', 'search');
  const filterButton = iconButton('Filters', 'filter');
  filterButton.setAttribute('aria-expanded', 'false');
  const focusButton = iconButton('Focus selection', 'focus');
  const assetsButton = iconButton('Protected assets', 'box');
  const layersButton = iconButton('Graph layers', 'layers-3');
  const settingsButton = iconButton('Graph settings', 'settings');
  const fitButton = iconButton('Fit graph', 'scan-search');
  const fullscreenButton = iconButton('Fullscreen', 'fullscreen');
  tools.append(
    orbitButton,
    searchButton,
    filterButton,
    focusButton,
    assetsButton,
    layersButton,
    settingsButton,
    fitButton,
    fullscreenButton
  );

  const scene = element('div', 'vault-scene');
  scene.setAttribute('aria-label', 'Interactive Vault graph');
  if (graph.nodes.length === 0) {
    const empty = element('div', 'vault-empty-state');
    empty.append(
      element('strong', undefined, 'No security memory yet'),
      element('span', undefined, 'Run BreachProof locally to build the graph.')
    );
    const reportLink = element('a', undefined, 'Open current Markdown report');
    reportLink.href = '../final-report.md';
    empty.append(reportLink);
    scene.append(empty);
  }

  const inspector = element('aside', 'vault-inspector');
  inspector.setAttribute('aria-label', 'Vault inspector');
  const inspectorBar = element('div', 'vault-inspector-bar');
  inspectorBar.append(element('span', undefined, 'EVIDENCE INSPECTOR'));
  const inspectorClose = iconButton('Close inspector', 'x', 'vault-inspector-close');
  inspectorBar.append(inspectorClose);
  const inspectorContent = element('div', 'vault-inspector-content');
  inspector.append(inspectorBar, inspectorContent);

  const timeline = element('footer', 'vault-timeline');
  timeline.dataset.testid = 'vault-timeline';
  const playback = element('div', 'vault-playback');
  const playButton = iconButton('Play timeline', 'play');
  const pauseButton = iconButton('Pause timeline', 'pause');
  playButton.setAttribute('aria-pressed', 'false');
  pauseButton.setAttribute('aria-pressed', 'false');
  playback.append(playButton, pauseButton, element('span', undefined, 'RUN HISTORY'));
  const timelineTrack = element('div', 'vault-timeline-track');
  const timelineEventButtons = new Map<string, HTMLButtonElement>();
  for (const event of graph.timeline) {
    const marker = element('button', `vault-event vault-event-${event.lifecycle}`);
    marker.type = 'button';
    marker.title = `${event.timestamp} · ${event.lifecycle} · ${event.ruleId}`;
    marker.setAttribute('aria-label', `${event.lifecycle} ${event.ruleId} ${event.title}`);
    marker.append(
      element('span', 'vault-event-dot'),
      element('span', 'vault-event-state', event.lifecycle.toUpperCase()),
      element('time', undefined, event.timestamp.slice(5, 10))
    );
    timelineEventButtons.set(event.id, marker);
    timelineTrack.append(marker);
  }
  if (graph.timeline.length === 0) {
    timelineTrack.append(element('span', 'vault-timeline-empty', 'No recorded events'));
  }
  const timelineSummary = element(
    'div',
    'vault-timeline-summary',
    `${graph.summary.newIssues} NEW · ${graph.summary.fixedIssues} FIXED · ${graph.summary.reopenedIssues} REOPENED`
  );
  timeline.append(playback, timelineTrack, timelineSummary);

  const filters = buildFilterPanel();
  shell.append(topbar, tools, scene, inspector, timeline, filters.filterPanel);
  root.replaceChildren(shell);

  createIcons({
    root: shell,
    icons: {
      Box,
      Filter,
      Focus,
      Fullscreen,
      Layers3,
      Network,
      Orbit,
      Pause,
      Play,
      ScanSearch,
      Search,
      Settings,
      Shield,
      X
    }
  });

  return {
    shell,
    scene,
    inspector,
    inspectorContent,
    inspectorClose,
    searchInput,
    searchResults,
    filterPanel: filters.filterPanel,
    filterButton,
    modeButtons,
    toolButtons: {
      orbit: orbitButton,
      search: searchButton,
      focus: focusButton,
      assets: assetsButton,
      layers: layersButton,
      settings: settingsButton,
      fit: fitButton,
      fullscreen: fullscreenButton
    },
    nodeTypeInputs: filters.nodeTypeInputs,
    edgeTypeInputs: filters.edgeTypeInputs,
    severitySelect: filters.severitySelect,
    statusSelect: filters.statusSelect,
    depthInput: filters.depthInput,
    fromInput: filters.fromInput,
    toInput: filters.toInput,
    playButton,
    pauseButton,
    timelineEventButtons
  };
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

function connectedEdges(graph: VaultGraph, nodeId: string): VaultEdge[] {
  return graph.edges.filter((edge) => edge.from === nodeId || edge.to === nodeId);
}

function renderInspector(
  ui: VaultShell,
  graph: VaultGraph,
  selectedNode: VaultNode | undefined,
  nodeById: Map<string, VaultNode>,
  onSelect: (id: string) => void
): void {
  ui.inspectorContent.replaceChildren();
  if (!selectedNode) {
    ui.inspectorContent.append(
      element('div', 'vault-inspector-empty', 'Select a node to inspect evidence and history.')
    );
    return;
  }

  const header = element('header', 'vault-inspector-header');
  header.append(
    element('span', `vault-type-label vault-type-${selectedNode.type}`, selectedNode.type),
    element('h2', undefined, selectedNode.label),
    element('span', 'vault-node-state', selectedNode.status)
  );
  if (selectedNode.metadata.ruleId) {
    header.append(element('code', 'vault-rule-id', selectedNode.metadata.ruleId));
  }
  ui.inspectorContent.append(header);

  const metadata = element('section', 'vault-inspector-section');
  metadata.append(element('h3', undefined, 'Properties'));
  const definitions = element('dl');
  const properties: Array<[string, string | undefined]> = [
    ['Type', selectedNode.type],
    ['State', selectedNode.status],
    ['Severity', selectedNode.severity],
    ['Run', selectedNode.runId],
    ['Route', selectedNode.route]
  ];
  for (const [key, value] of Object.entries(selectedNode.metadata)) {
    properties.push([titleCase(key), value]);
  }
  for (const [label, value] of properties) {
    if (!value) continue;
    definitions.append(element('dt', undefined, label), element('dd', undefined, value));
  }
  metadata.append(definitions);
  ui.inspectorContent.append(metadata);

  const edges = connectedEdges(graph, selectedNode.id);
  const related = new Map<string, VaultNode>();
  for (const edge of edges) {
    const relatedId = edge.from === selectedNode.id ? edge.to : edge.from;
    const node = nodeById.get(relatedId);
    if (node) related.set(node.id, node);
  }

  const controlIds = [...related.values()]
    .filter((node) => node.type === 'invariant')
    .map((node) => node.metadata.invariantId ?? node.label);
  if (controlIds.length > 0) {
    const controls = element('section', 'vault-inspector-section');
    controls.append(element('h3', undefined, 'Controls'));
    const list = element('ul', 'vault-compact-list');
    for (const id of [...new Set(controlIds)]) list.append(element('li', undefined, id));
    controls.append(list);
    ui.inspectorContent.append(controls);
  }

  if (edges.length > 0) {
    const evidence = element('section', 'vault-inspector-section');
    evidence.append(element('h3', undefined, 'Evidence'));
    const list = element('ul', 'vault-evidence-list');
    const seen = new Set<string>();
    for (const edge of edges) {
      if (seen.has(edge.evidence)) continue;
      seen.add(edge.evidence);
      const item = element('li');
      item.append(
        element('span', 'vault-edge-label', titleCase(edge.type)),
        element('p', undefined, edge.evidence)
      );
      list.append(item);
    }
    evidence.append(list);
    ui.inspectorContent.append(evidence);
  }

  if (related.size > 0) {
    const connections = element('section', 'vault-inspector-section');
    connections.append(element('h3', undefined, 'Connections'));
    const list = element('div', 'vault-connection-list');
    for (const node of [...related.values()].sort((left, right) => left.id.localeCompare(right.id))) {
      const button = element('button', 'vault-connection');
      button.type = 'button';
      button.append(
        element('span', undefined, node.label),
        element('small', undefined, `${node.type} · ${node.status}`)
      );
      button.addEventListener('click', () => onSelect(node.id));
      list.append(button);
    }
    connections.append(list);
    ui.inspectorContent.append(connections);
  }

  const profileNode = selectedNode.profilePath
    ? selectedNode
    : [...related.values()].find((node) => Boolean(node.profilePath));
  const profileHref = routeProfileHref(profileNode?.profilePath);
  if (profileHref) {
    const profile = element('section', 'vault-inspector-section');
    profile.append(element('h3', undefined, 'Route profile'));
    const link = element('a', 'vault-profile-link', 'Open route security profile');
    link.href = profileHref;
    profile.append(link);
    ui.inspectorContent.append(profile);
  }
}

function eventNodeId(
  event: VaultTimelineEvent,
  nodes: VaultNode[]
): string | undefined {
  return nodes.find(
    (node) =>
      node.type === 'finding' &&
      node.runId === event.runId &&
      node.metadata.fingerprint === event.findingFingerprint
  )?.id;
}

export function startVaultGraph(root: HTMLElement, graphInput: VaultGraph): VaultGraphController {
  const graph = vaultGraphSchema.parse(graphInput);
  const ui = buildShell(root, graph);
  const abortController = new AbortController();
  const listenerOptions = { signal: abortController.signal };
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  const render = renderData(graph);
  const renderNodeById = new Map(render.nodes.map((node) => [node.id, node]));
  const objects = new Map<string, THREE.Group>();
  const adjacency = new Map<string, Array<{ id: string; edge: VaultEdge }>>();
  for (const edge of graph.edges) {
    adjacency.set(edge.from, [...(adjacency.get(edge.from) ?? []), { id: edge.to, edge }]);
    adjacency.set(edge.to, [...(adjacency.get(edge.to) ?? []), { id: edge.from, edge }]);
  }
  const runTimestamps = new Map<string, string>();
  for (const event of graph.timeline) {
    const prior = runTimestamps.get(event.runId);
    if (!prior || event.timestamp > prior) runTimestamps.set(event.runId, event.timestamp);
  }
  runTimestamps.set(graph.currentRunId, runTimestamps.get(graph.currentRunId) ?? graph.generatedAt);

  let mode: VaultGraphMode = 'global';
  let depth = 2;
  let selectedNodeId =
    graph.nodes.find((node) => node.status === 'reopened')?.id ??
    graph.nodes.find(
      (node) => node.type === 'finding' && node.runId === graph.currentRunId
    )?.id ??
    graph.nodes.find((node) => node.type === 'finding')?.id;
  let rangeFrom = '';
  let rangeTo = '';
  let severityFilter = 'all';
  let statusFilter = 'all';
  let timelineTimer: number | undefined;
  let timelineIndex = 0;
  let destroyed = false;
  let cameraInteracted = false;
  let engineTick = 0;
  const excludedNodeTypes = new Set<VaultNodeType>();
  const excludedEdgeTypes = new Set<VaultEdgeType>();
  let visibleNodeIds = new Set(graph.nodes.map((node) => node.id));
  let breachNodeIds = new Set<string>();

  const renderer = new ForceGraph3D(ui.scene, {
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
  const nodeIsVisible = (node: RenderNode): boolean => visibleNodeIds.has(node.id);
  const linkIsVisible = (link: RenderLink): boolean => {
    const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
    const targetId = typeof link.target === 'object' ? link.target.id : link.target;
    return (
      visibleNodeIds.has(sourceId) &&
      visibleNodeIds.has(targetId) &&
      !excludedEdgeTypes.has(link.edge.type)
    );
  };
  const linkIsDimmed = (link: RenderLink): boolean =>
    mode === 'breach_path' &&
    (!breachNodeIds.has(link.edge.from) ||
      !breachNodeIds.has(link.edge.to) ||
      !BREACH_PATH_EDGE_TYPES.has(link.edge.type));

  renderer
    .backgroundColor('#030507')
    .showNavInfo(false)
    .nodeId('id')
    .nodeLabel(nodeTooltip)
    .nodeThreeObject(nodeObjectFactory)
    .nodeVisibility(nodeIsVisible)
    .linkVisibility(linkIsVisible)
    .linkColor((link) => (linkIsDimmed(link) ? '#252b33' : edgeColor(link.edge)))
    .linkWidth((link) => (linkIsDimmed(link) ? 0.15 : edgeWidth(link.edge)))
    .linkCurvature((link) => edgeCurvature(link.edge))
    .linkDirectionalParticles((link) =>
      linkIsDimmed(link) ? 0 : edgeParticleCount(link.edge)
    )
    .linkDirectionalParticleColor((link) => edgeColor(link.edge))
    .linkDirectionalParticleWidth((link) => edgeWidth(link.edge) + 0.65)
    .linkDirectionalParticleSpeed((link) => edgeParticleSpeed(link.edge))
    .linkDirectionalArrowLength((link) =>
      !linkIsDimmed(link) && edgeShowsDirection(link.edge) ? 2.8 : 0
    )
    .linkDirectionalArrowColor((link) => edgeColor(link.edge))
    .linkDirectionalArrowRelPos(0.72)
    .warmupTicks(80)
    .cooldownTicks(180)
    .onNodeClick((node) => selectNode(node.id))
    .onEngineTick(() => {
      engineTick += 1;
      if (!cameraInteracted && (engineTick === 1 || engineTick % 20 === 0)) {
        frameVisibleGraph(0);
      }
    })
    .onEngineStop(() => {
      if (!cameraInteracted) frameVisibleGraph(350);
    })
    .graphData(render);

  const bloomPass = new UnrealBloomPass(
    new THREE.Vector2(Math.max(ui.scene.clientWidth, 1), Math.max(ui.scene.clientHeight, 1)),
    0.42,
    0.18,
    0.88
  );
  renderer.postProcessingComposer().addPass(bloomPass);

  function baseNodeIsVisible(node: VaultNode): boolean {
    if (excludedNodeTypes.has(node.type)) return false;
    if (severityFilter !== 'all' && node.severity !== severityFilter) return false;
    if (statusFilter !== 'all' && node.status !== statusFilter) return false;
    if (node.runId) {
      const timestamp = runTimestamps.get(node.runId);
      if (timestamp && rangeFrom && timestamp < rangeFrom) return false;
      if (timestamp && rangeTo && timestamp > rangeTo) return false;
    }
    return true;
  }

  function walkFrom(
    startId: string,
    maximumDepth: number,
    edgeAllowed: (edge: VaultEdge) => boolean
  ): Set<string> {
    const visited = new Set<string>([startId]);
    let frontier = [startId];
    for (let level = 0; level < maximumDepth; level += 1) {
      const next: string[] = [];
      for (const id of frontier) {
        for (const neighbor of adjacency.get(id) ?? []) {
          if (!edgeAllowed(neighbor.edge) || visited.has(neighbor.id)) continue;
          visited.add(neighbor.id);
          next.push(neighbor.id);
        }
      }
      frontier = next;
      if (frontier.length === 0) break;
    }
    return visited;
  }

  function recomputeVisibility(): void {
    const base = new Set(graph.nodes.filter(baseNodeIsVisible).map((node) => node.id));
    if (mode === 'local' && selectedNodeId) {
      const local = walkFrom(
        selectedNodeId,
        depth,
        (edge) => !excludedEdgeTypes.has(edge.type)
      );
      visibleNodeIds = new Set([...base].filter((id) => local.has(id)));
    } else {
      visibleNodeIds = base;
    }

    if (mode === 'breach_path') {
      if (selectedNodeId) {
        breachNodeIds = walkFrom(
          selectedNodeId,
          graph.nodes.length,
          (edge) => BREACH_PATH_EDGE_TYPES.has(edge.type)
        );
      } else {
        breachNodeIds = new Set(
          graph.edges
            .filter((edge) => BREACH_PATH_EDGE_TYPES.has(edge.type))
            .flatMap((edge) => [edge.from, edge.to])
        );
      }
    } else {
      breachNodeIds = new Set();
    }

    for (const [id, object] of objects) {
      updateVaultNodeState(object, {
        selected: id === selectedNodeId,
        dimmed: mode === 'breach_path' && !breachNodeIds.has(id)
      });
    }
    renderer
      .nodeVisibility(nodeIsVisible)
      .linkVisibility(linkIsVisible)
      .linkColor((link) => (linkIsDimmed(link) ? '#252b33' : edgeColor(link.edge)))
      .linkWidth((link) => (linkIsDimmed(link) ? 0.15 : edgeWidth(link.edge)))
      .linkDirectionalParticles((link) =>
        linkIsDimmed(link) ? 0 : edgeParticleCount(link.edge)
      )
      .linkDirectionalArrowLength((link) =>
        !linkIsDimmed(link) && edgeShowsDirection(link.edge) ? 2.8 : 0
      )
      .refresh();
  }

  function focusNode(node: RenderNode): void {
    if (![node.x, node.y, node.z].every((coordinate) => Number.isFinite(coordinate))) return;
    const x = node.x ?? 0;
    const y = node.y ?? 0;
    const z = node.z ?? 0;
    const distance = Math.hypot(x, y, z);
    const ratio = 1 + 78 / Math.max(distance, 1);
    renderer.cameraPosition(
      { x: x * ratio, y: y * ratio, z: z * ratio + (distance < 1 ? 78 : 0) },
      { x, y, z },
      550
    );
  }

  function selectNode(id: string): void {
    const node = nodeById.get(id);
    if (!node) return;
    selectedNodeId = id;
    cameraInteracted = true;
    renderInspector(ui, graph, node, nodeById, selectNode);
    ui.inspector.classList.add('is-open');
    recomputeVisibility();
    const renderNode = renderNodeById.get(id);
    if (renderNode) focusNode(renderNode);
  }

  function setMode(nextMode: VaultGraphMode): void {
    mode = nextMode;
    ui.shell.dataset.mode = mode;
    for (const [buttonMode, button] of Object.entries(ui.modeButtons)) {
      button.setAttribute('aria-pressed', String(buttonMode === mode));
    }
    recomputeVisibility();
  }

  function setDepth(nextDepth: number): void {
    depth = Math.max(1, Math.min(4, Math.round(nextDepth)));
    ui.depthInput.value = String(depth);
    recomputeVisibility();
  }

  function setRunRange(from: string, to: string): void {
    rangeFrom = from;
    rangeTo = to;
    recomputeVisibility();
  }

  function search(query: string): string[] {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return [];
    return graph.nodes
      .filter((node) => {
        const searchable = [
          node.label,
          node.type,
          node.status,
          node.severity,
          node.runId,
          node.route,
          ...Object.entries(node.metadata).flatMap(([key, value]) => [key, value])
        ]
          .filter((value): value is string => Boolean(value))
          .join(' ')
          .toLowerCase();
        return searchable.includes(normalized);
      })
      .sort(
        (left, right) =>
          Number(right.runId === graph.currentRunId) - Number(left.runId === graph.currentRunId) ||
          Number(right.status === 'reopened') - Number(left.status === 'reopened') ||
          left.id.localeCompare(right.id)
      )
      .map((node) => node.id);
  }

  function pauseTimeline(): void {
    if (timelineTimer !== undefined) window.clearInterval(timelineTimer);
    timelineTimer = undefined;
    ui.playButton.setAttribute('aria-pressed', 'false');
    ui.pauseButton.setAttribute('aria-pressed', 'true');
  }

  function selectTimelineEvent(event: VaultTimelineEvent): void {
    const nodeId = eventNodeId(event, graph.nodes);
    if (nodeId) selectNode(nodeId);
    for (const [eventId, button] of ui.timelineEventButtons) {
      button.classList.toggle('is-current', eventId === event.id);
    }
  }

  function playTimeline(): void {
    pauseTimeline();
    ui.playButton.setAttribute('aria-pressed', 'true');
    ui.pauseButton.setAttribute('aria-pressed', 'false');
    if (graph.timeline.length === 0) return;
    if (timelineIndex >= graph.timeline.length) timelineIndex = 0;
    selectTimelineEvent(graph.timeline[timelineIndex]!);
    timelineIndex += 1;
    timelineTimer = window.setInterval(() => {
      const event = graph.timeline[timelineIndex];
      if (!event) {
        pauseTimeline();
        return;
      }
      selectTimelineEvent(event);
      timelineIndex += 1;
    }, 900);
  }

  function fit(): void {
    cameraInteracted = true;
    frameVisibleGraph(450);
  }

  function frameVisibleGraph(duration: number): void {
    const bounds = renderer.getGraphBbox(nodeIsVisible);
    if (!bounds) return;
    const center = {
      x: (bounds.x[0] + bounds.x[1]) / 2,
      y: (bounds.y[0] + bounds.y[1]) / 2,
      z: (bounds.z[0] + bounds.z[1]) / 2
    };
    const width = Math.max(bounds.x[1] - bounds.x[0], 1);
    const height = Math.max(bounds.y[1] - bounds.y[0], 1);
    const depthSpan = Math.max(bounds.z[1] - bounds.z[0], 1);
    const camera = renderer.camera();
    const verticalFov = camera instanceof THREE.PerspectiveCamera
      ? THREE.MathUtils.degToRad(camera.fov)
      : THREE.MathUtils.degToRad(50);
    const aspect = Math.max(ui.scene.clientWidth / Math.max(ui.scene.clientHeight, 1), 1);
    const heightDistance = height / (2 * Math.tan(verticalFov / 2));
    const widthDistance = width / (2 * Math.tan(verticalFov / 2) * aspect);
    const distance = Math.max(heightDistance, widthDistance, depthSpan * 0.9, 42) * 1.15;
    const direction = new THREE.Vector3(0, 0, 1);
    renderer.cameraPosition(
      {
        x: center.x + direction.x * distance,
        y: center.y + direction.y * distance,
        z: center.z + direction.z * distance
      },
      center,
      duration
    );
    ui.scene.dataset.cameraFramed = 'true';
  }

  const resize = (): void => {
    const width = Math.max(ui.scene.clientWidth, 1);
    const height = Math.max(ui.scene.clientHeight, 1);
    renderer.width(width).height(height);
    bloomPass.setSize(width, height);
  };
  resize();
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(ui.scene);
  const initialFitTimer = window.setTimeout(() => {
    if (!cameraInteracted) frameVisibleGraph(450);
  }, 700);

  function toggleFilterPanel(open = Boolean(ui.filterPanel.hidden)): void {
    ui.filterPanel.hidden = !open;
    ui.filterButton.setAttribute('aria-expanded', String(open));
    ui.filterButton.classList.toggle('is-active', open);
  }

  function renderSearchResults(): void {
    const ids = search(ui.searchInput.value).slice(0, 12);
    ui.searchResults.replaceChildren();
    for (const id of ids) {
      const node = nodeById.get(id);
      if (!node) continue;
      const ruleId = node.metadata.ruleId;
      const button = element('button', 'vault-search-result');
      button.type = 'button';
      button.setAttribute('aria-label', `${ruleId ? `${ruleId} — ` : ''}${node.label}`);
      button.append(
        element('span', undefined, ruleId ?? node.type.toUpperCase()),
        element('strong', undefined, node.label),
        element('small', undefined, node.status)
      );
      button.addEventListener(
        'click',
        () => {
          selectNode(node.id);
          ui.searchResults.hidden = true;
        },
        listenerOptions
      );
      ui.searchResults.append(button);
    }
    ui.searchResults.hidden = ids.length === 0;
  }

  ui.modeButtons.global.addEventListener('click', () => setMode('global'), listenerOptions);
  ui.modeButtons.local.addEventListener('click', () => setMode('local'), listenerOptions);
  ui.modeButtons.breach_path.addEventListener(
    'click',
    () => setMode('breach_path'),
    listenerOptions
  );
  ui.searchInput.addEventListener('input', renderSearchResults, listenerOptions);
  ui.toolButtons.search.addEventListener('click', () => ui.searchInput.focus(), listenerOptions);
  ui.filterButton.addEventListener('click', () => toggleFilterPanel(), listenerOptions);
  ui.toolButtons.layers.addEventListener(
    'click',
    () => {
      toggleFilterPanel(true);
      ui.filterPanel.querySelector<HTMLElement>('[data-filter-group="edges"]')?.focus();
    },
    listenerOptions
  );
  ui.toolButtons.settings.addEventListener(
    'click',
    () => {
      toggleFilterPanel(true);
      ui.depthInput.focus();
    },
    listenerOptions
  );
  ui.toolButtons.focus.addEventListener(
    'click',
    () => {
      if (selectedNodeId) selectNode(selectedNodeId);
      else fit();
    },
    listenerOptions
  );
  ui.toolButtons.fit.addEventListener('click', fit, listenerOptions);
  ui.toolButtons.orbit.addEventListener(
    'click',
    () => {
      cameraInteracted = true;
      renderer.cameraPosition({ x: 0, y: 0, z: 220 }, { x: 0, y: 0, z: 0 }, 500);
    },
    listenerOptions
  );
  ui.toolButtons.assets.addEventListener(
    'click',
    () => {
      const input = ui.nodeTypeInputs.get('asset');
      if (!input) return;
      input.checked = !input.checked;
      if (input.checked) excludedNodeTypes.delete('asset');
      else excludedNodeTypes.add('asset');
      recomputeVisibility();
    },
    listenerOptions
  );
  ui.toolButtons.fullscreen.addEventListener(
    'click',
    () => {
      if (document.fullscreenElement) void document.exitFullscreen();
      else void ui.shell.requestFullscreen();
    },
    listenerOptions
  );
  ui.inspectorClose.addEventListener(
    'click',
    () => ui.inspector.classList.remove('is-open'),
    listenerOptions
  );
  ui.playButton.addEventListener('click', playTimeline, listenerOptions);
  ui.pauseButton.addEventListener('click', pauseTimeline, listenerOptions);
  ui.depthInput.addEventListener(
    'input',
    () => setDepth(Number(ui.depthInput.value)),
    listenerOptions
  );
  ui.severitySelect.addEventListener(
    'change',
    () => {
      severityFilter = ui.severitySelect.value;
      recomputeVisibility();
    },
    listenerOptions
  );
  ui.statusSelect.addEventListener(
    'change',
    () => {
      statusFilter = ui.statusSelect.value;
      recomputeVisibility();
    },
    listenerOptions
  );
  const updateRange = (): void => {
    setRunRange(
      ui.fromInput.value ? `${ui.fromInput.value}T00:00:00.000Z` : '',
      ui.toInput.value ? `${ui.toInput.value}T23:59:59.999Z` : ''
    );
  };
  ui.fromInput.addEventListener('change', updateRange, listenerOptions);
  ui.toInput.addEventListener('change', updateRange, listenerOptions);
  for (const [type, input] of ui.nodeTypeInputs) {
    input.addEventListener(
      'change',
      () => {
        if (input.checked) excludedNodeTypes.delete(type);
        else excludedNodeTypes.add(type);
        recomputeVisibility();
      },
      listenerOptions
    );
  }
  for (const [type, input] of ui.edgeTypeInputs) {
    input.addEventListener(
      'change',
      () => {
        if (input.checked) excludedEdgeTypes.delete(type);
        else excludedEdgeTypes.add(type);
        recomputeVisibility();
      },
      listenerOptions
    );
  }
  for (const event of graph.timeline) {
    ui.timelineEventButtons.get(event.id)?.addEventListener(
      'click',
      () => selectTimelineEvent(event),
      listenerOptions
    );
  }
  document.addEventListener(
    'pointerdown',
    (event) => {
      if (!(event.target instanceof Node)) return;
      if (!ui.searchResults.hidden && !ui.searchResults.parentElement?.contains(event.target)) {
        ui.searchResults.hidden = true;
      }
    },
    listenerOptions
  );

  setMode('global');
  renderInspector(ui, graph, selectedNodeId ? nodeById.get(selectedNodeId) : undefined, nodeById, selectNode);

  return {
    selectNode,
    setMode,
    setDepth,
    setRunRange,
    search,
    playTimeline,
    pauseTimeline,
    fit,
    destroy(): void {
      if (destroyed) return;
      destroyed = true;
      pauseTimeline();
      window.clearTimeout(initialFitTimer);
      abortController.abort();
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

  let graph: VaultGraph;
  try {
    graph = vaultGraphSchema.parse(JSON.parse(payload.textContent) as unknown);
  } catch (error) {
    root.dataset.vaultBootError = 'true';
    root.textContent = error instanceof Error
      ? `Unable to open BreachProof Vault: ${error.message}`
      : 'Unable to open BreachProof Vault.';
    return;
  }

  try {
    startVaultGraph(root, graph);
  } catch (error) {
    renderVaultFallback(
      root,
      graph,
      error instanceof Error
        ? `3D renderer unavailable: ${error.message}`
        : 'Interactive 3D rendering is unavailable in this browser.'
    );
  }
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootEmbeddedVault, { once: true });
  } else {
    bootEmbeddedVault();
  }
}
