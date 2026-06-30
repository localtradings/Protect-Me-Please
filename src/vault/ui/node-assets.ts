/// <reference lib="dom" />

import * as THREE from 'three';
import type { VaultNode } from '../types.js';
import { nodeVisualStyle } from './graph-style.js';

export type VaultGlyph =
  | 'route'
  | 'alert'
  | 'shield'
  | 'check'
  | 'link'
  | 'test'
  | 'asset'
  | 'run';

interface MaterialState {
  material: THREE.Material;
  opacity: number;
  emissiveIntensity?: number;
}

interface NodeObjectState {
  materials: MaterialState[];
  baseScale: number;
}

const STATE_KEY = 'breachproofVaultNodeState';

function strokeGlyph(
  context: CanvasRenderingContext2D,
  glyph: VaultGlyph,
  size: number
): void {
  const center = size / 2;
  const radius = size * 0.25;
  context.beginPath();

  switch (glyph) {
    case 'route':
      context.moveTo(center, center - radius);
      context.lineTo(center + radius, center + radius * 0.82);
      context.lineTo(center - radius, center + radius * 0.82);
      context.closePath();
      context.moveTo(center, center - radius * 0.45);
      context.lineTo(center, center + radius * 0.34);
      break;
    case 'alert':
      for (let index = 0; index < 6; index += 1) {
        const angle = Math.PI / 3 * index - Math.PI / 6;
        const x = center + Math.cos(angle) * radius;
        const y = center + Math.sin(angle) * radius;
        if (index === 0) context.moveTo(x, y);
        else context.lineTo(x, y);
      }
      context.closePath();
      context.moveTo(center, center - radius * 0.5);
      context.lineTo(center, center + radius * 0.18);
      context.moveTo(center, center + radius * 0.55);
      context.lineTo(center, center + radius * 0.6);
      break;
    case 'shield':
      context.moveTo(center, center - radius);
      context.lineTo(center + radius * 0.82, center - radius * 0.52);
      context.lineTo(center + radius * 0.65, center + radius * 0.42);
      context.lineTo(center, center + radius);
      context.lineTo(center - radius * 0.65, center + radius * 0.42);
      context.lineTo(center - radius * 0.82, center - radius * 0.52);
      context.closePath();
      break;
    case 'check':
    case 'test':
      context.moveTo(center - radius * 0.72, center);
      context.lineTo(center - radius * 0.16, center + radius * 0.55);
      context.lineTo(center + radius * 0.8, center - radius * 0.62);
      if (glyph === 'test') {
        context.moveTo(center - radius, center + radius);
        context.lineTo(center + radius, center + radius);
      }
      break;
    case 'link':
      context.ellipse(
        center - radius * 0.44,
        center,
        radius * 0.65,
        radius * 0.38,
        -0.55,
        0,
        Math.PI * 2
      );
      context.moveTo(center + radius * 0.21, center - radius * 0.2);
      context.ellipse(
        center + radius * 0.44,
        center,
        radius * 0.65,
        radius * 0.38,
        -0.55,
        0,
        Math.PI * 2
      );
      break;
    case 'asset':
      context.ellipse(center, center - radius * 0.65, radius, radius * 0.36, 0, 0, Math.PI * 2);
      context.moveTo(center - radius, center - radius * 0.65);
      context.lineTo(center - radius, center + radius * 0.65);
      context.ellipse(center, center + radius * 0.65, radius, radius * 0.36, 0, Math.PI, 0, true);
      context.lineTo(center + radius, center - radius * 0.65);
      context.moveTo(center - radius, center);
      context.ellipse(center, center, radius, radius * 0.36, 0, Math.PI, 0, true);
      break;
    case 'run':
      context.rect(center - radius, center - radius, radius * 2, radius * 2);
      context.moveTo(center, center - radius);
      context.lineTo(center, center + radius);
      context.moveTo(center - radius, center);
      context.lineTo(center + radius, center);
      break;
  }

  context.stroke();
}

export function createGlyphTexture(glyph: VaultGlyph, color: string): THREE.CanvasTexture {
  const size = 128;
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  const context = canvas.getContext('2d');
  if (!context) throw new Error('Canvas 2D is unavailable for Vault glyph generation.');

  context.clearRect(0, 0, size, size);
  context.strokeStyle = color;
  context.lineWidth = 8;
  context.lineCap = 'round';
  context.lineJoin = 'round';
  context.shadowColor = color;
  context.shadowBlur = 12;
  strokeGlyph(context, glyph, size);

  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.minFilter = THREE.LinearFilter;
  texture.magFilter = THREE.LinearFilter;
  texture.generateMipmaps = false;
  return texture;
}

function beveledShapeGeometry(points: Array<[number, number]>, depth: number): THREE.ExtrudeGeometry {
  const shape = new THREE.Shape();
  const [first, ...rest] = points;
  if (!first) throw new Error('A Vault procedural shape requires at least one point.');
  shape.moveTo(first[0], first[1]);
  for (const [x, y] of rest) shape.lineTo(x, y);
  shape.closePath();
  const geometry = new THREE.ExtrudeGeometry(shape, {
    depth,
    bevelEnabled: true,
    bevelSegments: 2,
    bevelSize: 0.08,
    bevelThickness: 0.08,
    curveSegments: 2
  });
  geometry.center();
  return geometry;
}

function geometryFor(node: VaultNode): { geometry: THREE.BufferGeometry; glyph: VaultGlyph } {
  switch (node.type) {
    case 'route': {
      const geometry = new THREE.CylinderGeometry(0.78, 0.78, 0.62, 3, 1, false);
      geometry.rotateX(Math.PI / 2);
      return { geometry, glyph: 'route' };
    }
    case 'finding': {
      const geometry = new THREE.CylinderGeometry(0.82, 0.82, 0.55, 6, 1, false);
      geometry.rotateX(Math.PI / 2);
      return { geometry, glyph: 'alert' };
    }
    case 'invariant':
      return {
        geometry: beveledShapeGeometry(
          [[0, 0.92], [0.78, 0.5], [0.65, -0.4], [0, -0.98], [-0.65, -0.4], [-0.78, 0.5]],
          0.35
        ),
        glyph: 'shield'
      };
    case 'patch':
      return {
        geometry: beveledShapeGeometry(
          [[-0.66, -0.66], [0.66, -0.66], [0.66, 0.66], [-0.66, 0.66]],
          0.55
        ),
        glyph: 'check'
      };
    case 'replay':
      return { geometry: new THREE.BoxGeometry(1.08, 1.08, 1.08), glyph: 'link' };
    case 'test':
      return { geometry: new THREE.BoxGeometry(1, 1, 1), glyph: 'test' };
    case 'asset': {
      const geometry = new THREE.CylinderGeometry(0.92, 0.92, 0.45, 6, 1, true);
      geometry.rotateX(Math.PI / 2);
      return { geometry, glyph: 'asset' };
    }
    case 'run':
      return { geometry: new THREE.BoxGeometry(0.95, 0.95, 0.95), glyph: 'run' };
  }
}

function glyphDepthFor(node: VaultNode): number {
  switch (node.type) {
    case 'replay':
      return 0.59;
    case 'test':
      return 0.55;
    case 'run':
      return 0.53;
    case 'asset':
      return 0.32;
    default:
      return 0.46;
  }
}

function registerMaterial(group: THREE.Group, material: THREE.Material): void {
  const state = group.userData[STATE_KEY] as NodeObjectState;
  const standard = material instanceof THREE.MeshStandardMaterial ? material : undefined;
  state.materials.push({
    material,
    opacity: material.opacity,
    emissiveIntensity: standard?.emissiveIntensity
  });
}

function addGlyph(group: THREE.Group, glyph: VaultGlyph, color: string, z: number): void {
  const texture = createGlyphTexture(glyph, color);
  const material = new THREE.MeshBasicMaterial({
    map: texture,
    transparent: true,
    depthWrite: false,
    opacity: 0.95,
    side: THREE.DoubleSide,
    toneMapped: false
  });
  const sprite = new THREE.Mesh(new THREE.PlaneGeometry(1.05, 1.05), material);
  sprite.position.z = z;
  sprite.userData.vaultGlyph = true;
  group.add(sprite);
  registerMaterial(group, material);
}

export function createVaultNodeObject(node: VaultNode): THREE.Group {
  const style = nodeVisualStyle(node.type);
  const { geometry, glyph } = geometryFor(node);
  const group = new THREE.Group();
  group.name = `vault-node:${node.id}`;
  group.userData[STATE_KEY] = { materials: [], baseScale: style.scale } satisfies NodeObjectState;
  group.scale.setScalar(style.scale);

  const bodyMaterial = new THREE.MeshStandardMaterial({
    color: style.color,
    emissive: style.emissive,
    emissiveIntensity: 0.42,
    metalness: 0.46,
    roughness: 0.34,
    transparent: true,
    opacity: node.status === 'not_observed'
      ? 0.28
      : node.type === 'route'
        ? 0.2
        : node.type === 'asset'
          ? 0.14
          : 0.86,
    flatShading: true
  });
  const body = new THREE.Mesh(geometry, bodyMaterial);
  group.add(body);
  registerMaterial(group, bodyMaterial);

  const edgeMaterial = new THREE.LineBasicMaterial({
    color: style.color,
    transparent: true,
    opacity: 0.92,
    toneMapped: false
  });
  const outline = new THREE.LineSegments(new THREE.EdgesGeometry(geometry, 18), edgeMaterial);
  outline.scale.setScalar(1.015);
  group.add(outline);
  registerMaterial(group, edgeMaterial);

  if (node.type === 'replay') {
    const ringMaterial = new THREE.MeshStandardMaterial({
      color: style.color,
      emissive: style.emissive,
      emissiveIntensity: 0.7,
      metalness: 0.35,
      roughness: 0.28,
      transparent: true,
      opacity: 0.88
    });
    const ring = new THREE.Mesh(new THREE.TorusGeometry(0.85, 0.08, 8, 32), ringMaterial);
    ring.rotation.set(0.55, 0.35, 0);
    group.add(ring);
    registerMaterial(group, ringMaterial);
  }

  addGlyph(group, glyph, style.color, glyphDepthFor(node));
  return group;
}

export function updateVaultNodeState(
  object: THREE.Group,
  state: { selected: boolean; dimmed: boolean }
): void {
  const nodeState = object.userData[STATE_KEY] as NodeObjectState | undefined;
  if (!nodeState) return;

  const scale = nodeState.baseScale * (state.selected ? 1.18 : 1);
  object.scale.setScalar(scale);
  for (const item of nodeState.materials) {
    item.material.transparent = true;
    item.material.opacity = state.dimmed ? Math.min(item.opacity, 0.16) : item.opacity;
    if (item.material instanceof THREE.MeshStandardMaterial) {
      item.material.emissiveIntensity = state.selected
        ? Math.max(item.emissiveIntensity ?? 0, 1.35)
        : (item.emissiveIntensity ?? 0);
    }
    item.material.needsUpdate = true;
  }
}
