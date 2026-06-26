import { pluginManifestSchema, type PluginManifest } from '../core/types.js';

export function parsePluginManifest(value: unknown): PluginManifest {
  return pluginManifestSchema.parse(value);
}
