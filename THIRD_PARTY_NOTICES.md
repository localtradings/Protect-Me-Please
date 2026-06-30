# Third-Party Notices

The BreachProof Vault browser bundle and its test pipeline use the following third-party packages. Versions are the resolved versions in `package-lock.json` for this repository.

| Package | Resolved version | Repository | License | Role |
| --- | --- | --- | --- | --- |
| `three` | 0.185.0 | [mrdoob/three.js](https://github.com/mrdoob/three.js) | MIT | WebGL scene, geometry, materials, sprites, and post-processing |
| `3d-force-graph` | 1.80.0 | [vasturiano/3d-force-graph](https://github.com/vasturiano/3d-force-graph) | MIT | Interactive Three.js force-directed graph renderer |
| `d3-force-3d` | 3.0.6 | [vasturiano/d3-force-3d](https://github.com/vasturiano/d3-force-3d) | MIT | Transitive three-dimensional force simulation used by `3d-force-graph` |
| `lucide` | 1.21.0 | [lucide-icons/lucide](https://github.com/lucide-icons/lucide/tree/main/packages/lucide) | ISC | Accessible interface control icons |
| `esbuild` | 0.28.1 | [evanw/esbuild](https://github.com/evanw/esbuild) | MIT | Offline Vault JavaScript bundle generation |
| `@playwright/test` | 1.61.1 | [microsoft/playwright](https://github.com/microsoft/playwright) | Apache-2.0 | Desktop, mobile, interaction, and WebGL-fallback browser verification |

The Vault's visual meshes, node geometry, canvas sprites, materials, and composition are first-party procedural assets implemented in this repository. No stock 3D models or remote visual assets are bundled.

The authoritative license text and copyright notices for each dependency remain in that dependency's distributed package and linked repository.
