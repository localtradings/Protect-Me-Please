# Safety Model

BreachProof is local-first and defensive.

Allowed by default:

- reading local repository files
- parsing manifests, schemas, routes, Docker Compose, and GitHub Actions
- writing local reports
- writing local SQLite state
- writing redacted audit logs
- producing fix suggestions
- generating fake local cyber range data
- generating replayable evidence artifacts
- generating patch tournament artifacts without applying them
- appending local Vault security-memory events
- rebuilding offline Vault reports from existing local artifacts

Refused or manual review by default:

- public-target testing
- data dumping
- credential access
- destructive database actions
- payment or billing actions
- production mutations
- exploit payloads that can corrupt, steal, or delete data

Staging validation is limited to exact allowlisted targets from `breachproof.scope.yml`.

Proof evidence must stay local-first. Evidence folders may include HAR-shaped request sequences, regression test templates, and replay scripts, but they must not include production records, secrets, credential dumps, destructive payloads, or public-target automation.

## Vault Safety Boundaries

- Vault state is stored only in the workspace's `.breachproof/state.sqlite` database.
- Vault event writes are append-only insert-or-ignore operations. Report rebuilds do not add or change run history.
- Vault never disables RLS, uses a service role key, connects to Supabase, or modifies a remote database.
- Vault does not apply generated patches automatically. The default workflow continues to write patch artifacts only.
- The browser report performs no remote fetches. Its content security policy blocks network connections, frames, forms, remote fonts, and remote media.
- Embedded graph JSON is schema-validated and escaped before it is placed in HTML. Workspace paths and note content pass through Vault redaction helpers.
- When WebGL is disabled or unavailable, an accessible table and timeline preserve the evidence without weakening security claims.
- Generated `.breachproof/vault/` and `reports/vault/` output stays ignored locally. CI may retain `reports/vault/` only inside the repository workflow's private artifact.
