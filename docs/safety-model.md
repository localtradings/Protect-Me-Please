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
