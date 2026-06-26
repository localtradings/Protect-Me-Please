# Safety Model

BreachProof is local-first and defensive.

Allowed by default:

- reading local repository files
- parsing manifests, schemas, routes, Docker Compose, and GitHub Actions
- writing local reports
- writing local SQLite state
- writing redacted audit logs
- producing fix suggestions

Refused or manual review by default:

- public-target testing
- data dumping
- credential access
- destructive database actions
- payment or billing actions
- production mutations
- exploit payloads that can corrupt, steal, or delete data

Staging validation is limited to exact allowlisted targets from `breachproof.scope.yml`.
