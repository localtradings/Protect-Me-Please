# `/breachproof`

Use the local BreachProof CLI for the current authorized repository.

- If local scope approval is missing, ask the user to confirm ownership or explicit testing authorization. Do not invent approval.
- Run `npm run build` when the local CLI has not been built, then execute `node dist/cli/index.js --yes` from the repository being analyzed.
- Use `--open` only when requested. Use `--no-verify` only when project checks are intentionally excluded.
- BreachProof may generate reports, patches, regression-test proposals, verification logs, and local Vault state. It must not rewrite analyzed source automatically.
- Never push, access remote databases, use billing/payment pages, or enable paid services.
- Return the CLI's actual exit status and output paths. A failed project check is not a verified security fix; its reports and logs remain useful.
