# `/breachproof`

Run BreachProof's local, generated-artifact-only security workflow against the current repository.

1. Confirm that the user owns or is explicitly authorized to test the repository. If approval is absent, ask before continuing; for a noninteractive authorized run, use `--yes` only after that confirmation.
2. Build the local CLI when needed with `npm run build`.
3. Run `node dist/cli/index.js --yes` from the target repository. Add `--no-verify` only when the user explicitly wants project checks skipped. Add `--open` only when the user asks to open the offline Vault.
4. Never edit analyzed source automatically, push commits, access remote databases, activate paid services, or open billing/payment pages.
5. Report the actual paths printed by the CLI, including:
   - `reports/final-report.md`
   - `reports/final-report.html`
   - `reports/final-report.json`
   - `reports/final-report.sarif`
   - `reports/automation-summary.json`
   - `reports/vault/index.html`
6. If a project check fails, preserve the generated reports and state that BreachProof exited nonzero. Reference its log under `reports/verification/`.
