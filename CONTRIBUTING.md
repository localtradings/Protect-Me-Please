# Contributing

Thanks for helping build BreachProof.

## Development

```sh
npm install
npm test
npm run typecheck
npm run lint
npm run build
```

## Expectations

- Keep the tool defensive and owner-authorized.
- Do not add destructive exploit payloads.
- Do not add billing, payment, subscription, or paid API activation flows.
- Do not upload source code by default.
- Add tests for new analyzers, validators, report formats, and CLI behavior.
- Prefer deterministic local behavior before optional LLM integrations.
- Redact secrets in logs and reports.

## Pull Requests

Good pull requests include:

- clear problem statement
- focused implementation
- tests and fixtures
- documentation update when behavior changes
- safety impact notes for validators or fixers

## Plugin Contributions

Plugin manifests must declare permissions, inputs, outputs, supported frameworks, and entrypoint. Plugins that touch network, staging targets, files, or fix generation must document their safety boundaries.
