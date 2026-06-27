# Security Policy

BreachProof is a defensive breach-path proof and fix verification tool for systems you own or are explicitly authorized to test.

## Authorized Use Only

Do not use this project against public targets, third-party systems, accounts, networks, APIs, or applications unless you have explicit written authorization. The tool is designed for local repositories, local services, local containers, CI environments, and allowlisted staging targets.

## Safety Defaults

- One-time project approval is required before scoped workflows run.
- Approval is stored locally with timestamp, workspace, mode, and scope hash.
- Actions outside approved scope are refused.
- A local audit log records actions.
- Source code is not uploaded by default.
- Logs and reports redact common secret patterns.
- Validation must use fake/local/staging-safe data.
- Unsafe exploitation is marked for manual review.
- The project does not include weaponized exploit payloads by default.
- Proof Mode writes replayable evidence with fake users, fake tenants, fake records, and local-only request sequences.
- Patch tournaments generate patch artifacts only. They do not edit the analyzed repository unless a future explicit apply flow is approved and enabled.
- AI-agent checks are policy-based and do not include jailbreak payload libraries or destructive tool execution.

## Reporting Vulnerabilities In This Repository

If you find a vulnerability in BreachProof itself, please open a private security advisory on GitHub or contact the maintainers with:

- affected version or commit
- reproduction steps
- impact
- suggested fix if available

Please do not publicly disclose a vulnerability until maintainers have had a reasonable opportunity to investigate and release a fix.

## Not A Guarantee

BreachProof reduces realistic breach paths by mapping, validating, fixing, and verifying weaknesses in authorized environments. It does not guarantee that any application is secure or unhackable.
