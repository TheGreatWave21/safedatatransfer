# Security policy

`sdt` encrypts, verifies and wipes data, so security bugs matter here. Thank you for reporting them.

## Reporting a vulnerability

**Please don't open a public issue for security problems.**

Report privately on GitHub instead:
**[Security → Report a vulnerability](https://github.com/TheGreatWave21/safedatatransfer/security/advisories/new)**.
Only the maintainer can see the report.

Please include:
- what is affected (vault encryption, wipe, local drop, …) and the version (`sdt --version`);
- steps to reproduce, or a proof of concept;
- what an attacker could do with it.

You can expect a first reply within about a week. Once a fix is released, the issue is
published as a GitHub security advisory, and you're credited if you want to be.

## Supported versions

Only the newest release gets security fixes.

## In scope

- Vault encryption, key derivation, or manifest handling that leaks or corrupts data.
- A wipe that deletes anything outside the selected stick, or wipes before verification.
- Local drop: bypassing the code check, decrypting traffic, writing files outside the destination folder, or receiving files without approval.
- Supply chain: the build or release workflows.

## Out of scope

- Data left in flash-memory spare blocks after a wipe. This is a known hardware limitation, explained in [Limitation of wiping](README.md#limitation-of-wiping).
- Attacks that need admin rights or malware already running on the same PC.
