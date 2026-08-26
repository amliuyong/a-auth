# Security Policy

## Supported Version

Security fixes are developed against the latest commit on `main`.

## Reporting a Vulnerability

Please use GitHub's private vulnerability reporting feature from the
repository's **Security** tab. Do not open a public issue for an unpatched
vulnerability or include credentials, tokens, personal data, account
identifiers, or production-environment details in a public report.

Include:

- the affected component and version or commit;
- reproduction steps or a minimal proof of concept;
- the expected and observed security boundary;
- any suggested mitigation, if available.

Reports will be acknowledged after triage. Disclosure timing will be
coordinated with the reporter after a fix or mitigation is available.

## Secrets

Never commit real credentials or deployment identifiers. Use placeholders in
examples and store deployment secrets in AWS Secrets Manager, SSM Parameter
Store, or KMS-backed configuration.
