# Security Policy

## Supported Versions

`rusty-gasket` is pre-1.0. Security fixes are applied to the most
recent minor release line; users on older 0.x lines are expected to
upgrade.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in any
`rusty-gasket-*` crate, **please do not file a public issue**. Instead:

1. Email the maintainers at **opensource@godaddy.com** with the
   subject line `rusty-gasket security`.
2. Include a description of the vulnerability, the crate and version
   affected, a reproduction (proof-of-concept or steps), and any
   relevant logs.
3. We aim to acknowledge receipt within 3 business days and to ship
   a patched release within 30 days of confirmation.

We will credit you in the release notes unless you prefer anonymity.

## Out of Scope

- Issues that require an attacker to already have arbitrary code
  execution on the host (we already lost).
- Misconfigurations of consumer apps that are not the framework's
  responsibility (e.g., a JWKS endpoint pointed at an attacker-
  controlled URL).
- Denial-of-service via resource exhaustion that is bounded by an
  operator-configurable limit (we ship sensible defaults and document
  them; tuning is the operator's job).
