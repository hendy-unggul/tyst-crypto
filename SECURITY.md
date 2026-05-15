# Security Policy — tyst-crypto

## Scope

This policy covers the `tyst-crypto` library and its use in the TYST application at `tyst.site`.

**In scope:**
- Cryptographic implementation in `crypto.js`
- Protocol design (key exchange, encryption, padding)
- Test vector correctness in `crypto.test.js`

**Out of scope:**
- Social engineering attacks
- Physical device access
- Third-party infrastructure (Hetzner, Cloudflare)
- Attacks that require compromising the recipient's device

## Reporting

| Severity | Channel | Response |
|---|---|---|
| Critical | security@tyst.site | 48 hours |
| High | security@tyst.site | 48 hours |
| Medium/Low | GitHub issue | 7 days |

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

## Recognition

We do not offer monetary bounties at this stage.

Confirmed, responsibly disclosed vulnerabilities will be credited at `tyst.site/security/hall-of-fame` with your chosen handle (anonymous credit available on request).

## Disclosure Policy

- We ask for 7 days to patch critical vulnerabilities before public disclosure
- We will never ask you to stay silent indefinitely
- We will credit you publicly unless you prefer anonymity
