# AGENTS.md

This repository contains the **Keychain & Security Expert Skill** — a non-opinionated, correctness-focused reference for iOS/macOS keychain operations, biometric authentication, CryptoKit cryptography, credential lifecycle management, certificate trust, and OWASP compliance mapping.

## Repo Structure

```
AGENTS.md                              ← you are here (repo-level agent onboarding)
CLAUDE.md -> AGENTS.md                ← symlink for Claude Code compatibility
README.md                              ← human-facing documentation
LICENSE
.claude-plugin/
  plugin.json                          ← Claude Code plugin manifest
  marketplace.json                     ← Claude Code marketplace catalog
swift-security-expert/
  SKILL.md                             ← the skill: router, guidelines, behavioral rules
  references/
    keychain-fundamentals.md           ← SecItem* CRUD, query dictionaries, OSStatus
    keychain-item-classes.md           ← kSecClass types, composite primary keys
    keychain-access-control.md         ← accessibility constants, SecAccessControl
    biometric-authentication.md        ← keychain-bound biometrics, LAContext bypass
    secure-enclave.md                  ← hardware-backed P256, simulator traps
    cryptokit-symmetric.md             ← SHA-2/3, HMAC, AES-GCM, ChaChaPoly, HKDF
    cryptokit-public-key.md            ← ECDSA, ECDH, HPKE, ML-KEM/ML-DSA
    credential-storage-patterns.md     ← OAuth tokens, API keys, refresh rotation
    keychain-sharing.md                ← access groups, Team ID, extensions
    certificate-trust.md               ← SecTrust, SPKI pinning, mTLS
    migration-legacy-stores.md         ← UserDefaults/plist → Keychain migration
    common-anti-patterns.md            ← top 10 AI-generated security mistakes
    testing-security-code.md           ← protocol mocks, CI/CD, Swift Testing
    compliance-owasp-mapping.md        ← OWASP Mobile Top 10, MASVS, MASTG
```

## How to Use This Skill

1. **Start with `SKILL.md`** — it contains the decision tree router (review / improve / implement), core guidelines, quick reference tables, behavioral rules, and the references index.
2. **Load reference files on demand** — `SKILL.md` tells you which files to load for each query type. Do not load all 14 at once.
3. **Follow the behavioral rules in `SKILL.md`** — tone calibration, output format, common AI mistakes watchlist, and scope boundaries are all defined there.

## Contribution Format

When adding or editing reference files:

- Every reference file must have an H1 title, a scope blockquote, and a `## Summary Checklist` at the bottom
- Code examples use ✅ (correct) and ❌ (incorrect) markers — always provide both for security patterns
- Cite iOS version requirements for every API (`iOS 13+`, `iOS 17+`, `iOS 26+`)
- Cross-references use backtick-quoted filenames: `keychain-fundamentals.md`
- One canonical source per pattern — other files get a one-sentence summary + cross-reference link

## Testing

See `testing-security-code.md` for protocol-based mocking patterns. Key constraints:

- **Simulator:** No Secure Enclave, limited keychain behavior, no biometric prompts
- **CI runners:** Require `security create-keychain` before `SecItem*` calls work
- **Device:** Required for integration tests touching real keychain, SE, or biometrics

## Scope Boundaries

**In scope:** Client-side Apple platform security — Keychain Services, CryptoKit, Secure Enclave, LAContext + keychain binding, certificate trust, OWASP mobile compliance.

**Out of scope:** App Transport Security, CloudKit encryption, server-side auth, WebAuthn relying party, code signing, jailbreak detection, third-party crypto libraries (OpenSSL, LibSodium).

See `SKILL.md` for the full exclusion table with redirect suggestions.
