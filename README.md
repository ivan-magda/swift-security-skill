# Keychain & Security Expert Skill

[![License](https://img.shields.io/github/license/ivan-magda/swift-security-skill)](LICENSE)

Expert guidance for any AI coding tool that supports the [Agent Skills open format](https://agentskills.io/home) — Apple Keychain Services, biometric authentication, CryptoKit cryptography, credential lifecycle management, certificate trust, and OWASP compliance mapping for iOS/macOS (iOS 13–26+).

This repository distills verified Apple platform security practices into actionable, correctness-focused references for AI agents and code review workflows. Every code pattern is grounded in Apple documentation, DTS engineer guidance (Quinn "The Eskimo!"), WWDC sessions, and OWASP MASTG.

## Who This Is For

- Teams writing or reviewing keychain and security code who want correct defaults — not dangerous AI-generated patterns
- Developers implementing biometric authentication, token storage, or cryptographic operations
- Anyone migrating from `UserDefaults`/`NSCoding` secrets to proper Keychain storage
- Security auditors mapping iOS implementations to OWASP Mobile Top 10 / MASVS

## Why This Skill Exists

AI coding assistants routinely generate **dangerous security code**. This skill exists to catch and correct these patterns before they ship.

## How to Use This Skill

### Option A: Using skills.sh (Recommended)

```bash
npx skills add https://github.com/ivan-magda/swift-security-skill --skill swift-security-expert
```

Then use it in your AI agent:

> Use the swift security expert skill and review the current security code for authentication bypasses, credential storage issues, and cryptographic correctness.

### Option B: Claude Code Plugin

#### Personal Usage

```bash
/plugin marketplace add ivan-magda/swift-security-skill
/plugin install swift-security-expert@swift-security-skill
```

#### Project Configuration

To automatically provide this skill to everyone working in a repository, configure `.claude/settings.json`:

```json
{
  "enabledPlugins": {
    "swift-security-expert@swift-security-skill": true
  },
  "extraKnownMarketplaces": {
    "swift-security-skill": {
      "source": {
        "source": "github",
        "repo": "ivan-magda/swift-security-skill"
      }
    }
  }
}
```

### Option C: Claude Projects

Upload the `swift-security-expert/` folder contents to a Claude Project's knowledge base. Include `SKILL.md` and all files from `references/`.

### Option D: Manual Install

1. Clone this repository
2. Install or symlink the `swift-security-expert/` folder following your tool's skill installation docs
3. Ask your AI tool to use the "swift security expert" skill for security tasks

#### Where to Save Skills

- **Codex:** [Where to save skills](https://developers.openai.com/codex/skills/#where-to-save-skills)
- **Claude:** [Using Skills](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview#using-skills)
- **Cursor:** [Enabling Skills](https://cursor.com/docs/context/skills#enabling-skills)

**How to verify:** Your agent should reference the decision tree in `SKILL.md` and load the relevant reference file(s) for your task.

## What This Skill Offers

### Catch Dangerous AI-Generated Patterns

- Detect `LAContext.evaluatePolicy()` used alone as an authentication gate (bypassable via Frida/objection)
- Flag secrets stored in `UserDefaults`, property lists, or hardcoded in source
- Identify ignored `OSStatus` errors that silently fail keychain operations
- Catch wrong `kSecAttrAccessible` values that expose data at rest

### Guide Security Decisions

- Choose between `.biometryCurrentSet`, `.biometryAny`, and `.userPresence` for biometric gating
- Select the correct `kSecAttrAccessible` level for background vs foreground access
- Pick AES-GCM vs ChaChaPoly, P256 vs Curve25519, and when to use post-quantum algorithms (iOS 26+)
- Decide between Keychain Sharing entitlements vs App Groups for cross-app credential sharing

### Write Correct Security Code

- Hardware-bound biometric authentication via `SecAccessControl` + Keychain (not `LAContext` alone)
- Proper `SecItemAdd` / `SecItemCopyMatching` with add-or-update patterns and `errSecDuplicateItem` handling
- Secure Enclave key generation with correct availability checks (not the simulator trap)
- OAuth token lifecycle with refresh rotation and secure keychain storage

### Support Compliance Workflows

- Map implementations directly to OWASP Mobile Top 10 (2024) categories
- Verify alignment with MASVS controls and MASTG test cases
- Generate audit-ready compliance documentation

## Coverage

| #   | Domain                      | Risk         | Key APIs                                                                                                             |
| --- | --------------------------- | ------------ | -------------------------------------------------------------------------------------------------------------------- |
| 1   | Keychain Fundamentals       | **CRITICAL** | `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete`, `OSStatus`                                    |
| 2   | Keychain Item Classes       | HIGH         | `kSecClassGenericPassword`, `kSecClassInternetPassword`, `kSecClassKey`, `kSecClassCertificate`, `kSecClassIdentity` |
| 3   | Keychain Access Control     | **CRITICAL** | `kSecAttrAccessible*` (7 levels), `SecAccessControlCreateWithFlags`, `NSFileProtection`                              |
| 4   | Biometric Authentication    | **CRITICAL** | `LAContext`, `evaluatePolicy`, `SecAccessControlCreateWithFlags`, `.biometryCurrentSet`, `.biometryAny`              |
| 5   | Secure Enclave              | HIGH         | `SecureEnclave.P256.Signing.PrivateKey`, `SecureEnclave.isAvailable`, `kSecAttrTokenIDSecureEnclave`                 |
| 6   | CryptoKit — Symmetric       | HIGH         | `SHA256`–`SHA3_256`, `HMAC`, `AES.GCM`, `ChaChaPoly`, `SymmetricKey`                                                 |
| 7   | CryptoKit — Public Key      | HIGH         | `P256`, `P384`, `Curve25519`, `HKDF`, `HPKE` (iOS 17+), `MLKEM768`, `MLDSA65` (iOS 26+)                              |
| 8   | Credential Storage Patterns | **CRITICAL** | `ASWebAuthenticationSession`, keychain token patterns, `kSecAttrSynchronizable`                                      |
| 9   | Keychain Sharing            | MEDIUM       | `kSecAttrAccessGroup`, `keychain-access-groups`, App Groups entitlement                                              |
| 10  | Certificate Trust           | HIGH         | `SecCertificate`, `SecTrust`, `SecTrustEvaluateAsyncWithError`, `SecIdentity`                                        |
| 11  | Migration — Legacy Stores   | MEDIUM       | `UserDefaults.removeObject`, `FileManager.removeItem`, first-launch flag pattern                                     |
| 12  | Common Anti-Patterns        | **CRITICAL** | All anti-pattern APIs with correct/incorrect corrections                                                             |
| 13  | Testing Security Code       | MEDIUM       | `XCTest`, protocol-based keychain mocks, `Swift Testing`, CI/CD strategies                                           |
| 14  | Compliance & OWASP Mapping  | MEDIUM       | OWASP M1, M3, M9, M10; MASVS controls; MASTG test cases                                                              |

### Risk Level Legend

- **CRITICAL** — AI-generated mistakes directly cause data breaches or authentication bypasses
- **HIGH** — Incorrect implementation compromises security posture or causes cryptographic failures
- **MEDIUM** — Practical importance for code quality and auditability; errors cause functional bugs or compliance gaps

## What Makes This Skill Different

**Correctness over coverage.** Every reference file contains paired correct and incorrect code examples with explanations of _why_ the wrong pattern fails — not just what the right pattern looks like. This is specifically designed to counteract the dangerous security patterns dominant in AI training data.

**Non-opinionated.** Focuses on Apple-documented facts and best practices, not architecture mandates. Uses "prefer" and "consider" — not "always" and "never" — except where security correctness demands it.

## Skill Structure

```
AGENTS.md                              ← repo-level AI agent onboarding
README.md                              ← you are here
LICENSE
.claude-plugin/
  plugin.json                          ← Claude Code plugin manifest
  marketplace.json                     ← Claude Code marketplace catalog
swift-security-expert/
  SKILL.md                             ← the skill: decision tree router, guidelines, behavioral rules
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

## How It Works

`SKILL.md` acts as a decision tree router. Based on what you're doing — **reviewing** code, **improving** existing implementations, or **building** something new — it routes the agent to the relevant reference documents. Each reference is self-contained with correct/incorrect Swift code examples and a summary checklist.

### Review Workflow

Ask the agent to audit existing code. The skill runs the top-level review checklist (11 items covering biometric bypass, credential exposure, access control, crypto correctness, and more), flags each item as pass/fail/warning, and cites the specific reference file and section for each finding.

### Improve Workflow

Ask the agent to modernize or fix existing code. The skill identifies gaps (legacy storage, wrong API, missing auth), loads the relevant migration + domain-specific reference files, and applies the correct patterns while verifying with domain checklists.

### Implement Workflow

Ask the agent to build a security feature from scratch. The skill identifies which domains apply, loads those reference files, and follows the correct patterns with proper error handling and access control from the start.

## Contributing

Contributions are welcome. When adding or editing reference files:

- Every reference file must have an H1 title, a scope blockquote, and a `## Summary Checklist` at the bottom
- Code examples use ✅ (correct) and ❌ (incorrect) markers — always provide both for security patterns
- Cite iOS version requirements for every API (`iOS 13+`, `iOS 17+`, `iOS 26+`)
- Cross-references use backtick-quoted filenames: `keychain-fundamentals.md`
- One canonical source per pattern — other files get a one-sentence summary + cross-reference link
- Cite Apple documentation URLs, WWDC session numbers, or Quinn "The Eskimo!" DTS posts for every non-obvious claim

See [AGENTS.md](AGENTS.md) for full contribution format, testing constraints, and scope boundaries.

## References & Sources

- [Apple Keychain Services Documentation](https://developer.apple.com/documentation/security/keychain_services)
- [Apple CryptoKit Documentation](https://developer.apple.com/documentation/cryptokit)
- [WWDC 2019-709 — "Cryptography and Your Apps"](https://developer.apple.com/videos/play/wwdc2019/709/)
- [WWDC 2020 — "Secure your app: threat modeling and anti-patterns"](https://developer.apple.com/videos/play/wwdc2020/10189/)
- [WWDC 2025 — "Get ahead with quantum-secure cryptography"](https://developer.apple.com/videos/play/wwdc2025/314)
- [TN3137 — On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
- [OWASP Mobile Top 10 (2024)](https://owasp.org/www-project-mobile-top-10/)
- [OWASP MASVS](https://mas.owasp.org/MASVS/)
- [OWASP MASTG](https://mas.owasp.org/MASTG/)

## License

This skill is open-source and available under the MIT License. See [LICENSE](LICENSE) for details.
