# Swift Security Expert

An AI agent skill for secure credential storage and cryptography on Apple platforms: Keychain Services, biometric authentication, CryptoKit, Secure Enclave, certificate trust, and OWASP compliance for iOS, macOS, tvOS, watchOS, and visionOS (iOS 13 through 26+).

## Table of Contents

- [Background](#background)
- [Philosophy](#philosophy)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## Background

AI coding assistants are unreliable on Apple security code. They reach for `UserDefaults` to hold tokens, gate access on a patchable `LAContext.evaluatePolicy()` boolean, drop `OSStatus` return codes on the floor, and reuse AES-GCM nonces. Each of these is a real vulnerability, not a style problem.

This skill gives an agent the defaults and review guidance it needs to avoid those mistakes. It covers reviewing existing Swift security code, modernizing legacy storage, and implementing Keychain, biometric, and CryptoKit features from scratch. The guidance comes from Apple documentation, DTS engineer posts (Quinn "The Eskimo!"), WWDC sessions, and the OWASP MASTG rather than from the model's own recall.

## Philosophy

- **Non-opinionated.** It supplies verified patterns and Apple-documented behavior rather than mandating one architecture. Where several valid options exist (P256 vs Curve25519, AES-GCM vs ChaChaPoly, actor vs serial queue), it presents the tradeoffs and lets you choose.
- **Correctness over coverage.** Reference files pair correct and incorrect examples and explain why the wrong one fails.
- **Grounded.** Every non-obvious claim cites Apple docs, a WWDC session, or an OWASP control. The skill does not invent session numbers or version requirements.
- **Built for work.** It targets review, fixes, and implementation, with a severity rating and an iOS version tag on every recommendation.

## Features

The skill covers fourteen client-side security domains. Each maps to a reference file the agent loads when the task needs it.

| Domain | Risk | Key APIs |
| --- | --- | --- |
| Keychain Fundamentals | CRITICAL | `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete`, `OSStatus` |
| Keychain Item Classes | HIGH | `kSecClassGenericPassword`, `kSecClassInternetPassword`, `kSecClassKey`, `kSecClassCertificate`, `kSecClassIdentity` |
| Keychain Access Control | CRITICAL | `kSecAttrAccessible*` (7 levels), `SecAccessControlCreateWithFlags`, `NSFileProtection` |
| Biometric Authentication | CRITICAL | `LAContext`, `evaluatePolicy`, `SecAccessControlCreateWithFlags`, `.biometryCurrentSet`, `.biometryAny` |
| Secure Enclave | HIGH | `SecureEnclave.P256.Signing.PrivateKey`, `SecureEnclave.isAvailable`, `kSecAttrTokenIDSecureEnclave` |
| CryptoKit — Symmetric | HIGH | `SHA256`–`SHA3_256`, `HMAC`, `AES.GCM`, `ChaChaPoly`, `SymmetricKey` |
| CryptoKit — Public Key | HIGH | `P256`, `P384`, `Curve25519`, `HKDF`, `HPKE` (iOS 17+), `MLKEM768`, `MLDSA65` (iOS 26+) |
| Credential Storage Patterns | CRITICAL | `ASWebAuthenticationSession`, keychain token patterns, `kSecAttrSynchronizable` |
| Keychain Sharing | MEDIUM | `kSecAttrAccessGroup`, `keychain-access-groups`, App Groups entitlement |
| Certificate Trust | HIGH | `SecCertificate`, `SecTrust`, `SecTrustEvaluateAsyncWithError`, `SecIdentity` |
| Migration — Legacy Stores | MEDIUM | `UserDefaults.removeObject`, `FileManager.removeItem`, first-launch flag pattern |
| Common Anti-Patterns | CRITICAL | Top 10 AI-generated mistakes with correct/incorrect pairs |
| Testing Security Code | MEDIUM | `XCTest`, protocol-based keychain mocks, Swift Testing, CI/CD strategies |
| Compliance & OWASP Mapping | MEDIUM | OWASP M1, M3, M9, M10; MASVS controls; MASTG test cases |

Risk levels: **CRITICAL** can lead to data exposure or auth bypass, **HIGH** weakens security or breaks cryptographic correctness, **MEDIUM** hurts reliability, testing, or auditability.

The skill treats iOS 13 as the minimum deployment baseline, recommends iOS 17+ patterns for new code, and carries forward-looking guidance through iOS 26 (post-quantum ML-KEM and ML-DSA). Networking, server-side auth, App Transport Security, CloudKit encryption, and third-party crypto libraries fall outside its scope.

## Installation

This is an agent skill, not a Swift package. Install it into the AI tool you use.

### skills.sh (recommended)

```bash
npx skills add https://github.com/ivan-magda/swift-security-skill --skill swift-security-expert
```

See the [skills.sh platform page](https://skills.sh/ivan-magda/swift-security-skill/swift-security-expert) for details.

### Claude Code plugin

Install it for yourself from the plugin marketplace:

```bash
/plugin marketplace add ivan-magda/swift-security-skill
/plugin install swift-security-expert@swift-security-skill
```

To enable it for everyone working in a repository, add this to `.claude/settings.json`:

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

### Claude Projects

Upload the contents of the `swift-security-expert/` folder (`SKILL.md` and every file under `references/`) to a Claude Project's knowledge base.

### Manual install

1. Clone this repository.
2. Install or symlink the `swift-security-expert/` folder following your tool's skill installation docs.
3. Ask your agent to use the "swift security expert" skill for security tasks.

For where each tool expects skills to live, see the [Codex](https://developers.openai.com/codex/skills/#where-to-save-skills), [Claude](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview#using-skills), and [Cursor](https://cursor.com/docs/context/skills#enabling-skills) docs.

## Usage

The skill activates when a task touches Apple-platform security: Keychain queries and `OSStatus` errors, biometric authentication, CryptoKit, Secure Enclave, credential storage, certificate pinning, keychain sharing, migrating secrets out of `UserDefaults` or plists, or OWASP MASVS/MASTG compliance. Most agents pick it up from the task itself. You can also name it:

> Use the swift security expert skill and review the current security code for authentication bypasses, credential storage issues, and cryptographic correctness.

`SKILL.md` is the router. It reads the intent behind the task and follows one of three branches:

- **Review** audits existing code against a top-level checklist, flags each item pass / fail / warning, and cites the reference file and section behind every finding.
- **Improve** identifies the gap (legacy store, wrong API, missing auth binding), loads the relevant migration and domain references, and applies the safer pattern.
- **Implement** selects the domains the task touches and builds the feature with add-or-update flows, error handling, and correct access control from the start.

When it is working, the agent treats `SKILL.md` as the router and loads only the reference files the task needs instead of pulling in all fourteen.

## Project Structure

```
swift-security-skill/
├── swift-security-expert/
│   ├── SKILL.md                      # Router: decision tree, core guidelines, behavioral rules
│   └── references/
│       ├── keychain-fundamentals.md       # SecItem* CRUD, OSStatus, actor wrappers, macOS TN3137
│       ├── keychain-item-classes.md       # kSecClass types, composite primary keys
│       ├── keychain-access-control.md     # Accessibility constants, SecAccessControl
│       ├── biometric-authentication.md    # Keychain-bound biometrics, LAContext bypass
│       ├── secure-enclave.md              # Hardware-backed P256, simulator traps
│       ├── cryptokit-symmetric.md         # SHA-2/3, HMAC, AES-GCM, ChaChaPoly, HKDF
│       ├── cryptokit-public-key.md        # ECDSA, ECDH, HPKE, ML-KEM/ML-DSA
│       ├── credential-storage-patterns.md # OAuth tokens, API keys, refresh rotation
│       ├── keychain-sharing.md            # Access groups, Team ID, extensions
│       ├── certificate-trust.md           # SecTrust, SPKI pinning, mTLS
│       ├── migration-legacy-stores.md     # UserDefaults/plist → Keychain migration
│       ├── common-anti-patterns.md        # Top 10 AI-generated security mistakes
│       ├── testing-security-code.md       # Protocol mocks, CI/CD, Swift Testing
│       └── compliance-owasp-mapping.md    # OWASP Mobile Top 10, MASVS, MASTG
├── .claude-plugin/
│   ├── plugin.json                   # Claude Code plugin manifest
│   └── marketplace.json              # Claude Code marketplace catalog
├── AGENTS.md                         # Repo-level agent onboarding (CLAUDE.md symlinks here)
├── tests/                            # Test plans for the review/improve/implement workflows
├── README.md
└── LICENSE
```

## Contributing

Contributions are welcome. When adding or editing reference files:

- Every reference file needs an H1 title, a scope blockquote, and a `## Summary Checklist` at the bottom.
- Code examples use ✅ (correct) and ❌ (incorrect) markers; provide both for every security pattern.
- Cite the iOS version requirement for every API (`iOS 13+`, `iOS 17+`, `iOS 26+`).
- Cross-references use backtick-quoted filenames: `keychain-fundamentals.md`.
- Keep one canonical source per pattern; other files get a one-sentence summary plus a cross-reference link.
- Cite an Apple documentation URL, WWDC session number, or Quinn "The Eskimo!" DTS post for every non-obvious claim.

See [AGENTS.md](AGENTS.md) for the full contribution format, testing constraints, and scope boundaries.

## License

Released under the [MIT License](LICENSE).
