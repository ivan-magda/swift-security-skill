# Swift Security Expert

Agent skill for Apple platform security work in Swift. It covers Keychain Services, biometric access control, CryptoKit, Secure Enclave, certificate trust, and secure credential storage on iOS and macOS.

The point is simple: AI tools are often shaky on security code, especially around Keychain, biometrics, and cryptography. This repo gives them better defaults, sharper review guidance, and Apple-specific implementation patterns.

The guidance is based on Apple documentation, DTS engineer guidance, WWDC sessions, and OWASP MASTG.

## Best For

- Reviewing Swift security code for storage, auth, and crypto mistakes
- Implementing Keychain, biometrics, Secure Enclave, and CryptoKit correctly
- Moving secrets out of `UserDefaults`, plists, or legacy storage
- Mapping Apple-platform code to OWASP Mobile Top 10 / MASVS checks

## Why This Skill Exists

AI coding assistants routinely generate dangerous Apple security code. This skill exists to catch those patterns and replace them with safer ones.

## How to Use This Skill

### Option A: Using skills.sh (Recommended)

```bash
npx skills add https://github.com/ivan-magda/swift-security-skill --skill swift-security-expert
```

For more information, [visit the skills.sh platform page](https://skills.sh/ivan-magda/swift-security-skill/swift-security-expert).

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

**How to verify:** Your agent should use `SKILL.md` as the router and load the relevant reference files for the task.

## What This Skill Covers

### Review

- Catch `LAContext.evaluatePolicy()` used as a standalone auth gate
- Flag secrets stored in `UserDefaults`, property lists, or source
- Catch ignored `OSStatus` failures and weak `kSecAttrAccessible` choices

### Build

- Implement keychain-backed biometrics with `SecAccessControl`
- Use correct `SecItemAdd` / `SecItemCopyMatching` add-or-update flows
- Generate and use Secure Enclave keys without simulator mistakes
- Store and rotate OAuth tokens safely

### Decide

- Choose between `.biometryCurrentSet`, `.biometryAny`, and `.userPresence`
- Pick the right accessibility class for foreground vs background access
- Choose between AES-GCM and ChaChaPoly, P256 and Curve25519, and newer post-quantum options on iOS 26+
- Decide between Keychain Sharing and App Groups for shared credentials

### Audit

- Map findings to OWASP Mobile Top 10 (2024)
- Check MASVS / MASTG alignment
- Produce audit-ready notes for reviews

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

- **CRITICAL** — mistakes that can lead to data exposure or auth bypass
- **HIGH** — mistakes that weaken security or break cryptographic correctness
- **MEDIUM** — mistakes that hurt reliability, testing, or auditability

## What Makes This Skill Different

- **Correctness over coverage.** Reference files include correct and incorrect examples, plus why the wrong pattern fails.
- **Apple-specific.** Focuses on Apple APIs and Apple-platform failure modes, not generic security advice.
- **Non-opinionated.** Stays close to documented Apple behavior and verified patterns rather than pushing one architecture.
- **Practical.** Built for review, fixes, and implementation work — not just reference reading.

## How It Works

`SKILL.md` is a router. It looks at the task — **review**, **improve**, or **implement** — then pulls in the right reference files.

### Review

Use it to audit existing code. The skill runs the review checklist, flags findings as pass/fail/warning, and points to the exact reference file and section behind each call.

### Improve

Use it to fix or modernize existing code. The skill identifies the gap, loads the relevant migration and domain references, then applies the safer pattern.

### Implement

Use it to build a security feature from scratch. The skill selects the relevant domains and follows the correct patterns from the start.

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

MIT
