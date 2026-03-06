# Test Plan Summary

This test plan contains 28 test cases across 5 categories, designed for RED-GREEN comparison testing of the Keychain & Security Expert Skill. Each test is run twice: once without the skill (RED/baseline) and once with the skill loaded (GREEN). The delta measures the skill's value-add.

---

## Test Index

| ID  | Title                                              | Domains                                                       | Difficulty | Points |
| --- | -------------------------------------------------- | ------------------------------------------------------------- | ---------- | ------ |
| R-1 | Keychain CRUD with Ignored Errors and MainActor    | `keychain-fundamentals.md`                                    | EASY       | 5      |
| R-2 | Wrong kSecClass for Web Credentials                | `keychain-item-classes.md`                                    | MEDIUM     | 4      |
| R-3 | Broken Accessibility for Background Fetch          | `keychain-access-control.md`                                  | MEDIUM     | 5      |
| R-4 | Boolean Gate Biometric Authentication              | `biometric-authentication.md`                                 | EASY       | 4      |
| R-5 | Secure Enclave Misuse Trifecta                     | `secure-enclave.md`                                           | HARD       | 5      |
| R-6 | AES-GCM Nonce Reuse and Insecure Hashing           | `cryptokit-symmetric.md`                                      | MEDIUM     | 4      |
| R-7 | Raw ECDH and Wrong HPKE Version                    | `cryptokit-public-key.md`                                     | HARD       | 4      |
| R-8 | Insecure Token Storage and Missing Cleanup         | `credential-storage-patterns.md`                              | EASY       | 5      |
| M-1 | KeychainManager with Biometrics + Threading        | `keychain-fundamentals`, `keychain-access-control`, `biometric-authentication` | HARD | 7 |
| M-2 | SE Signing with ECDH and Keychain Persistence      | `secure-enclave`, `cryptokit-public-key`, `keychain-fundamentals` | HARD    | 6      |
| M-3 | UserDefaults Migration with Missing Cleanup        | `credential-storage-patterns`, `migration-legacy-stores`, `common-anti-patterns` | MEDIUM | 6 |
| M-4 | App Group Sharing with Wrong Access Group          | `keychain-sharing`, `keychain-access-control`, `keychain-item-classes` | MEDIUM | 6 |
| M-5 | Certificate Pinning with Token Storage             | `certificate-trust`, `credential-storage-patterns`, `compliance-owasp-mapping` | HARD | 7 |
| I-1 | UserDefaults to Keychain Token Migration           | `migration-legacy-stores`, `credential-storage-patterns`, `keychain-fundamentals` | MEDIUM | 8 |
| I-2 | Security Framework RSA to CryptoKit Migration      | `cryptokit-public-key`, `migration-legacy-stores`, `secure-enclave` | HARD   | 6      |
| I-3 | LAContext-Only to Keychain-Bound Biometrics        | `biometric-authentication`, `keychain-access-control`, `keychain-fundamentals` | MEDIUM | 7 |
| I-4 | Leaf Pinning to SPKI Pinning                       | `certificate-trust`                                           | HARD       | 7      |
| I-5 | Single App to Shared Keychain with Extension       | `keychain-sharing`, `keychain-fundamentals`, `keychain-access-control` | MEDIUM | 6 |
| B-1 | Secure Token Storage Manager for OAuth2            | `credential-storage-patterns`, `keychain-fundamentals`, `keychain-access-control` | MEDIUM | 8 |
| B-2 | Secure Enclave Signing Service                     | `secure-enclave`, `keychain-fundamentals`                     | HARD       | 8      |
| B-3 | Encrypted Local Cache with Keychain Key            | `cryptokit-symmetric`, `keychain-fundamentals`, `credential-storage-patterns` | MEDIUM | 8 |
| B-4 | Certificate Pinning for Banking App                | `certificate-trust`                                           | HARD       | 8      |
| B-5 | Biometric Unlock Surviving Re-Enrollment           | `biometric-authentication`, `keychain-access-control`, `keychain-fundamentals` | HARD | 9 |
| E-1 | Out-of-Scope: App Transport Security               | (scope boundary)                                              | EASY       | 4      |
| E-2 | Opinion-Seeking: Third-Party Keychain Wrapper      | (tone rules)                                                  | MEDIUM     | 5      |
| E-3 | Version Constraint: CryptoKit on iOS 12            | `cryptokit-symmetric` (version baseline)                      | EASY       | 5      |
| E-4 | Opinion-Seeking: P256 vs Curve25519                | `cryptokit-public-key` (curve selection)                      | MEDIUM     | 6      |
| E-5 | Out-of-Scope: CloudKit Encrypted Records           | (scope boundary)                                              | EASY       | 4      |

**Total maximum points across all 28 tests: 170**

---

## Coverage Matrix: Common AI Mistakes (1-10)

Every Common AI Mistake from SKILL.md is covered by at least 2 test cases.

| Mistake # | Description                        | Covered by Tests                   | Count |
| --------- | ---------------------------------- | ---------------------------------- | ----- |
| 1         | Boolean gate (LAContext-only)      | R-4, M-1, I-3, B-5                | 4     |
| 2         | SE simulator guard missing         | R-5, M-2, B-2                     | 3     |
| 3         | SE key import (rawRepresentation)  | R-5, M-2, B-2                     | 3     |
| 4         | SE symmetric (non-existent API)    | R-5, B-2                          | 2     |
| 5         | Missing kSecAttrAccessible         | R-1, R-3, M-2, B-1                | 4     |
| 6         | Missing duplicate handling         | R-1, M-1, M-2, M-3, I-1, B-1     | 6     |
| 7         | Explicit nonce (AES-GCM)           | R-6, B-3                          | 2     |
| 8         | Raw ECDH shared secret             | R-7, M-2, R-5                     | 3     |
| 9         | SHA-3 / HPKE version errors        | R-7, I-2, E-3                     | 3     |
| 10        | First-launch cleanup missing       | R-8, M-3, I-1                     | 3     |

---

## Coverage Matrix: Core Guidelines (1-7)

Every Core Guideline from SKILL.md is covered by at least 3 test cases.

| Guideline # | Description                      | Covered by Tests                        | Count |
| ----------- | -------------------------------- | --------------------------------------- | ----- |
| 1           | Never ignore OSStatus            | R-1, R-3, M-1, M-2, B-1, B-2           | 6     |
| 2           | Never use LAContext as sole gate  | R-4, M-1, I-3, B-5                      | 4     |
| 3           | Never store secrets in UserDefaults | R-8, M-3, I-1, B-1                   | 4     |
| 4           | Never SecItem on @MainActor      | R-1, M-1, I-1, I-3, B-1, B-5           | 6     |
| 5           | Always set kSecAttrAccessible    | R-1, R-3, M-2, M-4, I-1, I-5, B-1, B-2 | 8    |
| 6           | Always add-or-update pattern     | R-1, R-3, M-1, M-2, M-3, I-1, B-1, B-2 | 8    |
| 7           | macOS data protection keychain   | I-5                                      | 1     |

> Note: Core Guideline #7 (macOS data protection keychain) has minimal coverage because all test prompts target iOS. Only I-5 (shared keychain with extension) includes a macOS caveat as an expected catch. To increase coverage, a future test could add an explicit macOS or Catalyst scenario.

---

## Coverage Matrix: Reference Files

Every reference file is exercised by at least 2 tests.

| Reference File                    | Tests Using It                        | Count |
| --------------------------------- | ------------------------------------- | ----- |
| `keychain-fundamentals.md`        | R-1, M-1, M-2, I-1, I-3, I-5, B-1, B-2, B-3, B-5 | 10 |
| `keychain-item-classes.md`        | R-2, M-4                             | 2     |
| `keychain-access-control.md`      | R-3, M-1, M-4, I-3, I-5, B-1, B-5   | 7     |
| `biometric-authentication.md`     | R-4, M-1, I-3, B-5                   | 4     |
| `secure-enclave.md`               | R-5, M-2, I-2, B-2                   | 4     |
| `cryptokit-symmetric.md`          | R-6, E-3, B-3                        | 3     |
| `cryptokit-public-key.md`         | R-7, M-2, I-2, E-4                   | 4     |
| `credential-storage-patterns.md`  | R-8, M-3, M-5, I-1, B-1, B-3        | 6     |
| `keychain-sharing.md`             | M-4, I-5                             | 2     |
| `certificate-trust.md`            | M-5, I-4, B-4                        | 3     |
| `migration-legacy-stores.md`      | M-3, I-1, I-2                        | 3     |
| `common-anti-patterns.md`         | M-3 (+ all R-* tests implicitly)     | 3+    |
| `testing-security-code.md`        | (not directly tested — supplementary) | 0     |
| `compliance-owasp-mapping.md`     | M-5                                   | 1     |

> `testing-security-code.md` and `compliance-owasp-mapping.md` are supplementary reference files. Testing and compliance are indirectly tested via the review and implement categories.

---

## Coverage Matrix: Skill Behavioral Features

| Feature                        | Tests                   |
| ------------------------------ | ----------------------- |
| Scope exclusion (out-of-scope) | E-1, E-5               |
| Advisory tone (choices)        | E-2, E-4               |
| Directive tone (invariants)    | R-1 through R-8, all M-*, all B-* |
| Version baseline accuracy      | R-7, I-2, E-3          |
| Reference file citation        | All tests (bonus point) |
| Decision tree: REVIEW branch   | R-1 through R-8, M-1 through M-5 |
| Decision tree: IMPROVE branch  | I-1 through I-5        |
| Decision tree: IMPLEMENT branch | B-1 through B-5       |

---

## Expected RED-GREEN Delta Predictions

These predictions estimate how much the skill improves response quality over Claude's baseline knowledge.

| Category               | Tests | Expected RED avg | Expected GREEN avg | Predicted delta | Rationale                                                                                          |
| ---------------------- | ----- | ---------------- | ------------------ | --------------- | -------------------------------------------------------------------------------------------------- |
| Single-domain review   | 8     | ~45-60%          | ~85-95%            | +30-40%         | RED catches obvious issues (UserDefaults, MD5) but misses subtle ones (MainActor, SE APIs, nonce)  |
| Multi-domain review    | 5     | ~30-50%          | ~80-90%            | +35-50%         | Cross-domain interactions compound difficulty; RED focuses on one domain at a time                  |
| Improve workflow       | 5     | ~50-65%          | ~85-95%            | +25-35%         | RED provides basic migration but misses pre-warming, first-launch cleanup, atomic operations       |
| Implement workflow     | 5     | ~40-55%          | ~80-90%            | +30-40%         | RED generates code with common AI mistakes; GREEN avoids all 10 by design                          |
| Edge cases             | 5     | ~55-70%          | ~90-100%           | +25-35%         | RED may answer out-of-scope questions; GREEN correctly declines. Tone calibration is skill-specific |

### Where the Largest Deltas Are Expected

1. **Secure Enclave tests (R-5, M-2, B-2)** — RED will fabricate non-existent SE APIs (`rawRepresentation:`, `SecureEnclave.AES`). GREEN knows these don't exist.
2. **Boolean gate tests (R-4, M-1, I-3, B-5)** — RED generates the boolean pattern from training data. GREEN replaces it with keychain-bound biometrics.
3. **Nonce management (R-6, B-3)** — RED commonly generates explicit nonces. GREEN knows to omit the parameter.
4. **Version accuracy (R-7, I-2, E-3)** — RED hallucinates iOS version requirements. GREEN uses the Version Baseline table.
5. **Scope boundaries (E-1, E-5)** — RED answers everything. GREEN correctly declines out-of-scope topics.
6. **First-launch cleanup (R-8, M-3, I-1)** — RED never generates this pattern. GREEN knows keychain survives app deletion.

### Where the Smallest Deltas Are Expected

1. **UserDefaults for tokens (R-8)** — well-known issue, RED likely catches it.
2. **MD5 insecurity (R-6)** — basic security knowledge, RED should catch it.
3. **CryptoKit iOS 13+ requirement (E-3)** — factual knowledge RED likely has correct.

---

## Test Execution Notes

### Setup
- RED runs: Claude without any skill files loaded. System prompt: standard Claude behavior.
- GREEN runs: Claude with `SKILL.md` loaded + relevant reference files per the "Domains tested" field.

### Scoring Protocol
1. Run the prompt exactly as written (copy-paste).
2. Score each expected catch as: 1 (found with correct detail), 0.5 (found but wrong detail), or 0 (missed).
3. Award bonus point only if the specific reference file is cited by name.
4. Record the raw score and calculate percentage: `(score / total possible) * 100`.
5. Compare RED and GREEN percentages per test and per category.

### Statistical Notes
- Run each test 3 times per condition (RED/GREEN) to account for model variability.
- Use the median score for comparison.
- A delta of >20% with p<0.05 (paired t-test across all 28 tests) would indicate statistically significant skill impact.
