# Category 4: Implement Workflow Tests

Each test asks Claude to build from scratch with no starting code. Tests the IMPLEMENT branch of the skill's decision tree. The focus is on whether generated code follows all Core Guidelines and avoids the 10 Common AI Mistakes.

---

### Test B-1: Secure Token Storage Manager for OAuth2 App

**Category:** Implement Workflow
**Domains tested:** `credential-storage-patterns.md`, `keychain-fundamentals.md`, `keychain-access-control.md`
**Difficulty:** MEDIUM

**Prompt (give this exact text to Claude):**
> Implement a secure token storage manager for an OAuth2 app targeting iOS 17+. It should store access tokens and refresh tokens, support token rotation, handle logout cleanup, and be safe to call from SwiftUI views.

**Expected catches (GREEN should find all, RED may miss some):**
1. **Actor isolation** — uses a dedicated `actor` (not `@MainActor`) for all SecItem calls. SwiftUI views call methods via `await`. (Core Guideline #4)
2. **Add-or-update pattern** — `SecItemAdd` with `errSecDuplicateItem` fallback to `SecItemUpdate`. (Core Guideline #6)
3. **Explicit `kSecAttrAccessible`** — `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for tokens (or `AfterFirstUnlockThisDeviceOnly` if background refresh is needed). (Core Guideline #5)
4. **Exhaustive OSStatus handling** — `switch` covering `errSecSuccess`, `errSecDuplicateItem`, `errSecItemNotFound`, `errSecInteractionNotAllowed`. (Core Guideline #1)
5. **Refresh token rotation** — mechanism to store new refresh token atomically when the old one is exchanged. Single-use semantics for RTR compliance.
6. **Complete logout cleanup** — deletes ALL credential artifacts (access token, refresh token, any cached user data). Not just one key.
7. **No UserDefaults for tokens** — all secrets in Keychain. (Core Guideline #3)

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but incomplete implementation
- 0 points if missed entirely
- Bonus point (+1) if GREEN includes a `## Reference Files` section citing sources
- Total possible: 8

**Why this tests the skill (not just general knowledge):**
> An unassisted LLM commonly generates a token manager that uses `@MainActor`, ignores `errSecDuplicateItem`, omits `kSecAttrAccessible`, or does partial logout cleanup. The complete set of 7 Core Guidelines applied simultaneously is what the skill provides.

---

### Test B-2: Secure Enclave Signing Service

**Category:** Implement Workflow
**Domains tested:** `secure-enclave.md`, `keychain-fundamentals.md`
**Difficulty:** HARD

**Prompt (give this exact text to Claude):**
> Create a Secure Enclave signing service for document authentication on iOS 17+. It should generate a P256 signing key in the Secure Enclave, persist it across app launches, and provide sign/verify operations.

**Expected catches (GREEN should find all, RED may miss some):**
1. **SE P256 key generation (not import)** — uses `SecureEnclave.P256.Signing.PrivateKey()` to generate, never imports external keys. (AI Mistake #3)
2. **Simulator guard** — `#if targetEnvironment(simulator)` compile-time guard wrapping SE code. Runtime `SecureEnclave.isAvailable` check only in device builds. (AI Mistake #2)
3. **Keychain persistence of opaque blob** — saves `key.dataRepresentation` (encrypted opaque blob) to Keychain, restores via `SecureEnclave.P256.Signing.PrivateKey(dataRepresentation:)`.
4. **No SE symmetric API references** — must not fabricate `SecureEnclave.AES` or similar. (AI Mistake #4)
5. **Proper error handling** — OSStatus on keychain persist, SE availability errors, key creation errors.
6. **Explicit `kSecAttrAccessible`** on keychain persistence — the SE key blob in keychain needs appropriate accessibility.
7. **Add-or-update for keychain persistence** — the key blob save must handle duplicates. (Core Guideline #6)

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but incomplete
- 0 points if missed entirely
- Bonus point (+1) if GREEN includes a `## Reference Files` section
- Total possible: 8

**Why this tests the skill (not just general knowledge):**
> An unassisted LLM frequently generates SE code that imports keys (`rawRepresentation:`), omits the simulator guard, or fabricates symmetric SE APIs. The opaque blob persistence pattern (save `dataRepresentation`, restore via `init(dataRepresentation:)`) is specific knowledge from the skill.

---

### Test B-3: Encrypted Local Cache with Keychain-Stored Key

**Category:** Implement Workflow
**Domains tested:** `cryptokit-symmetric.md`, `keychain-fundamentals.md`, `credential-storage-patterns.md`
**Difficulty:** MEDIUM

**Prompt (give this exact text to Claude):**
> Build an encrypted local cache using CryptoKit AES-GCM with a key stored in the Keychain. The cache should encrypt arbitrary Data blobs for local persistence and support key rotation. iOS 17+ target.

**Expected catches (GREEN should find all, RED may miss some):**
1. **`SymmetricKey` stored in Keychain** — key material goes into Keychain with proper `kSecAttrAccessible`, not in UserDefaults, files, or hardcoded. (Core Guideline #3)
2. **No explicit nonce** — `AES.GCM.seal(plaintext, using: key)` called without `nonce:` parameter, letting CryptoKit auto-generate random nonces. (AI Mistake #7)
3. **Proper SealedBox handling** — uses `.combined` for storage (nonce || ciphertext || tag), reconstructs via `AES.GCM.SealedBox(combined:)` for decryption.
4. **Key rotation strategy** — mechanism to generate a new key, re-encrypt cached data, and securely delete the old key. Version or tag the key so old ciphertext can be decrypted during transition.
5. **Actor isolation** — keychain key retrieval off main thread. (Core Guideline #4)
6. **Add-or-update for key storage** — keychain key save handles duplicates. (Core Guideline #6)
7. **OSStatus handling** — all keychain calls check return codes. (Core Guideline #1)

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but incomplete
- 0 points if missed entirely
- Bonus point (+1) if GREEN includes a `## Reference Files` section
- Total possible: 8

**Why this tests the skill (not just general knowledge):**
> The key trap is explicit nonce management — an unassisted LLM commonly generates `AES.GCM.Nonce()` or constructs nonces manually. The skill's directive to always omit the nonce parameter is non-obvious. Key rotation strategy (versioned keys, transition period) is domain-specific guidance.

---

### Test B-4: Certificate Pinning for Banking App

**Category:** Implement Workflow
**Domains tested:** `certificate-trust.md`
**Difficulty:** HARD

**Prompt (give this exact text to Claude):**
> Implement certificate pinning for our banking app's API client. We need it to survive server certificate renewals and have a plan for pin rotation. iOS 17+ target.

**Expected catches (GREEN should find all, RED may miss some):**
1. **SPKI hash pinning (not leaf)** — hashes the SubjectPublicKeyInfo structure, not raw certificate bytes. Survives certificate renewal with the same key pair. Must prepend ASN.1 header before SHA-256 hashing.
2. **`SecTrustEvaluateWithError` or `SecTrustEvaluateAsyncWithError`** — not deprecated `SecTrustEvaluate`. In `URLSessionDelegate`, synchronous `SecTrustEvaluateWithError` is valid (already off main thread).
3. **`SecTrustCopyCertificateChain`** — not deprecated `SecTrustGetCertificateAtIndex`. (iOS 15+)
4. **Pin rotation plan** — include at least one backup pin hash (the next key pair's SPKI). Document the rotation procedure: generate new key pair on server, add its SPKI hash to the app, deploy, then rotate the certificate.
5. **Walk the full chain** — check SPKI hashes against all certificates in the chain, not just the leaf. This allows pinning at the intermediate CA level as well.
6. **Mention `NSPinnedDomains` alternative** (iOS 14+) — declarative pinning without delegate code. Advisory recommendation alongside the programmatic approach.
7. **System trust evaluation first** — always validate the chain against the system trust store before checking pins. Never skip standard trust evaluation.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but incomplete
- 0 points if missed entirely
- Bonus point (+1) if GREEN includes a `## Reference Files` section
- Total possible: 8

**Why this tests the skill (not just general knowledge):**
> An unassisted LLM commonly generates leaf pinning (comparing raw certificate bytes) which breaks on every renewal — the exact problem the prompt describes wanting to avoid. The ASN.1 header requirement for correct SPKI hashing is a critical detail most implementations miss. Backup pin and rotation planning require operational knowledge.

---

### Test B-5: Biometric Unlock Surviving Face ID Re-Enrollment

**Category:** Implement Workflow
**Domains tested:** `biometric-authentication.md`, `keychain-access-control.md`, `keychain-fundamentals.md`
**Difficulty:** HARD

**Prompt (give this exact text to Claude):**
> Add biometric unlock to our password manager. It must survive Face ID re-enrollment gracefully (detect when biometrics change and guide the user through re-enrollment). iOS 17+ target.

**Expected catches (GREEN should find all, RED may miss some):**
1. **Keychain-bound biometrics (not boolean gate)** — store a secret behind `SecAccessControl` with `.biometryCurrentSet`, retrieve via `SecItemCopyMatching`. No `evaluatePolicy()` as standalone gate. (Core Guideline #2; AI Mistake #1)
2. **`.biometryCurrentSet` flag** — this flag invalidates the keychain item when biometrics change. This is the mechanism that detects re-enrollment — `SecItemCopyMatching` fails with `errSecAuthFailed` or `errSecItemNotFound` after enrollment change.
3. **`evaluatedPolicyDomainState` monitoring** — use `LAContext.evaluatedPolicyDomainState` to proactively detect biometric changes before attempting keychain access. Compare stored domain state with current state on app launch.
4. **Re-enrollment flow** — when biometrics change: detect via domain state or keychain error, prompt user for master password (or other fallback), re-store the secret behind the new biometric set with a fresh `SecAccessControl`.
5. **Graceful degradation** — if biometrics are unavailable (not enrolled, hardware failure), fall back to passcode via `.devicePasscode` or manual password entry. Don't crash or lock the user out.
6. **`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` as the `protection` parameter of `SecAccessControlCreateWithFlags`** — this is how the accessibility level is set for biometric items. Per `biometric-authentication.md`: do NOT also set `kSecAttrAccessible` in the query dictionary — `SecAccessControl` already encodes it, and setting both causes `errSecParam`. Items in this class are permanently deleted if the user removes their passcode.
7. **Actor isolation** — all keychain operations off `@MainActor`. (Core Guideline #4)
8. **OSStatus handling** — handle `errSecAuthFailed` (biometric change), `errSecUserCanceled` (user dismissed prompt), `errSecInteractionNotAllowed` (device locked). (Core Guideline #1)

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but incomplete
- 0 points if missed entirely
- Bonus point (+1) if GREEN includes a `## Reference Files` section
- Total possible: 9

**Why this tests the skill (not just general knowledge):**
> The re-enrollment flow is the key differentiator. An unassisted LLM may use `.biometryCurrentSet` but not explain what happens when biometrics change — the item becomes inaccessible and the user needs a recovery path. The `evaluatedPolicyDomainState` proactive detection and the full re-enrollment UX flow require domain expertise that the skill provides.
