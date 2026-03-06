# Category 3: Improve Workflow Tests

Each test presents existing legacy code and asks Claude to modernize it. Tests the IMPROVE branch of the skill's decision tree. The focus is on migration correctness, secure deletion, and proper use of modern APIs.

---

### Test I-1: UserDefaults to Keychain Token Migration

**Category:** Improve Workflow
**Domains tested:** `migration-legacy-stores.md`, `credential-storage-patterns.md`, `keychain-fundamentals.md`
**Difficulty:** MEDIUM

**Prompt (give this exact text to Claude):**
> Modernize this token storage. It currently uses UserDefaults and I need to migrate to Keychain. The app has existing users so tokens must be migrated on upgrade without data loss:
>
> ```swift
> class LegacyTokenStore {
>     func save(accessToken: String, refreshToken: String) {
>         UserDefaults.standard.set(accessToken, forKey: "access_token")
>         UserDefaults.standard.set(refreshToken, forKey: "refresh_token")
>     }
>
>     func getAccessToken() -> String? {
>         UserDefaults.standard.string(forKey: "access_token")
>     }
>
>     func getRefreshToken() -> String? {
>         UserDefaults.standard.string(forKey: "refresh_token")
>     }
>
>     func clear() {
>         UserDefaults.standard.removeObject(forKey: "access_token")
>         UserDefaults.standard.removeObject(forKey: "refresh_token")
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Keychain storage with add-or-update pattern** — new implementation must use `SecItemAdd` with `errSecDuplicateItem` fallback to `SecItemUpdate`. (Core Guideline #6)
2. **Explicit `kSecAttrAccessible`** — must specify accessibility constant (e.g., `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for tokens). (Core Guideline #5)
3. **Migration with secure legacy deletion** — after verified keychain write, remove all legacy UserDefaults keys. Must verify keychain write succeeded before deleting legacy data (atomic migration).
4. **Versioned migration flag** — use a UserDefaults flag (e.g., `hasMigratedToKeychain`) so migration runs only once, not on every launch. Must handle iOS 15+ pre-warming (check `isProtectedDataAvailable`).
5. **First-launch keychain cleanup** — separate from migration: detect app reinstall via UserDefaults flag and clear stale keychain items before migration runs. (AI Mistake #10)
6. **Actor or background queue isolation** — SecItem calls must not be on `@MainActor`. (Core Guideline #4)
7. **OSStatus handling** — all keychain operations must check return codes. (Core Guideline #1)

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN cites the reference files in a `## Reference Files` section
- Total possible: 8

**Why this tests the skill (not just general knowledge):**
> The migration has multiple trap doors: pre-warming during protected data unavailability, first-launch cleanup separate from migration, atomic verification before legacy deletion. An unassisted LLM typically provides a straightforward "save to keychain instead" without addressing migration sequencing, reinstall detection, or pre-warming.

---

### Test I-2: Security Framework RSA to CryptoKit Migration

**Category:** Improve Workflow
**Domains tested:** `cryptokit-public-key.md`, `migration-legacy-stores.md`, `secure-enclave.md`
**Difficulty:** HARD

**Prompt (give this exact text to Claude):**
> Modernize this RSA encryption from the Security framework to CryptoKit. We need to encrypt sensitive payloads sent to our server (iOS 17+ deployment target):
>
> ```swift
> import Security
>
> func encryptWithRSA(_ data: Data, publicKeyPEM: String) throws -> Data {
>     let keyData = // ... base64 decode PEM ...
>     let attributes: [String: Any] = [
>         kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
>         kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
>         kSecAttrKeySizeInBits as String: 2048
>     ]
>     var error: Unmanaged<CFError>?
>     guard let secKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
>         throw error!.takeRetainedValue()
>     }
>     guard let encrypted = SecKeyCreateEncryptedData(secKey, .rsaEncryptionOAEPSHA256, data as CFData, &error) else {
>         throw error!.takeRetainedValue()
>     }
>     return encrypted as Data
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Recommend HPKE for iOS 17+** — with iOS 17+ deployment target, HPKE (`HPKE.Sender`) replaces manual ECDH+HKDF+AES-GCM chains and is the modern equivalent for hybrid public-key encryption. Specify the correct ciphersuite (e.g., `Curve25519_SHA256_ChachaPoly` or P256 variant for server interop).
2. **Correct HPKE version gate** — must be `@available(iOS 17.0, *)`, not iOS 15 or iOS 18. (AI Mistake #9 — version errors)
3. **Key storage guidance** — if the recipient key needs to be stored locally, store in Keychain with proper accessibility, not in files or UserDefaults.
4. **Consider Secure Enclave for signing** — if the app also needs to sign payloads (related use case), SE P256 keys provide hardware-backed signing. SE keys are P256 only, cannot be imported, must be generated on-device. (SE constraints awareness)
5. **Include `encapsulatedKey` handling** — HPKE sender produces both sealed data and an encapsulated key. Both must be transmitted to the recipient for decryption.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN cites the reference files in a `## Reference Files` section
- Total possible: 6

**Why this tests the skill (not just general knowledge):**
> An unassisted LLM may suggest P256 ECDH + HKDF + AES-GCM instead of the simpler HPKE path (which encapsulates the same pattern). The HPKE version gate (iOS 17, not 15 or 18) is a common AI error. Understanding that HPKE replaces the entire manual chain requires knowing the iOS 17 API surface.

---

### Test I-3: LAContext-Only to Keychain-Bound Biometrics

**Category:** Improve Workflow
**Domains tested:** `biometric-authentication.md`, `keychain-access-control.md`, `keychain-fundamentals.md`
**Difficulty:** MEDIUM

**Prompt (give this exact text to Claude):**
> Our security team flagged our biometric auth as bypassable. Modernize this to be secure:
>
> ```swift
> import LocalAuthentication
>
> class BiometricGate {
>     func checkBiometric(completion: @escaping (Bool) -> Void) {
>         let context = LAContext()
>         context.evaluatePolicy(
>             .deviceOwnerAuthenticationWithBiometrics,
>             localizedReason: "Verify your identity"
>         ) { success, _ in
>             DispatchQueue.main.async {
>                 completion(success)
>             }
>         }
>     }
> }
>
> // Usage in ViewController:
> biometricGate.checkBiometric { [weak self] success in
>     if success {
>         self?.showAccountDetails()
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Replace boolean gate with keychain-bound biometrics** — store a secret (e.g., session key or auth token) behind `SecAccessControl` with `.biometryCurrentSet` via `SecAccessControlCreateWithFlags`. Retrieval via `SecItemCopyMatching` triggers hardware biometric validation. (Core Guideline #2; AI Mistake #1)
2. **Use `.biometryCurrentSet` not `.biometryAny`** — `.biometryCurrentSet` invalidates the item on enrollment changes, preventing an attacker who gains physical access from enrolling their own biometrics.
3. **Add `evaluatedPolicyDomainState` monitoring** — detect enrollment changes and re-enroll the user's secret when biometrics change. Combine with graceful degradation to passcode.
4. **Provide re-enrollment flow** — when biometrics change, the old keychain item is invalidated. The app needs a flow to re-authenticate the user (e.g., password) and re-store the secret behind the new biometric set.
5. **Actor isolation for keychain calls** — the new keychain-based implementation must keep SecItem calls off the main thread. (Core Guideline #4)
6. **Correct accessibility via `SecAccessControlCreateWithFlags`** — the `protection` parameter of `SecAccessControlCreateWithFlags` embeds the accessibility level; use `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` for biometric-protected items. Per `biometric-authentication.md`: do NOT also set `kSecAttrAccessible` in the query dictionary alongside `kSecAttrAccessControl` — they conflict and cause `errSecParam`.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN cites the reference files in a `## Reference Files` section
- Total possible: 7

**Why this tests the skill (not just general knowledge):**
> The migration from boolean gate to keychain-bound biometrics requires understanding the full pattern: store, access control, retrieval, enrollment change detection, and re-enrollment flow. An unassisted LLM may add `SecAccessControl` but miss enrollment change detection and re-enrollment.

---

### Test I-4: Leaf Pinning to SPKI Pinning

**Category:** Improve Workflow
**Domains tested:** `certificate-trust.md`
**Difficulty:** HARD

**Prompt (give this exact text to Claude):**
> Our certificate pinning keeps breaking every time the server renews its TLS certificate. Modernize this to survive certificate renewals:
>
> ```swift
> class PinningDelegate: NSObject, URLSessionDelegate {
>     let pinnedCert: Data // loaded from bundle .cer
>
>     func urlSession(_ session: URLSession,
>                     didReceive challenge: URLAuthenticationChallenge,
>                     completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
>         guard let serverTrust = challenge.protectionSpace.serverTrust else {
>             completionHandler(.cancelAuthenticationChallenge, nil)
>             return
>         }
>         var result: SecTrustResultType = .invalid
>         SecTrustEvaluate(serverTrust, &result)
>         guard result == .unspecified || result == .proceed else {
>             completionHandler(.cancelAuthenticationChallenge, nil)
>             return
>         }
>         let serverCert = SecTrustGetCertificateAtIndex(serverTrust, 0)!
>         if SecCertificateCopyData(serverCert) as Data == pinnedCert {
>             completionHandler(.useCredential, URLCredential(trust: serverTrust))
>         } else {
>             completionHandler(.cancelAuthenticationChallenge, nil)
>         }
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Migrate to SPKI hash pinning** — hash the SubjectPublicKeyInfo structure instead of comparing raw certificate bytes. SPKI survives certificate renewal when the same key pair is reused. Must prepend the correct ASN.1 header before hashing (critical correctness detail).
2. **Replace `SecTrustEvaluate` with `SecTrustEvaluateWithError`** (iOS 12+) or `SecTrustEvaluateAsyncWithError` (iOS 13+). `SecTrustEvaluate` is deprecated since iOS 13.
3. **Replace `SecTrustGetCertificateAtIndex` with `SecTrustCopyCertificateChain`** (iOS 15+). The former is deprecated.
4. **Consider `NSPinnedDomains` as alternative** (iOS 14+) — declarative pinning in Info.plist that doesn't require delegate code. Supports SPKI hash pins with automatic rotation handling.
5. **Pin rotation plan** — include at least one backup pin (next key pair's SPKI hash) so that key rotation doesn't lock out users. Document the rotation procedure.
6. **Walk the entire chain** — check SPKI hashes against all certificates in the chain (not just leaf), so intermediate CA pinning is also supported.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN cites the reference files in a `## Reference Files` section
- Total possible: 7

**Why this tests the skill (not just general knowledge):**
> The ASN.1 header prepend step in SPKI hashing is a critical correctness detail that most implementations miss. An unassisted LLM may suggest "hash the public key" without the SPKI structure, producing incorrect hashes. The `NSPinnedDomains` alternative and backup pin strategy are non-obvious recommendations.

---

### Test I-5: Single App to Shared Keychain with Extension

**Category:** Improve Workflow
**Domains tested:** `keychain-sharing.md`, `keychain-fundamentals.md`, `keychain-access-control.md`
**Difficulty:** MEDIUM

**Prompt (give this exact text to Claude):**
> Our app stores auth tokens in the keychain. We're adding a Today widget extension that needs to read these tokens. How do I share keychain items between the main app and the extension? Here's our current keychain code:
>
> ```swift
> actor TokenManager {
>     func save(token: String, account: String) throws {
>         let data = Data(token.utf8)
>         let query: [String: Any] = [
>             kSecClass as String: kSecClassGenericPassword,
>             kSecAttrService as String: "com.myapp.tokens",
>             kSecAttrAccount as String: account,
>             kSecValueData as String: data,
>             kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
>         ]
>         let status = SecItemAdd(query as CFDictionary, nil)
>         switch status {
>         case errSecSuccess: return
>         case errSecDuplicateItem:
>             let search: [String: Any] = [
>                 kSecClass as String: kSecClassGenericPassword,
>                 kSecAttrService as String: "com.myapp.tokens",
>                 kSecAttrAccount as String: account
>             ]
>             let updateStatus = SecItemUpdate(search as CFDictionary,
>                 [kSecValueData as String: data] as CFDictionary)
>             guard updateStatus == errSecSuccess else { throw KeychainError(status: updateStatus) }
>         default: throw KeychainError(status: status)
>         }
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Add `kSecAttrAccessGroup` with full Team ID prefix** — must specify `"TEAMID.com.myapp.shared"` (or use `$(AppIdentifierPrefix)` in entitlements). Without the Team ID prefix, the group won't resolve correctly on device.
2. **Configure `keychain-access-groups` entitlement** — both the main app target and the widget extension target need the same group in their `keychain-access-groups` entitlement.
3. **Consider accessibility for widget** — `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` may fail when the widget timeline updates while the device is locked. Recommend `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` for items the widget needs in background.
4. **Existing items need migration** — items already stored without `kSecAttrAccessGroup` live in the app's default group (application identifier). They must be read, re-saved with the new access group, and the old items deleted.
5. **macOS consideration** — if the app supports macOS, note that App Groups cannot be used as keychain access groups on macOS; only `keychain-access-groups` entitlement works cross-platform.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN cites the reference files in a `## Reference Files` section
- Total possible: 6

**Why this tests the skill (not just general knowledge):**
> The Team ID prefix requirement is a deployment-time failure that works in development. The existing item migration (items without access group must be re-saved) is a non-obvious requirement. The macOS caveat about App Groups not working for keychain sharing is rarely mentioned in tutorials.
