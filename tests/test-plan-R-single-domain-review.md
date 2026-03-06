# Category 1: Single-Domain Review Tests

Each test presents a realistic Swift code snippet (15–40 lines) containing 2–4 intentional bugs or anti-patterns from a single domain. The prompt asks Claude to review the code. Together, these 8 tests cover all 10 Common AI Mistakes from SKILL.md.

---

### Test R-1: Keychain CRUD with Ignored Errors and MainActor

**Category:** Single-Domain Review
**Domains tested:** `keychain-fundamentals.md`
**Difficulty:** EASY

**Prompt (give this exact text to Claude):**
> Review this keychain helper class for security issues:
>
> ```swift
> import SwiftUI
>
> @MainActor
> class TokenStore: ObservableObject {
>     @Published var isLoggedIn = false
>
>     func saveToken(_ token: String) {
>         let data = Data(token.utf8)
>         let query: [String: Any] = [
>             kSecClass as String: kSecClassGenericPassword,
>             kSecAttrService as String: "com.myapp.auth",
>             kSecAttrAccount as String: "accessToken",
>             kSecValueData as String: data
>         ]
>         SecItemAdd(query as CFDictionary, nil)
>     }
>
>     func loadToken() -> String? {
>         let query: [String: Any] = [
>             kSecClass as String: kSecClassGenericPassword,
>             kSecAttrService as String: "com.myapp.auth",
>             kSecAttrAccount as String: "accessToken",
>             kSecReturnData as String: true,
>             kSecMatchLimit as String: kSecMatchLimitOne
>         ]
>         var result: AnyObject?
>         SecItemCopyMatching(query as CFDictionary, &result)
>         guard let data = result as? Data else { return nil }
>         isLoggedIn = true
>         return String(data: data, encoding: .utf8)
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **OSStatus ignored on `SecItemAdd`** — return value discarded; if item exists, `errSecDuplicateItem` goes unhandled and the token silently fails to save. Must use add-or-update pattern. (Core Guideline #1, #6; AI Mistake #6)
2. **OSStatus ignored on `SecItemCopyMatching`** — no error handling for `errSecItemNotFound` or `errSecInteractionNotAllowed`. (Core Guideline #1)
3. **All SecItem calls on `@MainActor`** — `SecItemAdd` and `SecItemCopyMatching` are IPC round-trips to `securityd` that block the main thread. Must use a dedicated `actor` or background queue. (Core Guideline #4)
4. **Missing `kSecAttrAccessible`** — no accessibility constant specified in `SecItemAdd`. System defaults to `kSecAttrAccessibleWhenUnlocked`, which is invisible in code review and breaks background operations. (Core Guideline #5; AI Mistake #5)

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail (e.g., names the wrong default accessibility constant)
- 0 points if missed entirely
- Bonus point (+1) if GREEN correctly cites `keychain-fundamentals.md`
- Total possible: 5

**Why this tests the skill (not just general knowledge):**
> LLMs commonly generate this exact pattern. Without the skill, Claude may catch the ignored return value but miss the `@MainActor` issue (which requires knowing `SecItem*` does IPC) and the missing accessibility constant (which requires knowing the implicit default is problematic).

---

### Test R-2: Wrong kSecClass for Web Credentials

**Category:** Single-Domain Review
**Domains tested:** `keychain-item-classes.md`
**Difficulty:** MEDIUM

**Prompt (give this exact text to Claude):**
> Review this credential manager that stores website login credentials for AutoFill:
>
> ```swift
> struct WebCredential {
>     let username: String
>     let password: String
>     let website: String
> }
>
> func saveWebCredential(_ credential: WebCredential) throws {
>     let query: [String: Any] = [
>         kSecClass as String: kSecClassGenericPassword,
>         kSecAttrServer as String: credential.website,
>         kSecAttrLabel as String: "Login for \(credential.website)",
>         kSecValueData as String: Data(credential.password.utf8),
>         kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
>     ]
>     let status = SecItemAdd(query as CFDictionary, nil)
>     switch status {
>     case errSecSuccess: return
>     case errSecDuplicateItem:
>         let update = [kSecValueData as String: Data(credential.password.utf8)]
>         let searchQuery: [String: Any] = [
>             kSecClass as String: kSecClassGenericPassword,
>             kSecAttrServer as String: credential.website
>         ]
>         let updateStatus = SecItemUpdate(searchQuery as CFDictionary, update as CFDictionary)
>         guard updateStatus == errSecSuccess else { throw KeychainError(status: updateStatus) }
>     default: throw KeychainError(status: status)
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Wrong `kSecClass` for web credentials** — uses `kSecClassGenericPassword` with `kSecAttrServer`, but `kSecAttrServer` is an `InternetPassword` attribute. GenericPassword ignores `kSecAttrServer` on the data protection keychain (or errors on legacy macOS keychain). Web credentials must use `kSecClassInternetPassword` for Password AutoFill to work. (Anti-Pattern Quick Scan table)
2. **Missing `kSecAttrAccount`** — no username stored. For InternetPassword, `kSecAttrAccount` is part of the composite primary key. Without it, all credentials for the same server collide. For GenericPassword, both `kSecAttrService` and `kSecAttrAccount` are needed.
3. **`kSecAttrLabel` is not a primary key attribute** — using it as an identifier is misleading; it does not participate in uniqueness for any kSecClass. The search query also relies only on `kSecAttrServer` which is meaningless for GenericPassword.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN correctly cites `keychain-item-classes.md`
- Total possible: 4

**Why this tests the skill (not just general knowledge):**
> The GenericPassword + `kSecAttrServer` mismatch is a subtle bug that the data protection keychain silently ignores. Without the skill's explicit table mapping this as a MEDIUM finding, an LLM may not flag it. The composite primary key rules are non-obvious and rarely covered in tutorials.

---

### Test R-3: Broken Accessibility for Background Fetch

**Category:** Single-Domain Review
**Domains tested:** `keychain-access-control.md`
**Difficulty:** MEDIUM

**Prompt (give this exact text to Claude):**
> Review this background task handler that refreshes tokens. Users report it works in foreground but fails silently during background app refresh:
>
> ```swift
> actor BackgroundTokenRefresher {
>     func refreshTokenIfNeeded() async throws -> String {
>         // Read current token
>         let readQuery: [String: Any] = [
>             kSecClass as String: kSecClassGenericPassword,
>             kSecAttrService as String: "com.myapp.auth",
>             kSecAttrAccount as String: "refreshToken",
>             kSecReturnData as String: true,
>             kSecMatchLimit as String: kSecMatchLimitOne
>         ]
>         var result: AnyObject?
>         let status = SecItemCopyMatching(readQuery as CFDictionary, &result)
>         guard status == errSecSuccess, let tokenData = result as? Data else {
>             throw TokenError.notFound
>         }
>
>         let newToken = try await networkService.refresh(token: String(data: tokenData, encoding: .utf8)!)
>
>         // Save new token
>         let saveQuery: [String: Any] = [
>             kSecClass as String: kSecClassGenericPassword,
>             kSecAttrService as String: "com.myapp.auth",
>             kSecAttrAccount as String: "refreshToken",
>             kSecAttrAccessible as String: kSecAttrAccessibleAlways,
>             kSecValueData as String: Data(newToken.utf8)
>         ]
>         SecItemDelete([kSecClass as String: kSecClassGenericPassword,
>                        kSecAttrService as String: "com.myapp.auth",
>                        kSecAttrAccount as String: "refreshToken"] as CFDictionary)
>         let addStatus = SecItemAdd(saveQuery as CFDictionary, nil)
>         guard addStatus == errSecSuccess else { throw TokenError.saveFailed }
>         return newToken
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **`kSecAttrAccessibleAlways` is deprecated** (iOS 12) — must migrate to a non-deprecated constant. (Core Guideline #5; AI Mistake #5)
2. **Background fetch with wrong accessibility** — the read query has no explicit `kSecAttrAccessible`, inheriting whatever the item was stored with. If the item was stored with `WhenUnlocked` (the default), reads fail when the device is locked during background refresh. Must use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` for background-safe operations.
3. **Delete-then-add anti-pattern** — deletes the item then re-adds instead of using add-or-update. Creates a race window and destroys persistent references. (Core Guideline #6)
4. **OSStatus of `SecItemDelete` ignored** — the delete call's return is not checked; if it fails, the subsequent add may also fail or produce duplicates.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN correctly cites `keychain-access-control.md`
- Total possible: 5

**Why this tests the skill (not just general knowledge):**
> The connection between accessibility constants and background fetch failures requires domain-specific knowledge. An unassisted LLM may spot the deprecated constant but miss that `WhenUnlocked` is the wrong choice for background operations, or not flag the delete-then-add as an anti-pattern.

---

### Test R-4: Boolean Gate Biometric Authentication

**Category:** Single-Domain Review
**Domains tested:** `biometric-authentication.md`
**Difficulty:** EASY

**Prompt (give this exact text to Claude):**
> Review this biometric authentication implementation for security:
>
> ```swift
> import LocalAuthentication
>
> class BiometricAuthManager {
>     private var isAuthenticated = false
>
>     func authenticate() async -> Bool {
>         let context = LAContext()
>         var error: NSError?
>
>         guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
>             return false
>         }
>
>         do {
>             let success = try await context.evaluatePolicy(
>                 .deviceOwnerAuthenticationWithBiometrics,
>                 localizedReason: "Unlock your vault"
>             )
>             isAuthenticated = success
>             return success
>         } catch {
>             return false
>         }
>     }
>
>     func getSecureData() -> SensitiveData? {
>         guard isAuthenticated else { return nil }
>         return loadFromDatabase()
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Boolean gate vulnerability (CRITICAL)** — `evaluatePolicy()` returns a `Bool` in hookable user-space memory. Frida/objection can force `success = true` with one command (`ios ui biometrics_bypass`). No cryptographic material is involved. Must use keychain-bound biometrics: store a secret behind `SecAccessControl` with `.biometryCurrentSet`, retrieve via `SecItemCopyMatching`. (Core Guideline #2; AI Mistake #1)
2. **No enrollment change detection** — no use of `evaluatedPolicyDomainState` to detect biometric enrollment changes (e.g., attacker enrolling their own Face ID). The `.biometryCurrentSet` flag in the secure pattern handles this automatically by invalidating the keychain item.
3. **`isAuthenticated` flag stored as a plain property** — a mutable boolean controlling access to sensitive data is the exact pattern that makes the boolean gate exploitable. The secure pattern eliminates this flag entirely — data is gated by keychain access, not a boolean.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN correctly cites `biometric-authentication.md`
- Total possible: 4

**Why this tests the skill (not just general knowledge):**
> This is the #1 most dangerous AI-generated pattern. An unassisted LLM may recognize "biometrics should be more secure" but frequently fails to articulate the specific bypass mechanism (Frida/objection), the exact fix (keychain-bound with `SecAccessControl`), or the enrollment change detection requirement.

---

### Test R-5: Secure Enclave Misuse Trifecta

**Category:** Single-Domain Review
**Domains tested:** `secure-enclave.md`
**Difficulty:** HARD

**Prompt (give this exact text to Claude):**
> Review this Secure Enclave signing service:
>
> ```swift
> import CryptoKit
> import Foundation
>
> class DocumentSigner {
>     private var signingKey: SecureEnclave.P256.Signing.PrivateKey?
>
>     func importKey(from keyData: Data) throws {
>         signingKey = try SecureEnclave.P256.Signing.PrivateKey(rawRepresentation: keyData)
>     }
>
>     func generateKey() throws {
>         guard SecureEnclave.isAvailable else {
>             throw SigningError.noSecureEnclave
>         }
>         signingKey = try SecureEnclave.P256.Signing.PrivateKey()
>     }
>
>     func sign(_ document: Data) throws -> Data {
>         guard let key = signingKey else { throw SigningError.noKey }
>         let signature = try key.signature(for: document)
>         return signature.rawRepresentation
>     }
>
>     func encryptWithSE(_ plaintext: Data, for recipientPublicKey: P256.KeyAgreement.PublicKey) throws -> Data {
>         let seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
>         let sharedSecret = try seKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)
>         let symmetricKey = try SecureEnclave.AES.GCM.seal(plaintext, using: sharedSecret)
>         return symmetricKey.combined!
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Importing external key into Secure Enclave** — `SecureEnclave.P256.Signing.PrivateKey(rawRepresentation:)` does not exist. SE keys must be generated inside the hardware. Only `init(dataRepresentation:)` exists, accepting the opaque encrypted blob from a previously created SE key. This will not compile. (AI Mistake #3)
2. **Missing simulator guard** — `SecureEnclave.isAvailable` check without `#if !targetEnvironment(simulator)`. On simulators with T2/M-series host Macs, `isAvailable` may return `true` but key generation fails at runtime. Must use compile-time `#if targetEnvironment(simulator)` guard. (AI Mistake #2)
3. **Non-existent `SecureEnclave.AES.GCM` API** — the SE's internal AES engine is not exposed as a developer API. There is no `SecureEnclave.AES`. Pre-iOS 26, SE supports only P256 signing and key agreement. Must derive a `SymmetricKey` via ECDH + HKDF, then use `AES.GCM.seal` from regular CryptoKit. (AI Mistake #4)
4. **Raw shared secret used without HKDF** — even if the encryption API existed, the code passes the raw shared secret directly. `SharedSecret` must be derived through `hkdfDerivedSymmetricKey(...)` before use. (AI Mistake #8)

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN correctly cites `secure-enclave.md`
- Total possible: 5

**Why this tests the skill (not just general knowledge):**
> All three SE mistakes (#2, #3, #4) are patterns that AI assistants generate because they extrapolate API surfaces that don't exist. Without the skill's explicit "these APIs do not exist" guidance, an LLM may not recognize that `SecureEnclave.AES.GCM` is fabricated or that `init(rawRepresentation:)` is invalid for SE types.

---

### Test R-6: AES-GCM Nonce Reuse and Insecure Hashing

**Category:** Single-Domain Review
**Domains tested:** `cryptokit-symmetric.md`
**Difficulty:** MEDIUM

**Prompt (give this exact text to Claude):**
> Review this encryption utility for a messaging app:
>
> ```swift
> import CryptoKit
> import Foundation
>
> class MessageEncryptor {
>     private let key: SymmetricKey
>     private var messageCounter: UInt64 = 0
>
>     init(key: SymmetricKey) {
>         self.key = key
>     }
>
>     func encryptBatch(_ messages: [Data]) throws -> [Data] {
>         return try messages.map { message in
>             messageCounter += 1
>             var nonceBytes = Data(count: 12)
>             withUnsafeMutableBytes(of: &messageCounter) { src in
>                 nonceBytes.replaceSubrange(0..<8, with: src)
>             }
>             let nonce = try AES.GCM.Nonce(data: nonceBytes)
>             let sealed = try AES.GCM.seal(message, using: key, nonce: nonce)
>             return sealed.combined!
>         }
>     }
>
>     func computeIntegrity(of data: Data) -> String {
>         let hash = Insecure.MD5.hash(data: data)
>         return hash.map { String(format: "%02x", $0) }.joined()
>     }
>
>     func verifyHash(_ data: Data, expected: String) -> Bool {
>         return computeIntegrity(of: data) == expected
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Explicit nonce construction in a loop (CRITICAL)** — counter-based nonce that resets on app restart creates collision risk. If the app is killed and relaunched, `messageCounter` resets to 0 and the same nonce-key pairs are reused, enabling plaintext recovery via `C1 XOR C2 = P1 XOR P2`. CryptoKit auto-generates random nonces when the parameter is omitted — always prefer this. (AI Mistake #7)
2. **`Insecure.MD5` used for integrity checking** — MD5 is cryptographically broken (collision attacks since 2005). The `Insecure` namespace signals this explicitly. Must use `SHA256` minimum for integrity verification. (Anti-Pattern #7 in `common-anti-patterns.md`)
3. **Non-constant-time hash comparison** — `computeIntegrity(...) == expected` uses Swift's default string equality, which may not be constant-time. CryptoKit's digest equality (`==` on `Digest` types) is constant-time, but comparing hex strings is not. Should use `HMAC` for message authentication with built-in constant-time verification.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN correctly cites `cryptokit-symmetric.md`
- Total possible: 4

**Why this tests the skill (not just general knowledge):**
> The counter-based nonce looks reasonable at first glance — it increments per message. The key insight that it resets on app restart requires understanding CryptoKit's design philosophy of auto-random nonces. The MD5 issue is easier but the `Insecure` namespace detail and the HMAC alternative require domain knowledge.

---

### Test R-7: Raw ECDH and Wrong HPKE Version

**Category:** Single-Domain Review
**Domains tested:** `cryptokit-public-key.md`
**Difficulty:** HARD

**Prompt (give this exact text to Claude):**
> Review this end-to-end encryption implementation:
>
> ```swift
> import CryptoKit
>
> class E2EEncryption {
>     let privateKey = Curve25519.KeyAgreement.PrivateKey()
>
>     /// Encrypt a message for a recipient using ECDH
>     func encrypt(_ message: Data, for recipientPublicKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
>         let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: recipientPublicKey)
>
>         // Use the shared secret directly as the encryption key
>         let key = sharedSecret.withUnsafeBytes { SymmetricKey(data: $0) }
>         let sealed = try AES.GCM.seal(message, using: key)
>         return sealed.combined!
>     }
>
>     /// Modern HPKE encryption (iOS 15+)
>     @available(iOS 15.0, *)
>     func encryptWithHPKE(_ message: Data, for recipientPublicKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
>         var sender = try HPKE.Sender(
>             recipientKey: recipientPublicKey,
>             ciphersuite: .Curve25519_SHA256_ChachaPoly,
>             info: Data("my-app-e2ee".utf8)
>         )
>         return try sender.seal(message)
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Raw ECDH shared secret used as symmetric key (HIGH)** — `sharedSecret.withUnsafeBytes` extracts raw bytes without key derivation. Per `cryptokit-public-key.md`: "`SharedSecret` is not uniformly distributed and must never be used directly as an encryption key. The only sanctioned paths are `.hkdfDerivedSymmetricKey()` or `.x963DerivedSymmetricKey()`." The forced extraction via `withUnsafeBytes` compiles but produces non-uniform key material with no domain separation and no salt. Must derive via `sharedSecret.hkdfDerivedSymmetricKey(using:sharedInfo:outputByteCount:)`. (AI Mistake #8)
2. **Wrong iOS version for HPKE** — `@available(iOS 15.0, *)` is incorrect. HPKE requires **iOS 17+**. Claiming iOS 15 will compile but crash at runtime on iOS 15–16. (AI Mistake #9 — version error; SKILL.md Version Baseline table)
3. **Missing `encapsulatedKey` in HPKE sender output** — `HPKE.Sender` produces both sealed data and an `encapsulatedKey` that must be transmitted to the recipient. The code discards it, making decryption impossible.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail (e.g., says HPKE is iOS 16+ instead of 17+)
- 0 points if missed entirely
- Bonus point (+1) if GREEN correctly cites `cryptokit-public-key.md`
- Total possible: 4

**Why this tests the skill (not just general knowledge):**
> The raw ECDH pattern compiles and appears to work — the `withUnsafeBytes` extraction produces a key that encrypts data without errors, but the key material is non-uniformly distributed. Recognizing this requires knowing CryptoKit's `SharedSecret` design intent from `cryptokit-public-key.md`. The HPKE version error (15 vs 17) is a common AI hallucination that the skill's Version Baseline table directly corrects. The missing encapsulated key requires understanding the HPKE protocol flow.

---

### Test R-8: Insecure Token Storage and Missing Cleanup

**Category:** Single-Domain Review
**Domains tested:** `credential-storage-patterns.md`
**Difficulty:** EASY

**Prompt (give this exact text to Claude):**
> Review this authentication manager for an OAuth2 app:
>
> ```swift
> import Foundation
>
> class AuthManager {
>     static let shared = AuthManager()
>
>     func saveTokens(accessToken: String, refreshToken: String) {
>         UserDefaults.standard.set(accessToken, forKey: "access_token")
>         UserDefaults.standard.set(refreshToken, forKey: "refresh_token")
>         UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: "token_timestamp")
>     }
>
>     func getAccessToken() -> String? {
>         return UserDefaults.standard.string(forKey: "access_token")
>     }
>
>     func getRefreshToken() -> String? {
>         return UserDefaults.standard.string(forKey: "refresh_token")
>     }
>
>     func isTokenExpired() -> Bool {
>         let timestamp = UserDefaults.standard.double(forKey: "token_timestamp")
>         return Date().timeIntervalSince1970 - timestamp > 3600
>     }
>
>     func logout() {
>         UserDefaults.standard.removeObject(forKey: "access_token")
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Tokens stored in UserDefaults (CRITICAL)** — `UserDefaults` writes plaintext XML plist readable from unencrypted backups and jailbroken devices. Must use Keychain with explicit `kSecAttrAccessible`. (Core Guideline #3; Anti-Pattern #1)
2. **Incomplete logout cleanup** — `logout()` removes only `access_token` but leaves `refresh_token` and `token_timestamp` in UserDefaults. A refresh token is more powerful than an access token — it can generate new access tokens. Must delete all credential artifacts on logout.
3. **Correct replacement must include first-launch keychain cleanup** — this code must be migrated to Keychain (catch #1). When implementing the keychain-based replacement, it must include first-launch cleanup: keychain items survive app uninstallation, so a reinstalled app inherits stale credentials from a previous install. Per `common-anti-patterns.md` #9: check a UserDefaults flag and `SecItemDelete` across all five kSecClass types on first launch, before any SDK initialization. (AI Mistake #10)
4. **No refresh token rotation** — the app stores a refresh token but has no mechanism to rotate it after use. Modern OAuth2 with Refresh Token Rotation (RTR) requires single-use refresh tokens; reuse triggers token family revocation.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN correctly cites `credential-storage-patterns.md`
- Total possible: 5

**Why this tests the skill (not just general knowledge):**
> While UserDefaults for tokens is a well-known issue, the incomplete logout cleanup (leaving refresh token) and the first-launch keychain cleanup pattern are non-obvious. An unassisted LLM will likely catch the UserDefaults issue but miss the logout incompleteness and the first-launch cleanup requirement.
