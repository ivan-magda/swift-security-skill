# Category 2: Multi-Domain Review Tests

Each test presents a larger code snippet or class (30–60 lines) spanning 2–4 domains. The prompt asks for a security review. These test whether the skill can catch issues that cross domain boundaries.

---

### Test M-1: KeychainManager with Biometrics, Threading, and Accessibility

**Category:** Multi-Domain Review
**Domains tested:** `keychain-fundamentals.md`, `keychain-access-control.md`, `biometric-authentication.md`
**Difficulty:** HARD

**Prompt (give this exact text to Claude):**
> Perform a security review of this KeychainManager that handles biometric-protected credentials:
>
> ```swift
> import SwiftUI
> import LocalAuthentication
>
> @MainActor
> class SecureCredentialManager: ObservableObject {
>     @Published var isUnlocked = false
>
>     func authenticateAndLoad() {
>         let context = LAContext()
>         context.evaluatePolicy(
>             .deviceOwnerAuthenticationWithBiometrics,
>             localizedReason: "Access your credentials"
>         ) { success, error in
>             DispatchQueue.main.async {
>                 if success {
>                     self.isUnlocked = true
>                     self.loadCredentials()
>                 }
>             }
>         }
>     }
>
>     private func loadCredentials() {
>         let query: [String: Any] = [
>             kSecClass as String: kSecClassGenericPassword,
>             kSecAttrService as String: "com.myapp.credentials",
>             kSecReturnData as String: true,
>             kSecMatchLimit as String: kSecMatchLimitAll
>         ]
>         var result: AnyObject?
>         let status = SecItemCopyMatching(query as CFDictionary, &result)
>         if status == errSecSuccess, let items = result as? [Data] {
>             processCredentials(items)
>         }
>     }
>
>     func saveCredential(account: String, password: Data) {
>         let query: [String: Any] = [
>             kSecClass as String: kSecClassGenericPassword,
>             kSecAttrService as String: "com.myapp.credentials",
>             kSecAttrAccount as String: account,
>             kSecValueData as String: password,
>             kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
>         ]
>         SecItemAdd(query as CFDictionary, nil)
>     }
>
>     private func processCredentials(_ items: [Data]) { /* ... */ }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Boolean gate biometric authentication (CRITICAL)** — `evaluatePolicy()` as sole gate; `isUnlocked` boolean controls access. Trivially bypassable with Frida. Must store credentials behind `SecAccessControl` with `.biometryCurrentSet` and retrieve via `SecItemCopyMatching`. (AI Mistake #1)
2. **All SecItem calls on `@MainActor` (HIGH)** — both `SecItemCopyMatching` and `SecItemAdd` execute on the main thread, blocking UI during `securityd` IPC. (Core Guideline #4)
3. **OSStatus ignored on `SecItemAdd`** — no handling for `errSecDuplicateItem`. Second save silently fails. (Core Guideline #1, #6)
4. **`kSecAttrAccessibleWhenUnlocked` without `ThisDeviceOnly`** — items migrate via encrypted backups. For credentials, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` is more appropriate. (Core Guideline #5)
5. **`loadCredentials` only handles `errSecSuccess`** — no handling for `errSecItemNotFound` or `errSecInteractionNotAllowed`. The latter is critical for data protection scenarios.
6. **No enrollment change detection** — no `evaluatedPolicyDomainState` check and no `.biometryCurrentSet` flag means a new biometric enrollment doesn't invalidate access.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN cites all three reference files
- Total possible: 7

**Why this tests the skill (not just general knowledge):**
> This code has interleaved issues across three domains. The boolean gate is embedded within a larger class that also has threading, accessibility, and error handling issues. An unassisted LLM may focus on one domain (e.g., biometrics) while missing cross-cutting concerns like `@MainActor` + `SecItem` calls.

---

### Test M-2: Secure Enclave Signing with ECDH and Keychain Persistence

**Category:** Multi-Domain Review
**Domains tested:** `secure-enclave.md`, `cryptokit-public-key.md`, `keychain-fundamentals.md`
**Difficulty:** HARD

**Prompt (give this exact text to Claude):**
> Review this signing service that uses Secure Enclave for document authentication and key agreement:
>
> ```swift
> import CryptoKit
> import Foundation
>
> actor SigningService {
>     private var signingKey: SecureEnclave.P256.Signing.PrivateKey?
>
>     func setupKeys(existingKeyData: Data?) throws {
>         if let keyData = existingKeyData {
>             // Restore key from backup
>             signingKey = try SecureEnclave.P256.Signing.PrivateKey(rawRepresentation: keyData)
>         } else {
>             guard SecureEnclave.isAvailable else { throw SEError.unavailable }
>             signingKey = try SecureEnclave.P256.Signing.PrivateKey()
>             // Persist key to keychain
>             persistKey(signingKey!.dataRepresentation)
>         }
>     }
>
>     func negotiateSharedKey(with peerPublicKey: P256.KeyAgreement.PublicKey) throws -> SymmetricKey {
>         let agreementKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
>         let sharedSecret = try agreementKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
>         return sharedSecret.withUnsafeBytes { SymmetricKey(data: $0) }
>     }
>
>     private func persistKey(_ keyData: Data) {
>         let query: [String: Any] = [
>             kSecClass as String: kSecClassGenericPassword,
>             kSecAttrService as String: "com.myapp.signing",
>             kSecAttrAccount as String: "se-signing-key",
>             kSecValueData as String: keyData
>         ]
>         SecItemAdd(query as CFDictionary, nil)
>     }
>
>     func sign(_ data: Data) throws -> P256.Signing.ECDSASignature {
>         guard let key = signingKey else { throw SEError.noKey }
>         return try key.signature(for: data)
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **`init(rawRepresentation:)` does not exist on SE types** — SE keys cannot be imported from raw key material. Only `init(dataRepresentation:)` with the opaque encrypted blob is valid. Comment says "restore from backup" but SE keys are device-bound and cannot be backed up. (AI Mistake #3)
2. **Missing simulator guard** — `SecureEnclave.isAvailable` without `#if !targetEnvironment(simulator)`. (AI Mistake #2)
3. **Raw shared secret used as symmetric key** — `sharedSecret.withUnsafeBytes` extracts raw bytes without HKDF derivation. Must use `sharedSecret.hkdfDerivedSymmetricKey(...)`. (AI Mistake #8)
4. **OSStatus ignored on keychain persist** — `SecItemAdd` return value discarded. Missing add-or-update pattern. (Core Guideline #1, #6)
5. **Missing `kSecAttrAccessible` on keychain persist** — SE key blob stored without explicit accessibility constant. (Core Guideline #5)

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN cites all three reference files
- Total possible: 6

**Why this tests the skill (not just general knowledge):**
> The SE key import issue and the raw ECDH pattern are both cases where the code looks plausible but relies on non-existent or misused APIs. Cross-domain interaction (SE + CryptoKit + keychain persistence) compounds the difficulty.

---

### Test M-3: UserDefaults Migration with Missing Cleanup

**Category:** Multi-Domain Review
**Domains tested:** `credential-storage-patterns.md`, `migration-legacy-stores.md`, `common-anti-patterns.md`
**Difficulty:** MEDIUM

**Prompt (give this exact text to Claude):**
> Review this migration code that moves tokens from UserDefaults to Keychain. It runs on every app launch:
>
> ```swift
> import Foundation
> import Security
>
> class TokenMigration {
>     static func migrateIfNeeded() {
>         // Check if legacy tokens exist
>         guard let accessToken = UserDefaults.standard.string(forKey: "auth_token"),
>               let refreshToken = UserDefaults.standard.string(forKey: "refresh_token") else {
>             return // Nothing to migrate
>         }
>
>         // Save to Keychain
>         saveToKeychain(key: "access_token", value: accessToken)
>         saveToKeychain(key: "refresh_token", value: refreshToken)
>
>         // Clean up legacy storage
>         UserDefaults.standard.removeObject(forKey: "auth_token")
>         // Note: refresh_token cleanup coming in next sprint
>     }
>
>     private static func saveToKeychain(key: String, value: String) {
>         let query: [String: Any] = [
>             kSecClass as String: kSecClassGenericPassword,
>             kSecAttrService as String: "com.myapp",
>             kSecAttrAccount as String: key,
>             kSecValueData as String: Data(value.utf8),
>             kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
>         ]
>         SecItemAdd(query as CFDictionary, nil)
>     }
> }
>
> // In AppDelegate:
> @main
> struct MyApp: App {
>     init() {
>         TokenMigration.migrateIfNeeded()
>     }
>     var body: some Scene {
>         WindowGroup { ContentView() }
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Incomplete legacy cleanup** — `refresh_token` is never removed from UserDefaults ("coming in next sprint"). The plaintext refresh token persists in unencrypted backups indefinitely. Legacy data must be deleted immediately after verified keychain write.
2. **Migration runs on every launch** — checks UserDefaults for legacy data each launch. On iOS 15+, app pre-warming can launch the process before the device is unlocked, causing UserDefaults to return empty values (encrypted plist inaccessible). The migration interprets this as "nothing to migrate" and skips real data. Should use a versioned migration flag.
3. **Missing first-launch keychain cleanup** — no `hasLaunchedBefore` check. Stale keychain items from a previous installation persist after uninstall/reinstall, potentially causing the migration to overwrite valid post-reinstall state or leave orphaned credentials. (AI Mistake #10)
4. **`SecItemAdd` without `errSecDuplicateItem` handling** — if migration runs again (e.g., after pre-warming skipped it), the second add silently fails. (Core Guideline #6; AI Mistake #6)
5. **Non-atomic migration** — keychain write and UserDefaults delete are separate operations. If the app is killed between them, data is in an inconsistent state.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN cites all three reference files
- Total possible: 6

**Why this tests the skill (not just general knowledge):**
> The pre-warming trap (iOS 15+) and the first-launch cleanup requirement are non-obvious domain-specific knowledge. An LLM may catch the incomplete cleanup but miss the pre-warming vulnerability and the atomic migration requirement.

---

### Test M-4: App Group Keychain Sharing with Wrong Access Group

**Category:** Multi-Domain Review
**Domains tested:** `keychain-sharing.md`, `keychain-access-control.md`, `keychain-item-classes.md`
**Difficulty:** MEDIUM

**Prompt (give this exact text to Claude):**
> Review this shared keychain setup between our main app and Today widget extension:
>
> ```swift
> // Shared constants file (used by both targets)
> enum SharedKeychain {
>     static let accessGroup = "com.myapp.shared"  // In both entitlements files
>     static let service = "shared-credentials"
> }
>
> // Main App — saves user session
> func saveSessionForWidget(session: SessionData) throws {
>     let encoded = try JSONEncoder().encode(session)
>     let query: [String: Any] = [
>         kSecClass as String: kSecClassKey,
>         kSecAttrAccessGroup as String: SharedKeychain.accessGroup,
>         kSecAttrService as String: SharedKeychain.service,
>         kSecAttrAccount as String: "userSession",
>         kSecValueData as String: encoded,
>         kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
>         kSecAttrSynchronizable as String: true
>     ]
>     let status = SecItemAdd(query as CFDictionary, nil)
>     guard status == errSecSuccess || status == errSecDuplicateItem else {
>         throw KeychainError(status: status)
>     }
> }
>
> // Widget Extension — reads user session
> func loadSessionForWidget() -> SessionData? {
>     let query: [String: Any] = [
>         kSecClass as String: kSecClassKey,
>         kSecAttrAccessGroup as String: SharedKeychain.accessGroup,
>         kSecAttrService as String: SharedKeychain.service,
>         kSecReturnData as String: true,
>         kSecMatchLimit as String: kSecMatchLimitOne
>     ]
>     var result: AnyObject?
>     let status = SecItemCopyMatching(query as CFDictionary, &result)
>     guard status == errSecSuccess, let data = result as? Data else { return nil }
>     return try? JSONDecoder().decode(SessionData.self, from: data)
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Access group missing Team ID prefix** — `"com.myapp.shared"` must be `"TEAMID.com.myapp.shared"` (e.g., `"SKMME9E2Y8.com.myapp.shared"`). Without the Team ID prefix, the access group won't match between targets on device. The `$(AppIdentifierPrefix)` build variable resolves this at signing time.
2. **Wrong `kSecClass` for session data** — `kSecClassKey` is for cryptographic keys (`SecKey`), not arbitrary data. Session data encoded as JSON should use `kSecClassGenericPassword`. The `kSecAttrService` and `kSecAttrAccount` attributes are specific to password classes, not key class.
3. **`kSecAttrSynchronizable: true` with `ThisDeviceOnly` accessibility** — contradictory constraints. `ThisDeviceOnly` prevents iCloud sync while `kSecAttrSynchronizable` requests it. Behavior is undefined. Remove `kSecAttrSynchronizable` for device-bound items.
4. **Duplicate handling incomplete** — `errSecDuplicateItem` is detected but no update is performed. The existing item retains its old value. Must use add-or-update pattern. (Core Guideline #6)
5. **Widget may need background access** — `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` may fail for widget timeline updates that happen while the device is locked. Consider `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN cites all three reference files
- Total possible: 6

**Why this tests the skill (not just general knowledge):**
> The missing Team ID prefix is a deployment-time failure that works in development (Xcode auto-fills it). The `kSecClassKey` + password attributes mismatch is subtle — it may work on the data protection keychain but is semantically incorrect. The synchronizable + ThisDeviceOnly contradiction requires knowing both attributes' semantics.

---

### Test M-5: Certificate Pinning with Token Storage and Legacy API

**Category:** Multi-Domain Review
**Domains tested:** `certificate-trust.md`, `credential-storage-patterns.md`, `compliance-owasp-mapping.md`
**Difficulty:** HARD

**Prompt (give this exact text to Claude):**
> Review this banking app's network security layer for OWASP MASVS compliance:
>
> ```swift
> import Foundation
> import Security
>
> class BankingNetworkManager: NSObject, URLSessionDelegate {
>     private var bearerToken: String?
>     private let pinnedCertData: Data  // Loaded from bundle .cer file
>
>     init(certificateName: String) {
>         let certURL = Bundle.main.url(forResource: certificateName, withExtension: "cer")!
>         pinnedCertData = try! Data(contentsOf: certURL)
>     }
>
>     func urlSession(_ session: URLSession,
>                     didReceive challenge: URLAuthenticationChallenge,
>                     completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
>         guard let serverTrust = challenge.protectionSpace.serverTrust else {
>             completionHandler(.cancelAuthenticationChallenge, nil)
>             return
>         }
>
>         var result: SecTrustResultType = .invalid
>         SecTrustEvaluate(serverTrust, &result)
>
>         guard result == .unspecified || result == .proceed else {
>             completionHandler(.cancelAuthenticationChallenge, nil)
>             return
>         }
>
>         // Pin against leaf certificate
>         let serverCertData = SecCertificateCopyData(
>             SecTrustGetCertificateAtIndex(serverTrust, 0)!) as Data
>         if serverCertData == pinnedCertData {
>             completionHandler(.useCredential, URLCredential(trust: serverTrust))
>         } else {
>             completionHandler(.cancelAuthenticationChallenge, nil)
>         }
>     }
>
>     func authenticate(username: String, password: String) async throws {
>         let (data, _) = try await URLSession.shared.data(for: authRequest(username, password))
>         let response = try JSONDecoder().decode(AuthResponse.self, from: data)
>         bearerToken = response.accessToken
>     }
>
>     func makeAuthenticatedRequest(_ request: URLRequest) async throws -> Data {
>         var req = request
>         req.setValue("Bearer \(bearerToken ?? "")", forHTTPHeaderField: "Authorization")
>         let (data, _) = try await URLSession.shared.data(for: req)
>         return data
>     }
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **`SecTrustEvaluate` is deprecated (iOS 13)** — returns opaque `SecTrustResultType` without error context. Must use `SecTrustEvaluateWithError` (iOS 12+, synchronous, valid in delegate) or `SecTrustEvaluateAsyncWithError` (iOS 13+, async).
2. **Leaf certificate pinning breaks on renewal** — comparing raw certificate bytes means the pin breaks when the server renews its TLS certificate (every 90–398 days). Must use SPKI hash pinning (survives renewal with same key pair) or `NSPinnedDomains` (iOS 14+, declarative).
3. **`SecTrustGetCertificateAtIndex` is deprecated** — deprecated in iOS 15. Use `SecTrustCopyCertificateChain` (iOS 15+) instead.
4. **Bearer token stored only in memory** — `bearerToken` is a plain property that's lost on app termination. For a banking app, this means re-authentication on every launch. Should be stored in Keychain with appropriate accessibility.
5. **No logout cleanup** — no method to clear `bearerToken` or any keychain items on logout. (Credential lifecycle issue)
6. **`URLSession.shared` used with custom delegate** — `URLSession.shared` ignores delegates. The pinning delegate is never called. Must create a custom `URLSession(configuration:delegate:delegateQueue:)`.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentioned but wrong detail
- 0 points if missed entirely
- Bonus point (+1) if GREEN cites all three reference files
- Total possible: 7

**Why this tests the skill (not just general knowledge):**
> The leaf pinning vs SPKI pinning distinction requires certificate trust domain knowledge. The `URLSession.shared` ignoring delegates is a subtle networking bug that interacts with the security review. The deprecated API chain (`SecTrustEvaluate` + `SecTrustGetCertificateAtIndex`) represents accumulated technical debt that requires knowing which alternatives exist and at which iOS versions.
