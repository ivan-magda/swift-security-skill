# Credential Storage Patterns

> Scope: Secure lifecycle patterns for client-side credentials on Apple platforms, including storage, refresh, rotation, migration, and logout cleanup.

The iOS Keychain is the only Apple-sanctioned storage mechanism for OAuth tokens, API keys, passwords, and other credentials. Cybernews found in 2025 that 71% of iOS apps leak at least one hardcoded secret — primarily through `UserDefaults`, `Info.plist`, or `.xcconfig` files that produce plaintext artifacts trivially extractable from device backups or IPA bundles. This reference covers the complete credential lifecycle: secure storage via Keychain Services, OAuth2/OIDC authentication flows, atomic token refresh with rotation, runtime secret fetching, key rotation strategies, and comprehensive logout cleanup.

Authoritative sources: Apple Developer Documentation (Keychain Services, Authentication Services), Apple Platform Security Guide (December 2024), WWDC 2019 Session 516 "What's New in Authentication", WWDC 2021 Session 10105 "Secure login with iCloud Keychain verification codes", WWDC 2024 Session 10125 "Streamline sign-in with passkey upgrades and credential managers", OWASP Mobile Top 10 2024, MASVS v2.1.0 (January 2024), MASTG v2, CISA/FBI "Product Security Bad Practices" advisory v2.0 (January 2025), and the Cybernews iOS app security research (March 2025).

---

## The Six Anti-Patterns AI Code Generators Reproduce

AI coding assistants routinely generate insecure credential handling. Each anti-pattern below is documented with evidence, an incorrect code sample, and the correct alternative.

### Anti-Pattern 1 — Tokens in UserDefaults

`UserDefaults` writes an unencrypted XML plist at `/var/mobile/Containers/Data/Application/{APP_ID}/Library/Preferences/{BUNDLE_ID}.plist`. This file is included in iTunes/Finder device backups, readable with iMazing or iExplorer on non-jailbroken devices, and trivially extractable on jailbroken devices via `objection`'s `ios nsuserdefaults get` command. Apple's documentation is explicit: the defaults system stores information on disk in an unencrypted format and must not be used for personal or sensitive information.

```swift
// ❌ INCORRECT — AI-generated token storage in UserDefaults
// Tokens are written as plaintext XML plist, readable from device backups
func saveTokens(accessToken: String, refreshToken: String) {
    UserDefaults.standard.set(accessToken, forKey: "access_token")
    UserDefaults.standard.set(refreshToken, forKey: "refresh_token")
}
```

**OWASP mapping:** Violates M9 (Insecure Data Storage), MASVS-STORAGE-1, MASWE-0002, and fails MASTG-TEST-0300/0301.

> For the canonical ❌/✅ code samples, objection detection commands, and full remediation checklist for this pattern, see `common-anti-patterns.md` § Anti-Pattern #1 — Storing Secrets in UserDefaults.

### Anti-Pattern 2 — Hardcoded API Keys in Source Code

CISA and the FBI classify hardcoded credentials as a formal "bad security practice" (CWE-798, ranked in 2024 CWE Top 25). The Cybernews research team found 815,000+ hardcoded secrets across 156,080 iOS apps simply by unzipping IPA files and scanning plaintext — no decompilation required.

```swift
// ❌ INCORRECT — Hardcoded API key discoverable via `strings` on the Mach-O binary
struct APIConfig {
    static let stripeSecretKey = "sk_live_51ABC123DEF456..."
    static let firebaseAPIKey = "AIzaSyB1234567890abcdefg"
}
// Attacker runs: strings MyApp.app/MyApp | grep "sk_live"
```

**OWASP mapping:** Violates M1 (Improper Credential Usage), MASWE-0005, and CISA/FBI advisory item #8.

### Anti-Pattern 3 — Production Secrets in .xcconfig

The `.xcconfig` pattern solves only the git-commit problem. When you reference `$(MY_API_KEY)` in Info.plist, Xcode resolves the variable at build time and embeds the literal plaintext value in the compiled Info.plist inside the `.app` bundle. Extraction takes seconds: rename `.ipa` to `.zip`, unzip, open Info.plist.

```swift
// ❌ INCORRECT — .xcconfig value compiled into Info.plist as plaintext
// In Secrets.xcconfig:  MAPS_API_KEY = gm_pk_a1b2c3d4e5f6g7h8i9
// In Info.plist:         <key>MapsAPIKey</key><string>$(MAPS_API_KEY)</string>

let apiKey = Bundle.main.infoDictionary?["MapsAPIKey"] as? String
// Attacker: unzip App.ipa && plutil -p Payload/App.app/Info.plist | grep Maps
```

### Anti-Pattern 4 — Missing kSecAttrAccessible Specification

When you add a Keychain item without specifying `kSecAttrAccessible`, the system applies the default: `kSecAttrAccessibleWhenUnlocked` (iOS 4.0+). While reasonable, this default allows Keychain items to migrate to new devices via encrypted backups and treats devices without a passcode as "always unlocked." Explicitly setting `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` prevents backup migration and confines the credential to the original hardware.

### Anti-Pattern 5 — Non-Atomic Token Refresh

When an access token expires, the app must delete the old token and store the new one. If the app crashes between these operations, the Keychain enters an inconsistent state. Concurrent refresh attempts compound the problem: two threads can both detect expiry, both call the refresh endpoint, and one writes a stale or already-rotated refresh token. With Refresh Token Rotation (RTR), this race can invalidate the entire token family.

### Anti-Pattern 6 — Incomplete Credential Clearing on Logout

The most common partial-cleanup bug is deleting the access token while leaving the refresh token in the Keychain. A refresh token is often longer-lived and more powerful — it can silently generate new access tokens.

```swift
// ❌ INCORRECT — Partial cleanup leaves refresh token behind
func logout() {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.myapp.auth",
        kSecAttrAccount as String: "access_token"
    ]
    SecItemDelete(query as CFDictionary)
    // BUG: refresh_token, user_profile, cached API keys all remain
}
```

### Correct Baseline for Credential Storage

✅ Store credentials in Keychain, not `UserDefaults`/plist/source literals.
✅ Set `kSecAttrAccessible` explicitly for each item based on access pattern.
✅ Use add-or-update semantics and handle all `OSStatus` outcomes.
✅ Delete all credential artifacts (access token, refresh token, derived caches) on logout.

---

## Data Protection Class Selection for Credentials

Choosing the correct `kSecAttrAccessible` value is the highest-ROI decision for credential confidentiality. The Keychain encrypts items using dual AES-256-GCM keys: a metadata key (cached for fast searches) and a per-row secret key that always requires a Secure Enclave round trip (Apple Platform Security Guide, December 2024; full architecture: `keychain-fundamentals.md` § Two-Tier Encryption and Query Cost).

| Accessibility Class                                | Device-Bound | Background Access       | Primary Use Case              | Risk Note                                                           |
| -------------------------------------------------- | ------------ | ----------------------- | ----------------------------- | ------------------------------------------------------------------- |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`     | Yes          | No                      | OAuth tokens, API keys        | **Recommended default** — strongest for credentials                 |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`  | Yes          | No                      | Highest-assurance secrets     | Item permanently destroyed if user removes passcode                 |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | Yes          | Yes (post-first unlock) | Background token refresh      | Larger exposure window; use only when background access is required |
| `kSecAttrAccessibleAfterFirstUnlock`               | No           | Yes                     | Background + backup migration | Transfers via encrypted backup; avoid for sensitive tokens          |

**Rule of thumb:** Default to `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for all OAuth tokens and API keys. Use `AfterFirstUnlockThisDeviceOnly` only when background refresh is required (e.g., silent push notification handling). Never use `kSecAttrSynchronizable` for app tokens — iCloud Keychain sync is designed for website passwords, not application secrets.

> For complete accessibility constant selection criteria, data protection tier explanations, and `SecAccessControl` interaction rules, see `keychain-access-control.md` § The "When" Layer: Seven Accessibility Constants.

---

## Actor-Based KeychainManager — Thread-Safe Credential Storage

The `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, and `SecItemDelete` functions (all iOS 2.0+) are synchronous C functions performing IPC to the `securityd` daemon. They are thread-safe for independent items, but concurrent modifications to the same item produce race conditions — notably `errSecDuplicateItem` (-25299) when two threads both try to add a missing item simultaneously. A Swift actor (iOS 13+, idiomatic from iOS 17+ with mature concurrency) provides a serial executor that eliminates these races.

```swift
// ✅ CORRECT — Actor-based KeychainManager with proper kSecAttrAccessible
// Requires: iOS 13+ (actors), recommended iOS 17+ for mature concurrency
import Foundation
import Security

public actor KeychainManager {

    public enum KeychainError: Error {
        case unexpectedStatus(OSStatus), itemNotFound, encodingFailed, decodingFailed
    }

    let service: String
    private let accessGroup: String?
    private let accessibility: CFString

    public init(service: String, accessGroup: String? = nil,
                accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly) {
        self.service = service; self.accessGroup = accessGroup; self.accessibility = accessibility
    }

    func baseQuery(account: String) -> [CFString: Any] {
        var q: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword, kSecAttrService: service,
            kSecAttrAccount: account, kSecAttrAccessible: accessibility
        ]
        if let accessGroup { q[kSecAttrAccessGroup] = accessGroup }
        #if os(macOS)
        q[kSecUseDataProtectionKeychain] = true   // iOS-style data protection on macOS
        #endif
        return q
    }

    /// Add-or-update semantics: try update first, fall back to add.
    public func save(account: String, data: Data) throws {
        var searchQ = baseQuery(account: account)
        searchQ.removeValue(forKey: kSecAttrAccessible)
        let attrs: [CFString: Any] = [kSecValueData: data, kSecAttrAccessible: accessibility]
        var status = SecItemUpdate(searchQ as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var addQ = baseQuery(account: account); addQ[kSecValueData] = data
            status = SecItemAdd(addQ as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }
    }

    public func load(account: String) throws -> Data {
        var q = baseQuery(account: account)
        q.removeValue(forKey: kSecAttrAccessible)
        q[kSecReturnData] = kCFBooleanTrue; q[kSecMatchLimit] = kSecMatchLimitOne
        var result: AnyObject?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        switch status {
        case errSecSuccess: guard let d = result as? Data else { throw KeychainError.decodingFailed }; return d
        case errSecItemNotFound: throw KeychainError.itemNotFound
        default: throw KeychainError.unexpectedStatus(status)
        }
    }

    public func delete(account: String) throws {
        var q = baseQuery(account: account); q.removeValue(forKey: kSecAttrAccessible)
        let s = SecItemDelete(q as CFDictionary)
        guard s == errSecSuccess || s == errSecItemNotFound else { throw KeychainError.unexpectedStatus(s) }
    }

    /// Delete ALL items for this service — used during logout.
    public func deleteAll() throws {
        var q: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service as CFString]
        if let accessGroup { q[kSecAttrAccessGroup] = accessGroup as CFString }
        #if os(macOS)
        q[kSecUseDataProtectionKeychain] = true
        #endif
        let s = SecItemDelete(q as CFDictionary)
        guard s == errSecSuccess || s == errSecItemNotFound else { throw KeychainError.unexpectedStatus(s) }
    }
}
```

**Why an actor?** The actor's serial executor guarantees that `save`, `load`, `delete`, and `deleteAll` never interleave. Two concurrent callers hitting `save` for the same account queue instead of racing. The synchronous `SecItem*` C calls execute safely within the actor — callers `await` access, suspending rather than blocking the cooperative thread pool.

**Global actor alternative** — when Keychain serialization must span multiple modules:

```swift
// ✅ Pattern: Global actor for cross-module Keychain serialization
// Requires: iOS 13.0+ (global actors via Swift 5.5+)
@globalActor
actor KeychainActor {
    static let shared = KeychainActor()
}

@KeychainActor
func saveCredential(_ data: Data, account: String) throws {
    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: "com.myapp.auth" as CFString,
        kSecAttrAccount: account as CFString,
        kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecValueData: data
    ]
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
        throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }
}
```

---

## OAuth2 Token Storage and Retrieval Cycle

`ASWebAuthenticationSession` (iOS 12.0+) is the mandatory standard for secure web-based login flows. Using legacy web views like `WKWebView` or `SFSafariViewController` for OAuth is a significant anti-pattern — they allow the host app to inspect web content or steal credentials. WWDC 2019 "What's New in Authentication" formally recommended migrating from the deprecated `SFAuthenticationSession` to `ASWebAuthenticationSession`.

### Token Model

```swift
// ✅ CORRECT — Codable token model with expiry tracking
struct OAuthTokens: Codable {
    let accessToken: String
    let refreshToken: String
    let expiresAt: Date
    let tokenType: String

    var isExpired: Bool {
        Date() >= expiresAt
    }

    /// Proactive refresh before expiry.
    /// Both providers agree: refresh at 75–90% of lifetime or with a fixed
    /// buffer (e.g., 60 seconds) to account for network latency and clock skew.
    var shouldRefresh: Bool {
        let buffer: TimeInterval = 60
        return Date() >= expiresAt.addingTimeInterval(-buffer)
    }
}
```

### ASWebAuthenticationSession + PKCE Flow

```swift
// ✅ CORRECT — ASWebAuthenticationSession + PKCE + Keychain storage
// Requires: iOS 13.0+ (for prefersEphemeralWebBrowserSession)
import AuthenticationServices
import CryptoKit

final class OAuthManager: NSObject, ASWebAuthenticationPresentationContextProviding {

    private let keychain = KeychainManager(
        service: "com.myapp.auth",
        accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    )
    private let clientID = "mobile-app-client" // public client, no secret needed
    private let redirectScheme = "com.myapp.auth"

    func startAuthentication() async throws -> OAuthTokens {
        let codeVerifier = generateCodeVerifier()  // RFC 7636 PKCE
        let codeChallenge = generateCodeChallenge(from: codeVerifier)

        var components = URLComponents(string: "https://auth.example.com/authorize")!
        components.queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: "\(redirectScheme)://callback"),
            URLQueryItem(name: "scope", value: "openid profile offline_access"),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "state", value: UUID().uuidString)
        ]

        let callbackURL: URL = try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: components.url!, callbackURLScheme: redirectScheme
            ) { url, error in
                if let error { continuation.resume(throwing: error) }
                else if let url { continuation.resume(returning: url) }
            }
            session.prefersEphemeralWebBrowserSession = true  // iOS 13+: no cookie sharing
            session.presentationContextProvider = self
            session.start()
        }

        guard let code = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false)?
            .queryItems?.first(where: { $0.name == "code" })?.value else {
            throw OAuthError.missingAuthorizationCode
        }

        let tokens = try await exchangeCodeForTokens(code: code, codeVerifier: codeVerifier)
        try await keychain.save(account: "oauth_tokens", data: JSONEncoder().encode(tokens))
        return tokens
    }

    // MARK: - PKCE helpers (RFC 7636)

    private func generateCodeVerifier() -> String {
        var buffer = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
        return Data(buffer).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func generateCodeChallenge(from verifier: String) -> String {
        // CryptoKit SHA256 (iOS 13.0+) — replaces legacy CC_SHA256
        let hash = SHA256.hash(data: Data(verifier.utf8))
        return Data(hash).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func exchangeCodeForTokens(code: String, codeVerifier: String) async throws -> OAuthTokens {
        // Standard OAuth2 token exchange — implement with your authorization server
        fatalError("Implement token exchange")
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor { ASPresentationAnchor() }
    enum OAuthError: Error { case missingAuthorizationCode }
}
```

**iOS 17.4+ improvement:** `ASWebAuthenticationSession.Callback` enables HTTPS universal link callbacks instead of custom URL schemes. Universal links provide a cryptographic guarantee of domain ownership, making them significantly less susceptible to interception (RFC 8252, OAuth 2.0 for Native Apps).

**Privacy vs SSO trade-off:** Setting `prefersEphemeralWebBrowserSession = true` maximizes privacy and session isolation but breaks Single Sign-On. Toggle based on whether your app prioritizes strict isolation or seamless SSO.

---

## Atomic Token Refresh with Rotation Support

When a server implements Refresh Token Rotation (RTR) — as Okta, Auth0, and others do — each refresh response includes a new refresh token and the old one is immediately invalidated. If the app stores the new access token but crashes before persisting the new refresh token, the user is locked out. The solution: update both tokens atomically within the actor's serial execution context.

Servers typically provide a short grace period (e.g., 30 seconds per Okta's configuration) during which the previous refresh token remains valid to handle network retries. If a previously invalidated token is reused outside the grace period, the server invalidates the entire token family — a strong signal of credential compromise.

```swift
// ✅ CORRECT — Atomic token refresh with rotation support
// Requires: iOS 13.0+ (actor serialization guarantees no interleaving)
extension KeychainManager {
    func atomicTokenUpdate(oldAccount: String = "oauth_tokens", newTokens: OAuthTokens) throws {
        let newData = try JSONEncoder().encode(newTokens) // Encode BEFORE mutation

        var delQ: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
                                      kSecAttrService: self.service as CFString,
                                      kSecAttrAccount: oldAccount as CFString]
        #if os(macOS)
        delQ[kSecUseDataProtectionKeychain] = true
        #endif
        let delStatus = SecItemDelete(delQ as CFDictionary)
        guard delStatus == errSecSuccess || delStatus == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(delStatus)
        }

        var addQ = baseQuery(account: oldAccount); addQ[kSecValueData] = newData
        let addStatus = SecItemAdd(addQ as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw KeychainError.unexpectedStatus(addStatus) }
    }
}
```

### Refresh Coordinator with Promise Coalescing

If multiple concurrent callers detect an expired token, only one refresh request should fire and all callers share the result:

```swift
// ✅ CORRECT — Single-flight refresh coordinator
// Requires: iOS 13.0+
actor TokenRefreshCoordinator {

    private let keychain: KeychainManager
    private let tokenEndpoint: URL
    private var refreshTask: Task<OAuthTokens, Error>?

    init(keychain: KeychainManager, tokenEndpoint: URL) {
        self.keychain = keychain; self.tokenEndpoint = tokenEndpoint
    }

    /// Returns a valid access token, refreshing if necessary.
    func validAccessToken() async throws -> String {
        guard let data = try? await keychain.load(account: "oauth_tokens"),
              let tokens = try? JSONDecoder().decode(OAuthTokens.self, from: data) else {
            throw TokenError.notAuthenticated
        }
        guard tokens.shouldRefresh else { return tokens.accessToken }

        // Coalesce: reuse in-flight refresh if one exists
        if let existing = refreshTask { return try await existing.value.accessToken }

        let task = Task<OAuthTokens, Error> {
            defer { refreshTask = nil }
            return try await performRefresh(currentRefreshToken: tokens.refreshToken)
        }
        refreshTask = task
        return try await task.value.accessToken
    }

    private func performRefresh(currentRefreshToken: String) async throws -> OAuthTokens {
        var request = URLRequest(url: tokenEndpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = "grant_type=refresh_token&refresh_token=\(currentRefreshToken)".data(using: .utf8)

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw TokenError.networkError }

        switch http.statusCode {
        case 200:
            // Decode server response (access_token, refresh_token?, expires_in, token_type)
            let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
            let newTokens = OAuthTokens(
                accessToken: json["access_token"] as! String,
                refreshToken: (json["refresh_token"] as? String) ?? currentRefreshToken,
                expiresAt: Date().addingTimeInterval(json["expires_in"] as! TimeInterval),
                tokenType: json["token_type"] as! String
            )
            try await keychain.atomicTokenUpdate(newTokens: newTokens)
            return newTokens
        case 400, 401:
            try? await keychain.deleteAll()  // Refresh token revoked — force re-auth
            throw TokenError.refreshTokenExpired
        default:
            throw TokenError.serverError(http.statusCode)
        }
    }

    enum TokenError: Error {
        case notAuthenticated, refreshTokenExpired, networkError, serverError(Int)
    }
}
```

---

## Runtime API Key Fetching with Keychain Cache and TTL

The most secure pattern for API keys is a backend proxy — the key never reaches the device. When that is not feasible, fetch the key from a secure backend at runtime and cache it in the Keychain with a time-to-live. The Keychain has no native TTL mechanism, so store expiry metadata alongside the secret.

Use App Attest (`DCAppAttestService`, iOS 14.0+) to prove app integrity before the backend issues secrets. The app generates a hardware-backed key pair in the Secure Enclave and requests an attestation object from Apple. The backend validates this object, ensuring the app is untampered and running on a genuine device, before delivering short-lived API keys.

```swift
// ✅ CORRECT — Runtime secret fetching with TTL-based Keychain cache
// Requires: iOS 13.0+
actor RuntimeSecretManager {

    private struct CachedSecret: Codable {
        let value: String; let fetchedAt: Date; let ttlSeconds: TimeInterval
        var isExpired: Bool { Date().timeIntervalSince(fetchedAt) >= ttlSeconds }
    }

    private let keychain: KeychainManager
    private let secretsEndpoint: URL
    private let defaultTTL: TimeInterval
    private var memoryCache: [String: CachedSecret] = [:]

    init(keychain: KeychainManager, secretsEndpoint: URL, defaultTTL: TimeInterval = 3600) {
        self.keychain = keychain; self.secretsEndpoint = secretsEndpoint; self.defaultTTL = defaultTTL
    }

    /// Three-tier lookup: memory → Keychain → network
    func secret(forKey key: String) async throws -> String {
        if let c = memoryCache[key], !c.isExpired { return c.value }

        if let data = try? await keychain.load(account: "secret_\(key)"),
           let c = try? JSONDecoder().decode(CachedSecret.self, from: data), !c.isExpired {
            memoryCache[key] = c; return c.value
        }

        let freshValue = try await fetchFromBackend(key: key)
        let cached = CachedSecret(value: freshValue, fetchedAt: Date(), ttlSeconds: defaultTTL)
        try await keychain.save(account: "secret_\(key)", data: JSONEncoder().encode(cached))
        memoryCache[key] = cached
        return freshValue
    }

    private func fetchFromBackend(key: String) async throws -> String {
        var request = URLRequest(url: secretsEndpoint.appendingPathComponent(key))
        // Authenticate with App Attest (iOS 14.0+) before backend issues secret
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              let json = try? JSONDecoder().decode([String: String].self, from: data),
              let value = json["value"] else { throw SecretFetchError.serverError }
        return value
    }

    enum SecretFetchError: Error { case serverError }
}
```

---

## Comprehensive Credential Clearing on Logout

A secure logout must clear every credential artifact: access token, refresh token, cached secrets, user profile data, and in-memory caches. It must also revoke tokens server-side when possible. Group all auth-related Keychain items under a single `kSecAttrService` value so `SecItemDelete` can wipe them in one call — no forgotten refresh tokens, no orphaned API keys.

```swift
// ✅ CORRECT — Complete credential clearing on logout
// OWASP MASVS-STORAGE-1, MASVS-STORAGE-2 compliant | iOS 13.0+
actor SessionManager {

    private let keychain = KeychainManager(service: "com.myapp.auth",
                                            accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly)

    func logout() async {
        // 1. Server-side revocation (best-effort)
        if let data = try? await keychain.load(account: "oauth_tokens"),
           let tokens = try? JSONDecoder().decode(OAuthTokens.self, from: data) {
            try? await revoke(token: tokens.refreshToken)
            try? await revoke(token: tokens.accessToken)
        }
        // 2. Nuclear Keychain cleanup — ALL items for this service
        try? await keychain.deleteAll()
        // 3. Clear cookies for auth domain
        HTTPCookieStorage.shared.cookies(for: URL(string: "https://auth.example.com")!)?
            .forEach { HTTPCookieStorage.shared.deleteCookie($0) }
        // 4. Clear URL cache
        URLCache.shared.removeAllCachedResponses()
    }

    private func revoke(token: String) async throws {
        var req = URLRequest(url: URL(string: "https://auth.example.com/oauth/revoke")!)
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.httpBody = "token=\(token)".data(using: .utf8)
        _ = try await URLSession.shared.data(for: req)
    }
}
```

**Server-driven revocation signals:** Backends can signal revocation via HTTP 401/403 with custom reason codes (e.g., `token_revoked`) or via silent push notifications (APNs) to trigger background logout and Keychain clearing.

---

## Key Rotation and Versioned Migration

### Rotation Strategies by Secret Type

**OAuth refresh tokens** — rely on server-driven RTR. Okta's model issues a new refresh token on every use with a configurable grace period (0–60 seconds). If a previously invalidated token is reused outside the grace period, the server invalidates the entire token family.

**Long-lived API keys** — rotation is a planned event: generate a new least-privilege key, deploy it, verify operation, then revoke the old one. Maintain emergency playbooks for compromise scenarios.

### Versioned Keychain Items for Migration

Version Keychain items using the `kSecAttrAccount` key to enable backward-compatible migration during rotation:

```swift
// ✅ CORRECT — Versioned Keychain migration during rotation
// Requires: iOS 13.0+
actor TokenMigrationManager {

    private let keychain: KeychainManager
    private static let currentVersion = 2

    init(keychain: KeychainManager) { self.keychain = keychain }

    /// Call on app launch to migrate old token formats.
    func migrateIfNeeded() async throws {
        if let _ = try? await keychain.load(account: "oauth_tokens_v2") {
            return // Already current
        }
        if let oldData = try? await keychain.load(account: "oauth_tokens") {
            let migrated = try migrateV1ToV2(oldData)
            try await keychain.save(account: "oauth_tokens_v2", data: migrated)
            try await keychain.delete(account: "oauth_tokens") // Clean up old
        }
    }

    private func migrateV1ToV2(_ data: Data) throws -> Data {
        // Implement format conversion between versions
        return data
    }
}
```

### Detecting Compromised Credentials

Four strategies: (1) **Token reuse detection** — server invalidates the entire token family when an already-rotated refresh token is presented. (2) **Anomaly monitoring** — geographic or temporal anomalies in token usage patterns. (3) **Proactive refresh** — refresh tokens at 75–90% of their lifetime rather than waiting for expiry. (4) **Breach database checks** — services like AWS Cognito check credentials against known breach databases during authentication.

---

## Device Binding and Backup Implications

Using `ThisDeviceOnly` variants prevents credential cloning but introduces friction during device upgrades. Because `ThisDeviceOnly` secrets are non-migratory, they will not transfer when a user restores an iCloud backup to a new device. The application must detect missing credentials on first launch and gracefully route the user through re-authentication.

```swift
// ✅ Pattern: Detect missing credentials after device restore
func handleAppLaunch() async {
    do {
        let _ = try await keychain.load(account: "oauth_tokens_v2")
        // Tokens present — proceed normally
    } catch KeychainManager.KeychainError.itemNotFound {
        // Likely a fresh install or device restore
        // Route to authentication flow
        await presentLoginScreen()
    } catch {
        // Unexpected error — log and route to auth
        logger.error("Keychain load failed: \(error)")
        await presentLoginScreen()
    }
}
```

**Why not `kSecAttrSynchronizable` for app tokens?** Setting it to `true` syncs the item across all trusted Apple devices via iCloud Keychain. While appropriate for website passwords managed by the Passwords app, this significantly increases the attack surface for OAuth tokens and API keys. Omit this attribute to keep secrets local.

---

## Biometric Protection for High-Value Credentials

For user-initiated, high-value operations (e.g., payment authorization, viewing sensitive data), add `SecAccessControl` with biometric gating. Avoid biometric protection for refresh tokens that require headless background renewal.

```swift
// ✅ CORRECT — Maximum OWASP MASTG L2 compliance configuration
// Requires: iOS 11.3+ (for .or compound constraint)
func createHighSecurityKeychainItem(account: String, secret: Data) throws {
    var error: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        [.biometryCurrentSet, .or, .devicePasscode],
        &error
    ) else {
        throw error!.takeRetainedValue() as Error
    }

    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: "com.myapp.auth" as CFString,
        kSecAttrAccount: account as CFString,
        kSecValueData: secret,
        kSecAttrAccessControl: accessControl,
        kSecUseDataProtectionKeychain: true
    ]

    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
        throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }
}
```

**Cross-reference:** See `biometric-authentication.md` for detailed `LAContext` integration patterns and the LAContext-only bypass vulnerability. See `keychain-access-control.md` for the full accessibility class decision tree.

---

## iOS 17+ and 18+ Modernizations

**iOS 17** introduced `ASWebAuthenticationSession.Callback` (iOS 17.4+), enabling HTTPS universal link callbacks instead of custom URL schemes — more secure redirect handling that verifies domain ownership. Shared password groups let teams share credentials via end-to-end encrypted iCloud Keychain. Third-party credential provider extensions can now supply passkeys alongside passwords.

**iOS 18** brought the standalone Passwords app (replacing Keychain Access for end users), automatic passkey upgrades via `.conditional` registration style, and expanded credential provider extensions to support verification codes. No new `SecItem*` APIs were introduced, but the ecosystem shift toward passkeys means the Keychain's role is evolving from storing passwords to storing cryptographic keys for WebAuthn-based authentication.

**WWDC 2024** Session 10125 "Streamline sign-in with passkey upgrades and credential managers" detailed the automatic passkey upgrade flow. WWDC 2021 Session 10105 introduced on-device TOTP verification code generation synced via iCloud Keychain, reducing dependence on SMS-based 2FA.

**Swift 6 strict concurrency direction:** The community `swift-keychain-kit` library introduces `SecretData` as a non-copyable type (`~Copyable`) that uses `mlock` to prevent swapping to disk and zeroes memory on deallocation. While not yet an Apple framework, this pattern points toward where Keychain APIs are heading: consumed secrets that cannot accidentally be copied into insecure memory.

---

## Static Analysis and CI/CD Guardrails

Catch credential anti-patterns before they reach production:

| Tool                         | Purpose                                                | Integration Point        |
| ---------------------------- | ------------------------------------------------------ | ------------------------ |
| **truffleHog / gitleaks**    | Scan for hardcoded secrets in source code              | PR/commit hooks          |
| **strings / class-dump**     | Verify no secrets in compiled binary                   | Post-build CI step       |
| **SwiftLint** (custom rules) | Flag `UserDefaults` usage for token-like keys          | Local + CI               |
| **Frida / Objection**        | Verify `kSecAttrAccessible` values at runtime          | QA / penetration testing |
| **MobSF**                    | Automated network traffic and storage leakage analysis | Dynamic regression gate  |

**Rule:** Fail the build if static analysis detects secrets in the codebase or compiled binary.

---

## OWASP MASTG Compliance Mapping

The OWASP Mobile Top 10 (2024) places M1 (Improper Credential Usage) as the number-one mobile security risk. The MASVS v2.1.0 restructured requirements with MASWE (Mobile App Security Weakness Enumeration) bridging controls to specific tests.

| Pattern                                    | OWASP Controls          | MASWE Weaknesses                   | MASTG Tests                           |
| ------------------------------------------ | ----------------------- | ---------------------------------- | ------------------------------------- |
| Keychain with `WhenUnlockedThisDeviceOnly` | M1, M9, MASVS-STORAGE-1 | MASWE-0002, MASWE-0004, MASWE-0036 | MASTG-TEST-0299, 0300, 0301, 0302     |
| Actor-based thread-safe access             | M9, MASVS-STORAGE-1     | MASWE-0002                         | MASTG-TEST-0300                       |
| ASWebAuthenticationSession (ephemeral)     | M1, MASVS-AUTH-1        | MASWE-0032                         | MASTG-TEST-0064                       |
| Atomic token refresh                       | M1, MASVS-AUTH-1        | MASWE-0038                         | —                                     |
| Runtime secret fetching                    | M1, MASVS-STORAGE-1     | MASWE-0005                         | —                                     |
| Comprehensive logout cleanup               | M9, MASVS-STORAGE-2     | MASWE-0004                         | MASTG-TEST-0298                       |
| Biometric + `ThisDeviceOnly`               | M9, MASVS-STORAGE-2     | MASWE-0046                         | MASTG-TEST-0298, MASTG-DEMO-0043–0047 |

The legacy test identifiers MSTG-STORAGE-1 and MSTG-STORAGE-2 map to the deprecated MASTG-TEST-0052 and MASTG-TEST-0053, now replaced by the granular suite MASTG-TEST-0296 through MASTG-TEST-0314.

---

## Conclusion

The Keychain is not optional — it is the only mechanism Apple provides that encrypts credentials via the Secure Enclave and enforces data protection classes tied to device lock state. Three architectural decisions eliminate the majority of credential vulnerabilities: (1) use a Swift actor as the single Keychain access point to eliminate race conditions in token refresh; (2) fetch secrets at runtime from a backend proxy using App Attest for app attestation rather than embedding them in the binary; (3) group all auth-related Keychain items under a single `kSecAttrService` so logout can clear everything in one call.

The future trajectory — passkeys, non-copyable secret types, HTTPS callbacks — reinforces rather than replaces these fundamentals.

---

## Summary Checklist

1. **Keychain-only storage** — all tokens, API keys, and credentials stored exclusively in the Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; never in `UserDefaults`, `Info.plist`, `.xcconfig`, or hardcoded in source
2. **Actor-serialized access** — all Keychain operations routed through a Swift `actor` (or `@globalActor`) to prevent race conditions and `errSecDuplicateItem` errors from concurrent access
3. **ASWebAuthenticationSession + PKCE** — OAuth2 flows use `ASWebAuthenticationSession` with `prefersEphemeralWebBrowserSession = true` and PKCE (RFC 7636); never `WKWebView` or `SFSafariViewController`
4. **Atomic token refresh** — refresh token rotation handled atomically within the actor: encode new tokens before any mutation, delete old, store new; promise coalescing prevents duplicate refresh requests
5. **Runtime secret fetching** — API keys fetched from an attested backend (App Attest / DeviceCheck, iOS 14.0+) and cached in Keychain with application-layer TTL; three-tier lookup: memory → Keychain → network
6. **Comprehensive logout** — `deleteAll()` by `kSecAttrService` clears all credential items in one call; also revokes tokens server-side, clears cookies, and clears `URLCache`
7. **No `kSecAttrSynchronizable` for app tokens** — iCloud Keychain sync is for website passwords, not application secrets; `ThisDeviceOnly` variants prevent backup exfiltration
8. **Device restore detection** — app detects missing `ThisDeviceOnly` credentials after device restore and gracefully routes to re-authentication
9. **Versioned migration** — Keychain items versioned via `kSecAttrAccount` naming (e.g., `oauth_tokens_v2`) to support format changes and rollback during rotation
10. **CI/CD secret scanning** — static analysis (truffleHog, gitleaks, `strings`) integrated into build pipeline to catch hardcoded secrets before deployment; fail the build on detection
11. **OWASP MASTG compliance** — patterns satisfy M1, M9, MASVS-STORAGE-1, MASVS-AUTH-1 controls; validate with MASTG-TEST-0298 through 0302 and dynamic analysis (Frida/Objection) confirming protection classes at runtime
