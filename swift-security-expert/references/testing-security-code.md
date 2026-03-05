# Testing Keychain, CryptoKit, and Biometric Code

> Scope: Unit, integration, and CI patterns for validating keychain, CryptoKit, and biometric security code across simulator, CI runners, and physical devices.

**Protocol-based abstraction is the single most important pattern for testable security code.** Wrapping Security framework calls behind a Swift protocol lets you inject an in-memory mock for unit tests while reserving real keychain integration tests for physical devices. The core challenge is that keychain behavior differs dramatically across three environments — Xcode simulator, CI runner, and physical device — and tests that ignore these differences produce flaky failures, crashes, or false confidence.

This reference covers mock design, CryptoKit round-trip tests, Secure Enclave guards, biometric mocking, CI/CD keychain creation, simulator limitations, Swift Testing framework patterns, mutation testing, and OWASP MASTG validation. All code targets Swift 5.9+/6.0, iOS 17–18+, with iOS 26 post-quantum notes where applicable.

Key sources: Apple TN3137 "On Mac keychain APIs and implementations," WWDC19-413 "Testing in Xcode," WWDC24-10179/10195 "Meet/Go further with Swift Testing," Apple Platform Security Guide, OWASP MASTG.

---

## Protocol-Based Keychain Abstraction

The foundation of testable keychain code is a protocol abstracting the four Security framework operations. Every view model, service, or manager that touches the keychain depends on this protocol, never on the Security framework directly.

### KeychainServiceProtocol with Real and Mock Implementations

```swift
import Foundation
import Security

enum KeychainError: Error, Equatable {
    case duplicateItem
    case itemNotFound
    case authFailed
    case interactionNotAllowed
    case unexpectedData
    case unhandledError(status: OSStatus)

    init(status: OSStatus) {
        switch status {
        case errSecDuplicateItem:          self = .duplicateItem
        case errSecItemNotFound:           self = .itemNotFound
        case errSecAuthFailed:             self = .authFailed
        case errSecInteractionNotAllowed:  self = .interactionNotAllowed
        default:                           self = .unhandledError(status: status)
        }
    }
}

protocol KeychainServiceProtocol: Sendable {
    func save(_ data: Data, forKey key: String) throws
    func read(forKey key: String) throws -> Data?
    func update(_ data: Data, forKey key: String) throws
    func delete(forKey key: String) throws
    func deleteAll() throws
}
```

The real `KeychainService` implementation wraps `SecItem*` calls with the add-or-update pattern and proper `OSStatus` mapping (see `keychain-fundamentals.md` for the full implementation). Key points: `save` attempts update first to avoid `errSecDuplicateItem`; `delete` treats `errSecItemNotFound` as success; the class conforms to `@unchecked Sendable` with immutable stored properties.

The mock replaces Security framework with a dictionary. Runs everywhere — simulator, CI, even Linux — with zero entitlement requirements. Supports injectable errors and call counting:

```swift
final class MockKeychainService: KeychainServiceProtocol, @unchecked Sendable {
    var storage: [String: Data] = [:]
    var saveCallCount = 0
    var readCallCount = 0
    var deleteCallCount = 0
    var errorToThrow: KeychainError?

    func save(_ data: Data, forKey key: String) throws {
        if let error = errorToThrow { throw error }
        saveCallCount += 1
        storage[key] = data
    }

    func read(forKey key: String) throws -> Data? {
        if let error = errorToThrow { throw error }
        readCallCount += 1
        return storage[key]
    }

    func update(_ data: Data, forKey key: String) throws {
        if let error = errorToThrow { throw error }
        guard storage[key] != nil else { throw KeychainError.itemNotFound }
        storage[key] = data
    }

    func delete(forKey key: String) throws {
        if let error = errorToThrow { throw error }
        storage.removeValue(forKey: key)
        deleteCallCount += 1
    }

    func deleteAll() throws {
        if let error = errorToThrow { throw error }
        storage.removeAll()
    }
}
```

Business logic depends only on the protocol — never on `SecItem*` directly:

```swift
final class AuthenticationManager {
    private let keychain: KeychainServiceProtocol

    init(keychain: KeychainServiceProtocol) {
        self.keychain = keychain
    }

    func storeToken(_ token: String) throws {
        guard let data = token.data(using: .utf8) else {
            throw KeychainError.unexpectedData
        }
        try keychain.save(data, forKey: "auth_token")
    }

    func retrieveToken() throws -> String? {
        guard let data = try keychain.read(forKey: "auth_token") else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
```

---

## Seven Mistakes AI Generators Make in Keychain Tests

Both research providers independently identified overlapping anti-patterns. This merged list covers the full set:

**1. Tests that use the real keychain without cleanup.** Tests calling `SecItemAdd` directly leave state across runs. Second run fails with `errSecDuplicateItem` (-25299). AI generators rarely include `setUp`/`tearDown` cleanup.

**2. Assuming Secure Enclave exists on simulator.** `SecureEnclave.isAvailable` returns `false` on every simulator. Tests calling `SecureEnclave.P256.Signing.PrivateKey()` directly throw `CryptoKitError` on simulator and crash CI.

**3. Not testing error paths.** Real keychain code must handle `errSecDuplicateItem` (-25299), `errSecItemNotFound` (-25300), `errSecAuthFailed` (-25293), and `errSecInteractionNotAllowed` (-25308). AI generators almost never test these failure modes.

**4. Assuming biometric hardware.** Tests instantiating a real `LAContext` and asserting `canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` returns `true` fail on simulator where no biometric hardware exists.

**5. Missing test host app.** Since Xcode 9, test bundles on iOS simulator require a host app to access the keychain. Without one, `SecItemAdd` returns `-25300` or `-34018`. AI generators never mention this requirement.

**6. No service/account scoping.** Tests omitting `kSecAttrService` match items from other tests or even other apps. Every keychain operation in tests must use a unique, test-specific service identifier.

**7. Confusing data protection keychain with file-based keychain.** Per Apple TN3137, macOS has two keychain implementations. The `security` CLI works with the file-based keychain; iOS apps use the data protection keychain. CI scripts using `security create-keychain` create the wrong type for `SecItemAdd` targets.

---

## Simulator vs. Device Testing Matrix

Understanding exactly what works where prevents entire categories of test failures:

| Feature                                                       | Simulator                             | Physical Device              |
| ------------------------------------------------------------- | ------------------------------------- | ---------------------------- |
| Keychain CRUD (`SecItemAdd`, etc.)                            | ✅ Works                              | ✅ Works                     |
| CryptoKit software crypto (AES-GCM, ChaChaPoly, P256, SHA256) | ✅ Software                           | ✅ Hardware-accelerated      |
| `kSecAttrAccessible` values                                   | ✅ Accepted but not hardware-enforced | ✅ Hardware-enforced         |
| `SecureEnclave.isAvailable`                                   | Returns **false**                     | Returns **true** (A7+)       |
| `SecureEnclave.P256.Signing.PrivateKey()`                     | ❌ Throws                             | ✅ Works                     |
| Biometric prompt on protected items                           | ❌ Skipped — value returned silently  | ✅ Shows prompt              |
| `LAContext.canEvaluatePolicy(.biometrics)`                    | Returns **false**                     | Returns **true** if enrolled |
| Face ID simulation via Xcode menu                             | ✅ Manual only                        | N/A (real hardware)          |
| Post-quantum (ML-KEM, ML-DSA) iOS 26+                         | ✅ Software (iOS 26 runtime)          | ✅ Works                     |

**Critical subtlety:** On simulator, keychain items protected with `kSecAttrAccessControl` and biometric flags return their value without showing a biometric prompt. Simulator tests that store biometric-protected items and read them succeed silently, giving false confidence the biometric gate works.

### Conditional Compilation and Runtime Guards

```swift
// Compile-time: exclude SE code on simulator
#if targetEnvironment(simulator)
    let signingKey = SoftwareSigningKey()
#else
    let signingKey = SecureEnclave.isAvailable
        ? try SecureEnclaveSigningKey()
        : SoftwareSigningKey()
#endif

// Runtime skip in XCTest
func testDeviceOnlyFeature() throws {
    #if targetEnvironment(simulator)
    throw XCTSkip("Requires physical device")
    #endif
    // Device-only test code here
}

// Runtime detection via ProcessInfo
struct EnvironmentDetector {
    static var isSimulator: Bool {
        ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
    }
    static var isRunningTests: Bool {
        ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil
    }
}
```

---

## Essential Testing Patterns

### setUp/tearDown Cleanup for Real Keychain Tests

```swift
final class KeychainIntegrationTests: XCTestCase {
    private let testService = "com.tests.keychain-integration"
    private var keychain: KeychainService!

    override func setUp() {
        super.setUp()
        keychain = KeychainService(service: testService)
        try? keychain.deleteAll()  // Clean slate
    }

    override func tearDown() {
        try? keychain.deleteAll()  // Leave no trace
        super.tearDown()
    }

    func testSaveAndRetrieveToken() throws {
        let token = "test-jwt-token-12345"
        try keychain.save(token.data(using: .utf8)!, forKey: "access_token")
        let retrieved = try keychain.read(forKey: "access_token")
        XCTAssertEqual(String(data: retrieved!, encoding: .utf8), token)
    }
}
```

### No Cleanup — Flaky Across Runs

```swift
// ❌ INCORRECT: No cleanup, no isolation
final class BadKeychainTests: XCTestCase {
    func testSaveToken() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "token",
            kSecValueData as String: "secret".data(using: .utf8)!
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        XCTAssertEqual(status, errSecSuccess)
        // First run: passes ✅
        // Second run: FAILS with errSecDuplicateItem (-25299) ❌
    }
}
```

### Testing Error Paths with Injected Failures

```swift
final class KeychainErrorPathTests: XCTestCase {
    var mockKeychain: MockKeychainService!
    var authManager: AuthenticationManager!

    override func setUp() {
        mockKeychain = MockKeychainService()
        authManager = AuthenticationManager(keychain: mockKeychain)
    }

    func testStoreToken_whenDuplicateItem_throwsExpectedError() {
        mockKeychain.errorToThrow = .duplicateItem
        XCTAssertThrowsError(try authManager.storeToken("token")) { error in
            XCTAssertEqual(error as? KeychainError, .duplicateItem)
        }
    }

    func testRetrieveToken_whenAuthFailed_throwsError() {
        mockKeychain.errorToThrow = .authFailed
        XCTAssertThrowsError(try authManager.retrieveToken()) { error in
            XCTAssertEqual(error as? KeychainError, .authFailed)
        }
    }

    func testRetrieveToken_whenInteractionNotAllowed_throwsError() {
        // Simulates the most common CI failure scenario
        mockKeychain.errorToThrow = .interactionNotAllowed
        XCTAssertThrowsError(try authManager.retrieveToken()) { error in
            XCTAssertEqual(error as? KeychainError, .interactionNotAllowed)
        }
    }
}
```

### CryptoKit Round-Trip Tests (Simulator-Safe)

All CryptoKit software operations work on simulator. These tests run everywhere:

```swift
import XCTest
import CryptoKit

final class CryptoKitTests: XCTestCase {

    func testAESGCMRoundTrip() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = "Sensitive credentials".data(using: .utf8)!
        let sealedBox = try AES.GCM.seal(plaintext, using: key)
        let ciphertext = sealedBox.combined!
        XCTAssertNotEqual(ciphertext, plaintext)

        let reopened = try AES.GCM.SealedBox(combined: ciphertext)
        let decrypted = try AES.GCM.open(reopened, using: key)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testAESGCMWrongKeyFails() throws {
        let correctKey = SymmetricKey(size: .bits256)
        let wrongKey = SymmetricKey(size: .bits256)
        let sealed = try AES.GCM.seal("secret".data(using: .utf8)!, using: correctKey)
        XCTAssertThrowsError(try AES.GCM.open(sealed, using: wrongKey))
    }

    func testP256SignVerify() throws {
        let privateKey = P256.Signing.PrivateKey()
        let data = "Message to authenticate".data(using: .utf8)!
        let signature = try privateKey.signature(for: data)
        XCTAssertTrue(privateKey.publicKey.isValidSignature(signature, for: data))

        let tampered = "Tampered message".data(using: .utf8)!
        XCTAssertFalse(privateKey.publicKey.isValidSignature(signature, for: tampered))
    }

    func testCurve25519KeyAgreement() throws {
        let alice = Curve25519.KeyAgreement.PrivateKey()
        let bob = Curve25519.KeyAgreement.PrivateKey()
        let aliceShared = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey)
        let bobShared = try bob.sharedSecretFromKeyAgreement(with: alice.publicKey)

        let aliceKey = aliceShared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: Data(), outputByteCount: 32)
        let bobKey = bobShared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: Data(), outputByteCount: 32)

        // Both parties can decrypt each other's messages
        let sealed = try AES.GCM.seal("test".data(using: .utf8)!, using: aliceKey)
        XCTAssertEqual(try AES.GCM.open(sealed, using: bobKey), "test".data(using: .utf8)!)
    }
}
```

**iOS 26 note:** Post-quantum cryptography (ML-KEM, ML-DSA) is available via CryptoKit starting iOS 26. Gate these tests with `@available(iOS 26, *)` and use the same round-trip pattern. Software-based PQC works on simulator (see `cryptokit-public-key.md`).

---

## Secure Enclave Test Strategy — Protocol Fallback

> **Cross-reference contradiction:** One research source used a function returning `P256.Signing.PrivateKey` for both SE and software paths. This is a type error — `SecureEnclave.P256.Signing.PrivateKey` and `P256.Signing.PrivateKey` are distinct types. The correct approach is a protocol-based abstraction:

### SigningKeyProvider Protocol with SE/Software Implementations

```swift
import CryptoKit

protocol SigningKeyProvider {
    func sign(_ data: Data) throws -> Data
    func publicKeyData() -> Data
}

final class SecureEnclaveSigningKey: SigningKeyProvider {
    private let key: SecureEnclave.P256.Signing.PrivateKey

    init() throws {
        guard SecureEnclave.isAvailable else {
            throw KeychainError.unhandledError(status: errSecUnimplemented)
        }
        self.key = try SecureEnclave.P256.Signing.PrivateKey()
    }

    func sign(_ data: Data) throws -> Data {
        try key.signature(for: data).derRepresentation
    }

    func publicKeyData() -> Data { key.publicKey.derRepresentation }
}

final class SoftwareSigningKey: SigningKeyProvider {
    private let key = P256.Signing.PrivateKey()

    func sign(_ data: Data) throws -> Data {
        try key.signature(for: data).derRepresentation
    }

    func publicKeyData() -> Data { key.publicKey.derRepresentation }
}

struct SigningKeyFactory {
    static func make() -> SigningKeyProvider {
        if SecureEnclave.isAvailable,
           let seKey = try? SecureEnclaveSigningKey() {
            return seKey
        }
        return SoftwareSigningKey()
    }
}
```

### Testing Secure Enclave Code

```swift
// ❌ INCORRECT: Crashes on simulator and CI
func testSecureEnclaveSigning_BROKEN() throws {
    let key = try SecureEnclave.P256.Signing.PrivateKey() // throws on simulator
    let sig = try key.signature(for: "data".data(using: .utf8)!)
    XCTAssertTrue(key.publicKey.isValidSignature(sig, for: "data".data(using: .utf8)!))
}

// ✅ CORRECT: Skip gracefully when SE unavailable
func testSecureEnclaveSigning_withGuard() throws {
    try XCTSkipUnless(SecureEnclave.isAvailable,
                      "Secure Enclave not available — skipping on simulator")
    let key = try SecureEnclave.P256.Signing.PrivateKey()
    let data = "authenticated payload".data(using: .utf8)!
    let sig = try key.signature(for: data)
    XCTAssertTrue(key.publicKey.isValidSignature(sig, for: data))
}

// ✅ CORRECT: Protocol-based test runs everywhere
func testSigningWithFallback() throws {
    let signer = SigningKeyFactory.make()
    let data = "payload".data(using: .utf8)!
    let sigBytes = try signer.sign(data)
    XCTAssertFalse(sigBytes.isEmpty)

    let publicKey = try P256.Signing.PublicKey(derRepresentation: signer.publicKeyData())
    let signature = try P256.Signing.ECDSASignature(derRepresentation: sigBytes)
    XCTAssertTrue(publicKey.isValidSignature(signature, for: data))
}
```

---

## Biometric Flow Testing — LAContext Mocking

Wrap `LAContext` behind a protocol for full control over biometric outcomes in tests. Alternatively, subclass `LAContext` directly (simpler but tighter coupling).

### Protocol-Based Approach (Preferred)

```swift
import LocalAuthentication

protocol BiometricAuthContext {
    func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool
    func evaluatePolicy(_ policy: LAPolicy, localizedReason: String,
                        reply: @escaping (Bool, Error?) -> Void)
}

extension LAContext: BiometricAuthContext {}

final class BiometricAuthManager {
    private let context: BiometricAuthContext

    init(context: BiometricAuthContext = LAContext()) {
        self.context = context
    }

    var isBiometricsAvailable: Bool {
        context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    func authenticate(reason: String,
                      completion: @escaping (Result<Void, Error>) -> Void) {
        guard isBiometricsAvailable else {
            completion(.failure(LAError(.biometryNotAvailable)))
            return
        }
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                               localizedReason: reason) { success, error in
            completion(success ? .success(()) : .failure(error ?? LAError(.authenticationFailed)))
        }
    }
}

final class MockBiometricContext: BiometricAuthContext {
    var canEvaluateResult = true
    var evaluateResult = true
    var evaluateError: Error?
    var evaluateCalled = false

    func canEvaluatePolicy(_ policy: LAPolicy, error: NSErrorPointer) -> Bool {
        canEvaluateResult
    }

    func evaluatePolicy(_ policy: LAPolicy, localizedReason: String,
                        reply: @escaping (Bool, Error?) -> Void) {
        evaluateCalled = true
        reply(evaluateResult, evaluateError)
    }
}
```

### Biometric Scenarios to Cover

| Scenario     | canEvaluate | evaluatePolicy | Error                  | Expected App Behavior     |
| ------------ | ----------- | -------------- | ---------------------- | ------------------------- |
| Success      | true        | true           | nil                    | Proceed                   |
| User cancel  | true        | false          | `.userCancel`          | Retry or abort gracefully |
| Lockout      | true        | false          | `.biometryLockout`     | Fallback to passcode      |
| Not enrolled | false       | n/a            | `.biometryNotEnrolled` | Show enrollment guidance  |

```swift
func testBiometricAuthSuccess() {
    let mock = MockBiometricContext()
    mock.canEvaluateResult = true
    mock.evaluateResult = true
    let manager = BiometricAuthManager(context: mock)

    let exp = expectation(description: "auth")
    manager.authenticate(reason: "Test") { result in
        if case .failure = result { XCTFail("Expected success") }
        exp.fulfill()
    }
    waitForExpectations(timeout: 1)
    XCTAssertTrue(mock.evaluateCalled)
}

func testBiometricAuthUnavailable() {
    let mock = MockBiometricContext()
    mock.canEvaluateResult = false
    let manager = BiometricAuthManager(context: mock)

    let exp = expectation(description: "unavailable")
    manager.authenticate(reason: "Test") { result in
        if case .success = result { XCTFail("Expected failure") }
        exp.fulfill()
    }
    waitForExpectations(timeout: 1)
    XCTAssertFalse(mock.evaluateCalled)  // Should not attempt auth
}
```

---

## CI/CD Pipeline Configuration

Running keychain tests in CI is the most error-prone part. The `-25308` (`errSecInteractionNotAllowed`) error is the most common CI failure — keychain locked or requires GUI interaction in a headless environment.

### GitHub Actions

```yaml
name: iOS CI
on: [push, pull_request]
jobs:
  test:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v5
      - name: Create temporary keychain
        env:
          KEYCHAIN_PASSWORD: ${{ secrets.KEYCHAIN_PASSWORD }}
        run: |
          KEYCHAIN_PATH=$RUNNER_TEMP/app-signing.keychain-db
          security create-keychain -p "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH
          security set-keychain-settings -lut 21600 $KEYCHAIN_PATH
          security unlock-keychain -p "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH
          security list-keychain -d user -s $KEYCHAIN_PATH
          # Import cert + CRITICAL partition list step
          echo -n "$BUILD_CERTIFICATE_BASE64" | base64 --decode -o $RUNNER_TEMP/cert.p12
          security import $RUNNER_TEMP/cert.p12 -P "$P12_PASSWORD" \
            -A -t cert -f pkcs12 -k $KEYCHAIN_PATH
          security set-key-partition-list -S apple-tool:,apple: \
            -k "$KEYCHAIN_PASSWORD" $KEYCHAIN_PATH
      - name: Run simulator-safe tests
        run: |
          xcodebuild test -scheme MyApp \
            -destination 'platform=iOS Simulator,name=iPhone 16' \
            -testPlan CITests
      - name: Cleanup
        if: always()
        run: security delete-keychain $RUNNER_TEMP/app-signing.keychain-db
```

**`security set-key-partition-list` must be called after importing certificates** — this is the step most people miss. Without it, `codesign` hangs indefinitely waiting for a GUI prompt. The `-A` flag on import grants access to all applications, necessary in CI.

**Xcode Cloud:** Uses ephemeral environments — no manual `security create-keychain`. Apple manages signing automatically. Ensure Keychain Sharing capability is enabled. The `-25308` error is common when SPM tries to save credentials.

**Fastlane:** `setup_ci` creates a temporary `fastlane_tmp_keychain` and sets it as default. On self-hosted runners, this can interfere with the host machine's keychain.

```ruby
lane :ci_test do
  setup_ci(timeout: 3600)
  sync_code_signing(type: "development", readonly: is_ci)
  run_tests(scheme: "MyApp", testplan: "CITests", device: "iPhone 16")
end
```

### Common CI Error Reference

| Error                         | OSStatus | Cause                                 | Fix                                             |
| ----------------------------- | -------- | ------------------------------------- | ----------------------------------------------- |
| `errSecInteractionNotAllowed` | -25308   | Keychain locked / needs GUI           | Unlock keychain + `set-key-partition-list`      |
| `errSecMissingEntitlement`    | -34018   | No keychain-access-groups entitlement | Add entitlements to test host app               |
| `errSecItemNotFound`          | -25300   | No test host or missing entitlement   | Use test host app with keychain capability      |
| `errSecInternalComponent`     | -67585   | Partition list not set after import   | Call `set-key-partition-list` after cert import |
| Default keychain not found    | -25307   | No default keychain on CI runner      | Create and set default keychain                 |

### Test Host App Requirement

Since Xcode 9, test bundles on iOS simulator require a host app to access the keychain. Without one, `SecItemAdd` returns `-25300` or `-34018`. Create a minimal iOS app target, enable the Keychain Sharing capability, and set the test target's **Test Host** and **Bundle Loader** build settings to point at it.

---

## Xcode Test Plans — Separating Simulator from Device

Create two test plans for CI/device split:

- **CITests.xctestplan**: Only tests using `MockKeychainService` and simulator-safe CryptoKit. Skips integration, biometric, and SE tests.
- **DeviceTests.xctestplan**: Real keychain integration, Secure Enclave, and biometric hardware tests. Requires physical device.

```bash
# CI: simulator-safe tests on every push
xcodebuild test -scheme MyApp \
  -destination 'platform=iOS Simulator,name=iPhone 16' \
  -testPlan CITests

# Nightly: device farm runs everything
xcodebuild test -scheme MyApp \
  -destination 'platform=iOS,id=DEVICE_UDID' \
  -testPlan DeviceTests
```

---

## Swift Testing Framework Patterns

Swift Testing (WWDC24) introduces tags, traits, and parameterized tests that map well to security test organization:

```swift
import Testing
@testable import MyApp

extension Tag {
    @Tag static var keychain: Self
    @Tag static var deviceOnly: Self
    @Tag static var ciSafe: Self
}

@Suite(.serialized, .tags(.keychain))
struct KeychainTests {

    @Test("Save and retrieve round-trip", .tags(.ciSafe))
    func saveAndRetrieve() throws {
        let mock = MockKeychainService()
        let manager = AuthenticationManager(keychain: mock)
        try manager.storeToken("test-token")
        let result = try #require(try manager.retrieveToken())
        #expect(result == "test-token")
    }

    @Test("Device-only: real keychain integration",
          .enabled(if: ProcessInfo.processInfo.environment["CI"] == nil),
          .tags(.deviceOnly))
    func realKeychainIntegration() throws {
        let keychain = KeychainService(service: "com.test.swift-testing")
        try keychain.deleteAll()
        defer { try? keychain.deleteAll() }
        try keychain.save("token".data(using: .utf8)!, forKey: "key")
        let data = try #require(try keychain.read(forKey: "key"))
        #expect(String(data: data, encoding: .utf8) == "token")
    }

    @Test("Parameterized error paths",
          arguments: [
              KeychainError.duplicateItem,
              KeychainError.itemNotFound,
              KeychainError.authFailed,
              KeychainError.interactionNotAllowed
          ])
    func errorPathHandling(expectedError: KeychainError) {
        let mock = MockKeychainService()
        mock.errorToThrow = expectedError
        #expect(throws: KeychainError.self) {
            try mock.read(forKey: "any-key")
        }
    }
}
```

The `.serialized` trait ensures keychain tests modifying shared state run sequentially. Tags integrate with test plans for filtering — `.ciSafe` tests run in CI, `.deviceOnly` tests run on device farms.

---

## Advanced Patterns

### Migration Testing: UserDefaults to Keychain

Migration code is security-critical — silent failure leaves credentials in UserDefaults (see `migration-legacy-stores.md`). The class under test accepts injected dependencies for both stores:

```swift
final class StorageMigrationManager {
    private let defaults: UserDefaults
    private let keychain: KeychainServiceProtocol

    init(defaults: UserDefaults = .standard,
         keychain: KeychainServiceProtocol) {
        self.defaults = defaults
        self.keychain = keychain
    }

    func migrateIfNeeded() throws {
        let version = defaults.integer(forKey: "migration_version")
        if version < 1 {
            if let token = defaults.string(forKey: "auth_token"),
               let data = token.data(using: .utf8) {
                try keychain.save(data, forKey: "auth_token")
                defaults.removeObject(forKey: "auth_token")
            }
        }
        defaults.set(1, forKey: "migration_version")
    }
}
```

Test with isolated `UserDefaults(suiteName:)` and mock keychain:

```swift
func testMigrationMovesTokenToKeychain() throws {
    let defaults = UserDefaults(suiteName: "migration-test")!
    defaults.removePersistentDomain(forName: "migration-test")
    defaults.set("my-secret", forKey: "auth_token")
    defaults.set(0, forKey: "migration_version")

    let mock = MockKeychainService()
    let migrator = StorageMigrationManager(defaults: defaults, keychain: mock)
    try migrator.migrateIfNeeded()

    // Token moved to keychain, removed from UserDefaults
    XCTAssertEqual(String(data: mock.storage["auth_token"]!, encoding: .utf8), "my-secret")
    XCTAssertNil(defaults.string(forKey: "auth_token"))
}
```

### Performance Testing

```swift
func testKeychainWritePerformance() {
    let keychain = KeychainService(service: "com.test.perf")
    let options = XCTMeasureOptions()
    options.iterationCount = 20

    measure(metrics: [XCTClockMetric(), XCTCPUMetric()], options: options) {
        let data = UUID().uuidString.data(using: .utf8)!
        try? keychain.save(data, forKey: "perf-key")
        try? keychain.delete(forKey: "perf-key")
    }
}
```

### Mutation Testing

Mutation testing introduces deliberate bugs (flipping `==` to `!=`, removing `SecItemDelete` calls, swapping `&&` to `||`) and checks whether your tests catch them. A project can have 81% code coverage but only 16% mutation score — tests execute security code without validating it does the right thing.

**Muter** (`brew install muter-mutation-testing/muter/muter`) is the primary Swift mutation testing tool. Its `RelationalOperatorReplacement` operator catches authentication bypasses; `RemoveSideEffects` catches missing `SecItemDelete` calls in logout flows. For security code, target mutation score above **80%**.

### OWASP MASTG Keychain Validation

MASTG-TEST-0052 requires that sensitive data use the Keychain, not `NSUserDefaults` or `.plist` files. OWASP also documents that keychain data persists after app uninstallation — the app sandbox is wiped but keychain items remain. Standard mitigation is a fresh-install detector (see `common-anti-patterns.md`):

```swift
static func handleFreshInstall(keychain: KeychainServiceProtocol) {
    let hasLaunched = UserDefaults.standard.bool(forKey: "has_launched")
    if !hasLaunched {
        try? keychain.deleteAll()
        UserDefaults.standard.set(true, forKey: "has_launched")
    }
}
```

---

## Conclusion

Protocol-abstraction is non-negotiable for testable keychain code. Every `SecItem` call should be behind `KeychainServiceProtocol` so that 95%+ of your test suite runs against `MockKeychainService` with zero entitlement requirements and zero CI flakiness. Reserve real-keychain integration tests for a dedicated test plan on physical devices.

Three insights most guides miss: (1) the simulator silently returns biometric-protected items without prompting — tests appear to validate biometric gates but test nothing; (2) TN3137's distinction between file-based and data protection keychains means `security create-keychain` in CI creates the wrong keychain type; (3) mutation testing reveals that even high-coverage suites fail to catch inverted conditionals and removed side effects — the exact mutations that create real vulnerabilities.

---

## Summary Checklist

1. **Protocol abstraction** — All keychain access goes through `KeychainServiceProtocol`; no direct `SecItem*` calls in business logic
2. **Mock with injectable errors** — `MockKeychainService` supports `errorToThrow` for testing `errSecDuplicateItem`, `errSecAuthFailed`, `errSecInteractionNotAllowed`, and `errSecItemNotFound` paths
3. **setUp/tearDown cleanup** — Every integration test using real keychain has both pre-test and post-test cleanup with a test-specific `kSecAttrService`
4. **Secure Enclave guard** — All SE tests use `try XCTSkipUnless(SecureEnclave.isAvailable, ...)` or protocol-based fallback; never call `SecureEnclave.P256.*` unconditionally
5. **Biometric mock** — `LAContext` wrapped behind protocol or subclass mock; tests cover success, user cancel, lockout, and not-enrolled scenarios
6. **Simulator/device split** — Two Xcode test plans: `CITests` (mock-based, simulator-safe) and `DeviceTests` (real keychain, SE, biometrics on physical device)
7. **CI keychain setup** — GitHub Actions calls `security set-key-partition-list` after cert import; test target has host app with Keychain Sharing capability enabled
8. **CryptoKit round-trips** — Encrypt→decrypt and sign→verify tests for AES-GCM, ChaChaPoly, P256, Curve25519; wrong-key failure tests included
9. **Error path coverage** — Every `OSStatus` code the app can encounter has a corresponding test with injected mock failure
10. **Migration testing** — UserDefaults→Keychain migration tested with isolated `UserDefaults(suiteName:)` and mock keychain; verifies source cleared after migration
11. **Mutation testing baseline** — Muter mutation score ≥80% for security-critical code paths; `RelationalOperatorReplacement` and `RemoveSideEffects` operators enabled
