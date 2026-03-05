# Secure Enclave: Hardware-Backed Key Operations for iOS & macOS

> Scope: Secure Enclave capabilities, constraints, and integration patterns for key generation, persistence, biometric gating, and testability on Apple platforms.

**The Secure Enclave (SE) is Apple's dedicated security coprocessor — a physically isolated chip that generates, stores, and operates on cryptographic keys in silicon that never exposes private key material to the application processor.** Every modern Apple device since iPhone 5s (2013) contains this hardware, but developers routinely misuse it because of subtle API behaviors, simulator traps, and fundamental architectural constraints that AI code generators consistently get wrong. This reference covers CryptoKit's `SecureEnclave` module (iOS 13+), the legacy Security framework path, iOS 26 post-quantum additions, correct and incorrect code patterns, persistence, testing strategies, and the hardware limitations you must design around.

Primary sources: Apple Platform Security Guide (Secure Enclave chapter), Apple Developer Documentation for CryptoKit `SecureEnclave` types, WWDC 2019 Session 709 "Cryptography and Your Apps," WWDC 2025 "Get ahead with quantum-secure cryptography," Apple DTS documentation "Protecting keys with the Secure Enclave," and "Storing CryptoKit Keys in the Keychain."

---

## What the Secure Enclave actually is

The SE is a dedicated security subsystem embedded in Apple's SoC, running its own microkernel (sepOS — a customized L4 microkernel on a proprietary AKF ARMv7a core at 300–400 MHz). It has its own boot ROM (immutable, cryptographically verified at startup), hardware true random number generator (TRNG), AES engine, public key accelerator (PKA), and encrypted memory region. Communication with the application processor happens exclusively through an interrupt-driven mailbox — a hardware filter blocks all other access paths.

The SE's core guarantee: **private key material generated inside the Secure Enclave never leaves its hardware boundary.** When your code "uses" an SE key, it sends a request through the mailbox, the SE performs the cryptographic operation internally, and only the result (a signature, a shared secret) comes back. There is no API, debug interface, or JTAG path to extract the raw key.

Each SoC has a Unique ID (UID) permanently fused into silicon at manufacturing. This UID is inaccessible to any software (including Apple's) and serves as the root cryptographic key from which all SE keys derive. This is what makes keys irrevocably device-bound.

**Devices with Secure Enclave:** All iPhones from iPhone 5s onward (A7+ chips), all iPads from iPad Air onward, Apple Watch Series 1+, Apple TV HD (4th gen) onward, HomePod, all Macs with T1/T2/M-series chips, and Apple Vision Pro. Intel Macs without T1 or T2 chips (pre-2016 MacBook Pro, pre-2018 MacBook Air, pre-2020 iMac except iMac Pro) do **not** have a Secure Enclave.

---

## Hardware limitations you must design around

These constraints are architectural, not bugs — they are fundamental to the SE's security model:

- **P-256 only for classical EC** — No P-384, P-521, Curve25519, or secp256k1. CryptoKit has no `SecureEnclave.P384` or `SecureEnclave.Curve25519` types. iOS 26 adds lattice-based post-quantum algorithms (ML-KEM, ML-DSA), not additional curves.
- **No symmetric key operations** — The internal AES engine handles Data Protection and FileVault but is **not exposed as a developer API**. There is no `SecureEnclave.AES`.
- **No key export** — `SecKeyCopyExternalRepresentation()` on an SE private key fails. The `dataRepresentation` property returns an encrypted opaque blob, not raw key material.
- **No key import** — Keys must be generated inside the SE. `init(dataRepresentation:)` accepts only the opaque blob from a previously created SE key — not arbitrary key material. There is no `init(rawRepresentation:)` on SE key types.
- **Device-bound** — Keys are tied to the device's UID fused at manufacturing. They do not survive factory resets, cannot be backed up to iCloud, cannot sync via iCloud Keychain, and cannot be transferred to a replacement device.
- **Limited storage** — The SE has approximately 4 MB of flash storage for keys. Not a concern for typical apps (a few dozen keys), but relevant if generating keys at high volume.
- **Performance overhead** — Each operation requires an interrupt-driven round-trip to the isolated coprocessor. The SE is not suitable for high-frequency operations (thousands of signatures per second). Batch signing or bulk encryption should use SE-derived symmetric keys instead.

---

## CryptoKit SecureEnclave API (iOS 13+)

CryptoKit's `SecureEnclave` module is the primary API for new code. It wraps the lower-level Security framework with Swift-native types that provide compile-time type safety, automatic memory zeroing on deallocation, and a curated surface that makes misuse difficult.

Two operation families are supported: **signing** (`SecureEnclave.P256.Signing`) and **key agreement** (`SecureEnclave.P256.KeyAgreement`).

### Creating signing keys

```swift
// ✅ CORRECT: Robust availability check + key creation
import CryptoKit

func createSigningKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
    #if targetEnvironment(simulator)
    throw SecureEnclaveError.notAvailable
    #else
    guard SecureEnclave.isAvailable else {
        throw SecureEnclaveError.notAvailable
    }
    return try SecureEnclave.P256.Signing.PrivateKey()
    #endif
}

enum SecureEnclaveError: Error {
    case notAvailable
    case keyCreationFailed(underlying: Error)
}
```

The `#if targetEnvironment(simulator)` compile-time guard is essential. **`SecureEnclave.isAvailable` can return `true` on the Simulator** when the host Mac has SE hardware (T2/M-series), but actual key generation fails at runtime. This behavior varies across Xcode versions — some return `false` consistently, others reflect the host's hardware. The compile-time check eliminates the ambiguity entirely.

> **Cross-validation note:** The Claude research source documents the simulator `isAvailable` returning `true` as a confirmed trap; the Parallel research source states `isAvailable` is always `false` on simulator. Real-world behavior depends on Xcode version and host hardware. The defensive pattern above (compile-time guard + runtime check) is correct regardless of which behavior your environment exhibits.

```swift
// ❌ INCORRECT: No availability check — crashes on simulator and old devices
let key = try SecureEnclave.P256.Signing.PrivateKey()
// Simulator: error -25293 or EXC_BAD_ACCESS depending on Xcode version
```

### Signing and verification

Once you have an SE key, signing is straightforward. The SE performs ECDSA internally and returns a standard `P256.Signing.ECDSASignature`. Verification uses the public key — a regular `P256.Signing.PublicKey` that can be freely exported and used anywhere:

```swift
// ✅ Sign with SE key, verify with public key
let privateKey = try SecureEnclave.P256.Signing.PrivateKey()
let message = "Transfer $500 to Alice".data(using: .utf8)!

// Signing happens inside the Secure Enclave hardware
let signature = try privateKey.signature(for: message)

// Public key is standard P256 — works anywhere, export as DER for servers
let publicKey = privateKey.publicKey
let isValid = publicKey.isValidSignature(signature, for: message) // true

let derSignature = signature.derRepresentation   // For wire format
let rawSignature = signature.rawRepresentation   // For compact storage
let publicDER = publicKey.derRepresentation       // Register with backend
```

### Key agreement (ECDH) with HKDF derivation

`SecureEnclave.P256.KeyAgreement.PrivateKey` performs Elliptic Curve Diffie-Hellman inside the SE. The resulting `SharedSecret` is then derived into a usable symmetric key via HKDF — this is the **only correct path to symmetric encryption** when starting from an SE key:

```swift
// ✅ CORRECT: ECDH key agreement → HKDF → AES-GCM
let localKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
let localPublicKey = localKey.publicKey // Send to peer

// Received from peer (decoded from DER or raw bytes)
let peerPublicKey: P256.KeyAgreement.PublicKey = // ...

// ECDH happens inside the Secure Enclave
let sharedSecret = try localKey.sharedSecretFromKeyAgreement(with: peerPublicKey)

// Derive a 256-bit AES key using HKDF-SHA256
let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
    using: SHA256.self,
    salt: "com.myapp.v1.salt".data(using: .utf8)!,
    sharedInfo: "encryption-key".data(using: .utf8)!,
    outputByteCount: 32
)

// Now use the derived software key for AES-GCM encryption
let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey)
```

```swift
// ❌ WRONG: There is no SE symmetric API
// SecureEnclave.AES.GCM.seal(data, using: seKey) — DOES NOT EXIST
// AES.GCM.seal(data, using: seSigningKey) — TYPE MISMATCH (needs SymmetricKey)
```

> The ECDH + HKDF pattern is covered in full — including curve selection, `info` parameter guidance, and output key length — in `cryptokit-public-key.md` § Key Agreement with HKDF Derivation.

---

## Persisting SE keys via dataRepresentation

CryptoKit SE keys are **ephemeral by default** — if you don't persist the `dataRepresentation`, the key reference is lost when the app terminates. The `dataRepresentation` property returns an opaque encrypted blob that only the same Secure Enclave on the same device can use to reconstruct the key. It is emphatically **not** the raw private key.

```swift
// ✅ Persist SE key to keychain and retrieve later
import CryptoKit
import Security

// --- Store ---
let privateKey = try SecureEnclave.P256.Signing.PrivateKey()
let keyBlob: Data = privateKey.dataRepresentation // Encrypted, device-bound

let storeQuery: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "com.myapp.signing-key",
    kSecValueData as String: keyBlob,
    kSecAttrAccessible as String:
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly
]
// Delete-then-add pattern to handle existing items
SecItemDelete(storeQuery as CFDictionary)
let status = SecItemAdd(storeQuery as CFDictionary, nil)
guard status == errSecSuccess else {
    throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
}

// --- Retrieve ---
let fetchQuery: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "com.myapp.signing-key",
    kSecReturnData as String: true,
    kSecMatchLimit as String: kSecMatchLimitOne
]
var item: CFTypeRef?
let fetchStatus = SecItemCopyMatching(fetchQuery as CFDictionary, &item)
guard fetchStatus == errSecSuccess, let storedBlob = item as? Data else {
    throw NSError(domain: NSOSStatusErrorDomain, code: Int(fetchStatus))
}

let restoredKey = try SecureEnclave.P256.Signing.PrivateKey(
    dataRepresentation: storedBlob
)
// restoredKey is fully functional — operations route to the same SE key
```

On macOS, add `kSecUseDataProtectionKeychain: true` to target the modern data protection keychain rather than the legacy file-based keychain. On iOS/tvOS/watchOS this flag is redundant but harmless.

**Always use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`** for SE key blobs — the key is device-bound anyway, and syncable accessibility levels would store the blob on iCloud servers where it is useless (the SE that can decrypt it isn't there).

---

## Biometric-gated SE keys with SecAccessControl

The most security-critical SE pattern combines hardware key isolation with biometric authentication. The SE evaluates access control policies internally, making them tamper-proof even against OS-level compromises.

```swift
// ✅ Complete biometric-gated SE key creation (iOS 13+)
import CryptoKit
import LocalAuthentication
import Security

func createBiometricKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
    guard SecureEnclave.isAvailable else {
        throw SecureEnclaveError.notAvailable
    }

    var error: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],
        &error
    ) else {
        throw error!.takeRetainedValue() as Error
    }

    let context = LAContext()
    context.localizedReason = "Authenticate to create signing key"
    context.touchIDAuthenticationAllowableReuseDuration = 10

    return try SecureEnclave.P256.Signing.PrivateKey(
        compactRepresentable: true,
        accessControl: accessControl,
        authenticationContext: context
    )
}

// Later: reconstruct and use (biometric prompt appears)
func signWithBiometricKey(storedBlob: Data, data: Data) throws -> Data {
    let context = LAContext()
    context.localizedReason = "Authenticate to sign transaction"

    let key = try SecureEnclave.P256.Signing.PrivateKey(
        dataRepresentation: storedBlob,
        authenticationContext: context
    )
    return try key.signature(for: data).derRepresentation
}
```

```swift
// ❌ Omitting .privateKeyUsage causes signing to fail
let badControl = SecAccessControlCreateWithFlags(
    nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    .biometryCurrentSet, // Missing .privateKeyUsage!
    nil
)!
// Key creation succeeds, but signing operations will fail
```

**Access control flag selection:**

- **`.biometryCurrentSet`** — Strongest. Key is permanently invalidated when the user re-enrolls biometrics (adds a new fingerprint, re-registers Face ID). Best for banking/healthcare. Requires re-keying logic when invalidation occurs.
- **`.biometryAny`** — Key survives biometric re-enrollment. Good balance of security and convenience for most apps.
- **`.userPresence`** — Accepts biometric or device passcode. Most flexible; use when you just need proof that a human is present.

**Critical operational note:** If you use `.biometryCurrentSet` and the user changes their enrolled biometrics, the key becomes **permanently unusable**. Your app must detect `errSecItemNotFound` or authentication errors, explain to the user why re-authentication is needed, and generate a fresh key with server-side re-enrollment. (See `biometric-authentication.md` for full LAContext integration patterns.)

---

## Legacy Security framework approach (iOS 10+)

Before CryptoKit, SE keys were created via `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`. This still works and is necessary when targeting pre-iOS 13 or working with certificate-based identity operations:

```swift
// Legacy approach — functional but verbose; prefer CryptoKit for new code
import Security

func legacyCreateSEKey(tag: String) throws -> SecKey {
    let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],
        nil
    )!

    let attributes: NSDictionary = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits: 256,
        kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs: [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: tag.data(using: .utf8)!,
            kSecAttrAccessControl: access
        ]
    ]

    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes, &error) else {
        throw error!.takeRetainedValue() as Error
    }
    return privateKey
}
```

CryptoKit is preferred for new code because it provides compile-time type safety (distinct types per algorithm/operation), automatic memory zeroing, Swift-native error handling, and a curated API surface. The Security framework remains necessary for certificate management (`SecTrust`), RSA keys, or existing keychain items stored via the older API. (See `certificate-trust.md` for SecTrust patterns.)

---

## iOS 26: Post-quantum cryptography in the Secure Enclave

WWDC 2025 session "Get ahead with quantum-secure cryptography" announced the most significant expansion of the SE's developer-facing capabilities since its 2013 introduction. Starting with **iOS 26, macOS 26, and all 2025 platform releases**, four new algorithm families are available:

- **`SecureEnclave.MLKEM768`** and **`SecureEnclave.MLKEM1024`** — Post-quantum key encapsulation (FIPS 203). Hardware-isolated ML-KEM operations for quantum-resistant key exchange.
- **`SecureEnclave.MLDSA65`** and **`SecureEnclave.MLDSA87`** — Post-quantum digital signatures (FIPS 204). Hardware-isolated ML-DSA signing resistant to quantum attacks.

These are **hardware-backed**, not software-only. Apple confirmed SE support explicitly. The implementations are formally verified as functionally equivalent to their FIPS specifications.

**Quantum-secure TLS by default:** `URLSession` and `Network.framework` automatically upgrade to quantum-secure TLS 1.3 using X-Wing (ML-KEM768 + X25519) in iOS 26. System services including CloudKit, Push Notifications, and Private Relay already use it. For most developers, no code changes are needed.

**Custom end-to-end encryption:** Apple recommends hybrid constructions that combine post-quantum and classical algorithms. The `XWingMLKEM768X25519` type provides a hybrid KEM ciphersuite. For application-level encryption, use `SecureEnclave.MLKEM768.PrivateKey` to encapsulate/decapsulate shared secrets within the hardware boundary.

**API evolution timeline:**

| Release                 | SE Developer Additions                                                                             |
| ----------------------- | -------------------------------------------------------------------------------------------------- |
| **iOS 13** (2019)       | CryptoKit introduced: `SecureEnclave.P256.Signing`, `.P256.KeyAgreement`, `.isAvailable`           |
| **iOS 14** (2020)       | No SE changes. Added HKDF, PEM/DER format support                                                  |
| **iOS 15–16** (2021–22) | No SE changes                                                                                      |
| **iOS 17** (2023)       | No SE changes. HPKE added (software-only). iMessage PQ3 shipped in 17.4                            |
| **iOS 18** (2024)       | No SE changes                                                                                      |
| **iOS 26** (2025)       | **Major expansion**: `.MLKEM768`, `.MLKEM1024`, `.MLDSA65`, `.MLDSA87`. Quantum-secure TLS default |

The SE's classical elliptic curve support remains **P-256 only** — the expansion is entirely into lattice-based post-quantum algorithms.

> For the full post-quantum algorithm catalog — including software-only types, X-Wing hybrid KEM construction, key/signature size trade-offs, HPKE integration patterns, and hybrid classical+PQ signing — see `cryptokit-public-key.md` § Post-Quantum Cryptography (iOS 26+). This section covers the hardware-backed SE variants specifically.

---

## When to use SE versus software keys

**Use the Secure Enclave for:** root signing keys, device attestation, transaction authorization, biometric-gated authentication, and any scenario where proving key possession on a specific physical device matters. The non-exportability guarantee is the core value — an attacker who compromises the application processor still cannot extract the private key.

**Use standard keychain (software keys) for:** session tokens, API keys, symmetric encryption keys, keys requiring algorithms beyond P-256 (RSA, P-384, Ed25519), keys that must sync via iCloud Keychain, keys that need to survive device replacement, and high-throughput operations requiring thousands of operations per second.

**Common effective pattern:** Store a master asymmetric key in the SE and use ECDH to derive or wrap symmetric keys for bulk encryption. The SE protects the root of trust; derived keys handle the high-throughput work.

The anti-pattern is reaching for the SE for every secret. The P-256 constraint, performance overhead, and device-binding mean SE keys should protect the most critical operations, not replace the standard keychain. (See `credential-storage-patterns.md` for token lifecycle patterns.)

---

## Six correctness traps AI generators get wrong

These patterns appear routinely in LLM-generated code. Each reflects a misunderstanding of the SE's hardware architecture.

### 1. Not checking isAvailable (and the simulator double-trap)

The minimal check is `SecureEnclave.isAvailable`, but this alone is insufficient on the simulator. The robust pattern combines compile-time and runtime checks:

```swift
// ✅ Robust availability check — safe everywhere
var canUseSecureEnclave: Bool {
    #if targetEnvironment(simulator)
    return false
    #else
    return SecureEnclave.isAvailable
    #endif
}
```

### 2. Attempting to import external keys

There is no `init(rawRepresentation:)` on SE key types. `init(dataRepresentation:)` accepts only the opaque blob from a previously created SE key:

```swift
// ❌ IMPOSSIBLE: Cannot import an existing key into the Secure Enclave
let externalKey = P256.Signing.PrivateKey()
let rawBytes = externalKey.rawRepresentation
// SecureEnclave.P256.Signing.PrivateKey(rawRepresentation:) DOES NOT EXIST
// SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: rawBytes) WILL THROW

// ✅ Keys MUST be generated inside the SE
let seKey = try SecureEnclave.P256.Signing.PrivateKey()
```

### 3. Attempting AES/symmetric encryption directly

The SE's internal AES engine is not exposed to developers. Use ECDH → HKDF → AES-GCM instead (see Key agreement section above).

### 4. Assuming SE keys can be backed up or transferred

SE keys are device-bound. Server-side architectures **must** register the device's public key and support re-keying when a user changes devices. Design re-enrollment flows from day one.

### 5. Using legacy Security framework when CryptoKit is available

`SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave` still works, but CryptoKit eliminates ~20 lines of dictionary-based C-style code and provides compile-time type safety. Use the legacy API only for pre-iOS 13 targets or certificate operations.

### 6. Omitting .privateKeyUsage in access control

SE keys created with `SecAccessControl` for biometric gating **must** include `.privateKeyUsage`. Without it, key creation succeeds but signing operations fail silently on some configurations. Always combine: `[.privateKeyUsage, .biometryCurrentSet]`.

---

## Testing and CI/CD strategies

### Protocol-based abstraction for testable SE code

Since SE operations fail on simulators and most CI environments, abstract cryptographic operations behind a protocol with SE, software, and mock implementations:

```swift
// ✅ Protocol abstraction for testable SE-dependent code
import CryptoKit
import Foundation

protocol SigningKeyProvider {
    var publicKeyData: Data { get throws }
    func sign(_ data: Data) throws -> Data
}

// Production: Secure Enclave implementation
final class SESigningKey: SigningKeyProvider {
    private let key: SecureEnclave.P256.Signing.PrivateKey

    init() throws { self.key = try SecureEnclave.P256.Signing.PrivateKey() }
    init(dataRepresentation: Data) throws {
        self.key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: dataRepresentation)
    }

    var publicKeyData: Data { get throws { key.publicKey.derRepresentation } }
    func sign(_ data: Data) throws -> Data {
        try key.signature(for: data).derRepresentation
    }
}

// Fallback: Software P256 (same curve, same signature format)
final class SoftwareSigningKey: SigningKeyProvider {
    private let key: P256.Signing.PrivateKey

    init() { self.key = P256.Signing.PrivateKey() }
    var publicKeyData: Data { get throws { key.publicKey.derRepresentation } }
    func sign(_ data: Data) throws -> Data {
        try key.signature(for: data).derRepresentation
    }
}

// Test: Mock implementation
final class MockSigningKey: SigningKeyProvider {
    var publicKeyDataToReturn = Data()
    var signatureToReturn = Data()
    var shouldThrow = false
    var signCallCount = 0

    var publicKeyData: Data { get throws { publicKeyDataToReturn } }
    func sign(_ data: Data) throws -> Data {
        signCallCount += 1
        if shouldThrow { throw NSError(domain: "Mock", code: -1) }
        return signatureToReturn
    }
}
```

### Factory with SE → software fallback

```swift
// ✅ Runtime factory — SE when available, software otherwise
struct SigningKeyFactory {
    static func create() throws -> SigningKeyProvider {
        #if targetEnvironment(simulator)
        return SoftwareSigningKey()
        #else
        if SecureEnclave.isAvailable {
            return try SESigningKey()
        }
        return SoftwareSigningKey()
        #endif
    }
}
```

Both SE and software implementations produce **identical P256 ECDSA signatures** — verification code works the same regardless of which implementation created the key.

### XCTest patterns

```swift
import XCTest
@testable import MyApp

final class AuthServiceTests: XCTestCase {
    func testSignChallenge() throws {
        let mock = MockSigningKey()
        mock.signatureToReturn = Data([0xDE, 0xAD])
        let service = AuthService(signingKey: mock)

        let result = try service.signChallenge(Data("test".utf8))

        XCTAssertEqual(mock.signCallCount, 1)
        XCTAssertEqual(result, Data([0xDE, 0xAD]))
    }

    func testRealSEKey() throws {
        #if targetEnvironment(simulator)
        throw XCTSkip("Secure Enclave not available on Simulator")
        #else
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this hardware")
        }
        let key = try SESigningKey()
        let signature = try key.sign(Data("test".utf8))
        XCTAssertFalse(signature.isEmpty)
        #endif
    }
}
```

### CI/CD reality

GitHub Actions macOS runners (both arm64 and Intel) run in VMs where the **Secure Enclave is not accessible** — the Apple Virtualization Framework does not pass through SE access to guest VMs. Self-hosted runners on physical Mac hardware (Mac mini M-series, MacBook Pro with T2) do have SE access. Xcode Cloud runs on Apple silicon but SE availability depends on the specific cloud configuration.

**Practical CI approach:** Run unit tests with mocks on CI; run SE integration tests only on physical device test farms or self-hosted runners; tag SE-specific tests with `XCTSkip` guards for conditional execution. (See `testing-security-code.md` for comprehensive CI/CD patterns.)

---

## Operational guidance: rotation, migration, and incident response

Treat SE keys as **ephemeral, device-bound artifacts** rather than permanent user identities:

- **Device replacement:** When a user gets a new device, SE keys from the old device are gone. Your app must detect a missing key (keychain blob absent or `dataRepresentation` fails to reconstruct) and trigger a re-enrollment flow: generate a new SE key, register its public key with your backend, and invalidate the old public key.
- **Biometric re-enrollment:** If using `.biometryCurrentSet`, adding a new fingerprint or resetting Face ID permanently invalidates the key. Catch the error, explain to the user why they need to re-authenticate, and provision a fresh key.
- **Key rotation:** Periodic rotation of SE keys follows the same re-enrollment pattern. Generate a new key, register the new public key with the server, sign a transition token with the old key (if still valid), and delete the old key blob from the keychain.
- **Incident response:** If a device is compromised at the OS level, SE keys remain protected (the SE operates independently). However, if the physical device is in an attacker's possession and they know the passcode, they can authenticate to the SE. Remote wipe via MDM or Find My destroys the UID-derived key hierarchy, rendering all SE keys permanently unrecoverable.

---

## Conclusion

The Secure Enclave's developer surface was remarkably stable from iOS 13 to iOS 25 — `SecureEnclave.P256` was the entire API. iOS 26 broke open the boundary with post-quantum ML-KEM and ML-DSA, the first algorithm expansion in the SE's 12-year history. The practical insight is that **correct SE usage is more about what you don't do** (don't skip availability checks, don't try to import keys, don't assume portability, don't use the SE for symmetric encryption) than complex API choreography. The CryptoKit API is deliberately minimal and hard to misuse, which is its greatest strength.

For new projects, the recommended architecture is: protocol-based abstraction around signing and key agreement; SE implementation as primary with software P256 fallback; `dataRepresentation` persisted in the keychain as `kSecClassGenericPassword` with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; biometric access control for high-value keys; server-side public key registration with re-keying support for device replacement; and `XCTSkip`-guarded integration tests on physical hardware.

---

## Summary Checklist

1. **Availability guard** — Always combine `#if targetEnvironment(simulator)` (compile-time) with `SecureEnclave.isAvailable` (runtime) before any SE key creation. Never assume SE is present.
2. **No key import** — SE keys must be generated inside the hardware. `init(dataRepresentation:)` reconstructs existing SE keys only — it cannot import external key material.
3. **No symmetric encryption** — The SE does not expose AES to developers. Use ECDH → HKDF → `AES.GCM` for encryption workflows starting from an SE key.
4. **Device-bound design** — SE keys cannot be backed up, synced, or transferred. Build server-side re-enrollment flows for device replacement from day one.
5. **Persist dataRepresentation** — Store the opaque encrypted blob in the keychain as `kSecClassGenericPassword` with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Without persistence, keys are lost on app termination.
6. **Include .privateKeyUsage** — When creating `SecAccessControl` for biometric-gated SE keys, always include `.privateKeyUsage` alongside the biometric flag. Omitting it causes signing to fail silently.
7. **Handle biometric invalidation** — `.biometryCurrentSet` keys are permanently invalidated on biometric re-enrollment. Detect the error and trigger re-keying with server notification.
8. **Protocol abstraction** — Abstract SE operations behind a protocol with SE, software, and mock implementations for testability. Both SE and software P256 produce identical signature formats.
9. **CryptoKit over Security framework** — Use `SecureEnclave.P256.Signing.PrivateKey` (CryptoKit) instead of `SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave` for new code. Reserve the Security framework for certificates and pre-iOS 13 targets.
10. **iOS 26 post-quantum** — `SecureEnclave.MLKEM768/1024` and `.MLDSA65/87` are hardware-backed. For custom E2E encryption, adopt hybrid constructions (classical + PQC). `URLSession` TLS upgrades automatically.
11. **CI/CD skip guards** — Use `XCTSkip` for SE-specific tests in CI. GitHub Actions VMs do not have SE access. Run SE integration tests only on physical hardware or device farms.
