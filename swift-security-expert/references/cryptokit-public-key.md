# CryptoKit Public-Key Cryptography

> **Scope:** ECDSA signing, ECDH key agreement, HPKE (iOS 17+), ML-KEM/ML-DSA and hybrid migration patterns (iOS 26+), key serialization, and Secure Enclave integration boundaries on Apple platforms.
>
> **Cross-references:** Secure Enclave key lifecycle → `secure-enclave.md`. Symmetric encryption after key agreement → `cryptokit-symmetric.md`. Keychain storage of CryptoKit keys → `credential-storage-patterns.md`. RSA → ECC migration → § "Stop Using RSA for New Apple Development" below.

CryptoKit's asymmetric cryptography API covers ECDSA signing, ECDH key agreement, HPKE (iOS 17+), and post-quantum ML-KEM/ML-DSA (iOS 26+). The framework enforces correct usage through its type system — signing keys cannot perform key agreement, shared secrets must pass through HKDF before use, and Secure Enclave access is limited to P256 for classical curves. This reference covers every asymmetric primitive from iOS 13 through iOS 26 with verified Swift implementations, common AI-generator mistakes, and the quantum migration path.

CryptoKit was introduced at WWDC 2019 (session 709, "Cryptography and Your Apps") as a Swift-native replacement for the Security framework's C-based `SecKey` API. It wraps Apple's corecrypto library with hand-tuned assembly per microarchitecture, delivering both performance and memory safety — private key material is automatically zeroed on deallocation. iOS 14 added PEM/DER interoperability and standalone HKDF. iOS 17 brought HPKE (RFC 9180). iOS 26 (WWDC 2025, session 314, "Get ahead with quantum-secure cryptography") completes the picture with formally verified post-quantum algorithms and quantum-secure TLS enabled by default.

---

## Curve and Algorithm Selection Guide

The single most important decision is choosing the right curve or algorithm. AI generators frequently recommend Curve25519 when Secure Enclave protection is required, or default to P-256 when modern constant-time performance matters more.

### Classical Curves

**P256 (secp256r1 / NIST P-256)** — The only classical curve supported by the Secure Enclave. Required for hardware-backed key storage with biometric access control. Conforms to NIST FIPS 186-5 for US government compliance and has the broadest interoperability with TLS, X.509 certificates, and server-side libraries. Public keys are 64 bytes (uncompressed raw), signatures are 64 bytes (raw r‖s). PEM and DER export supported from iOS 14.

**Curve25519 (X25519 / Ed25519)** — Should be the default for software-only keys. Its rigid parameter design eliminates entire classes of implementation vulnerabilities — constant-time execution is inherent to the curve arithmetic, no point validation is required, and public keys are a compact 32 bytes. Ed25519 handles signing; X25519 handles key agreement. The tradeoff: only `rawRepresentation` is available (no PEM, no DER, no x963), and there is no Secure Enclave support.

**P384 and P521** — Exist for specific compliance requirements. P384 provides ~192-bit security (NIST Category 3); P521 provides ~256-bit security (Category 5). Their API surface mirrors P256 exactly. Use only when a specification or regulatory framework demands them.

### Post-Quantum Algorithms (iOS 26+)

**ML-KEM-768 / ML-KEM-1024** — FIPS 203 lattice-based key encapsulation. ML-KEM-768 targets ~AES-128 equivalent security; ML-KEM-1024 targets ~AES-192. Both support Secure Enclave hardware isolation on iOS 26+.

**ML-DSA-65 / ML-DSA-87** — FIPS 204 lattice-based digital signatures. ML-DSA-65 targets ~AES-128 equivalent; ML-DSA-87 targets ~AES-192. Both support Secure Enclave on iOS 26+.

**X-Wing (XWingMLKEM768X25519)** — Hybrid KEM combining ML-KEM-768 with X25519. Both algorithms must be broken to compromise the exchange. This is Apple's recommended migration path for custom protocols via HPKE.

### Selection Decision Matrix

| Scenario                      | iOS Version | Default Choice                                     | Rationale                                    |
| ----------------------------- | ----------- | -------------------------------------------------- | -------------------------------------------- |
| Hardware-isolated keys        | All         | `SecureEnclave.P256.*`                             | Private key never leaves the coprocessor     |
| Software signing/agreement    | All         | `Curve25519.*`                                     | Constant-time, compact, modern protocols     |
| FIPS/enterprise interop       | 17+         | `P256` or `P384`                                   | Aligns with legacy standards                 |
| E2E encryption (modern)       | 17+         | HPKE with `Curve25519_SHA256_ChachaPoly`           | High performance, broad client support       |
| E2E encryption (future-proof) | 26+         | HPKE with `XWingMLKEM768X25519_SHA256_AES_GCM_256` | Hybrid PQC against harvest-now-decrypt-later |
| Maximum classical security    | All         | `P521`                                             | ~256-bit security; only when mandated        |

### Algorithm Quick Reference

| Algorithm   | Security | iOS | Secure Enclave | Pub Key Size | Best For                        |
| ----------- | -------- | --- | -------------- | ------------ | ------------------------------- |
| P256        | ~128-bit | 13+ | ✅ Yes         | 64 bytes     | Hardware keys, NIST compliance  |
| P384        | ~192-bit | 13+ | ❌ No          | 96 bytes     | Government/compliance           |
| P521        | ~256-bit | 13+ | ❌ No          | 132 bytes    | Maximum classical security      |
| Curve25519  | ~128-bit | 13+ | ❌ No          | 32 bytes     | Modern protocols, software keys |
| ML-KEM-768  | ~AES-128 | 26+ | ✅ Yes         | 1,184 bytes  | Key encapsulation               |
| ML-KEM-1024 | ~AES-192 | 26+ | ✅ Yes         | 1,568 bytes  | Higher-security KEM             |
| ML-DSA-65   | ~AES-128 | 26+ | ✅ Yes         | 1,952 bytes  | Post-quantum signatures         |
| ML-DSA-87   | ~AES-192 | 26+ | ✅ Yes         | 2,592 bytes  | Higher-security signatures      |
| X-Wing      | Hybrid   | 26+ | ✅ Yes         | 1,216 bytes  | Hybrid PQC KEM                  |

On Apple Silicon, both P256 and Curve25519 are heavily optimized in corecrypto with hand-tuned assembly. Performance differences are negligible for most applications — Apple's NISTZ256 optimization closes the gap that Curve25519 holds in non-Apple benchmarks.

---

## Signing and Key Agreement Are Separate Type Hierarchies

CryptoKit's most important design decision is splitting each curve into two non-interchangeable type families: `Signing` and `KeyAgreement`. A `P256.Signing.PrivateKey` cannot perform key agreement. A `Curve25519.KeyAgreement.PrivateKey` cannot sign. The compiler enforces this at build time. AI generators frequently conflate these, producing code that fails to compile.

### ✅ Correct: P256 key generation, signing, and verification

```swift
import CryptoKit

// Generate a signing key pair
let signingKey = P256.Signing.PrivateKey()
let verifyingKey = signingKey.publicKey  // P256.Signing.PublicKey

// Sign data (CryptoKit hashes internally with SHA-256)
let message = Data("Transfer $100 to Alice".utf8)
let signature = try signingKey.signature(for: message)
// signature is P256.Signing.ECDSASignature

// Verify
let isValid = verifyingKey.isValidSignature(signature, for: message)

// Signature serialization
let derSig = signature.derRepresentation    // ASN.1 DER (interoperable)
let rawSig = signature.rawRepresentation    // Raw r‖s concatenation (64 bytes)
let restored = try P256.Signing.ECDSASignature(derRepresentation: derSig)
```

For pre-hashed data (when the digest is computed externally), use `signature(for:)` with a `Digest` parameter or the `SHA256Digest` directly.

### ❌ Wrong: Mixing signing and key agreement key types

```swift
// This will NOT compile — signing keys cannot do key agreement
let key = P256.Signing.PrivateKey()
let shared = try key.sharedSecretFromKeyAgreement(with: otherPublicKey)
// Error: P256.Signing.PrivateKey has no member 'sharedSecretFromKeyAgreement'

// Likewise, Curve25519.KeyAgreement.PrivateKey has no .signature(for:) method
```

---

## Key Agreement with HKDF Derivation

The `SharedSecret` produced by ECDH is not uniformly distributed and must never be used directly as an encryption key. CryptoKit enforces this — `SharedSecret` is not directly convertible to `SymmetricKey`. The only sanctioned paths are `.hkdfDerivedSymmetricKey()` or `.x963DerivedSymmetricKey()`. Apple's documentation states explicitly: "The shared secret isn't suitable as a symmetric cryptographic key by itself."

### ✅ Correct: Curve25519 key agreement with HKDF derivation

```swift
import CryptoKit

// Both parties generate key agreement keys (NOT signing keys)
let aliceKey = Curve25519.KeyAgreement.PrivateKey()
let bobKey = Curve25519.KeyAgreement.PrivateKey()

// Alice computes shared secret using Bob's public key
let sharedSecret = try aliceKey.sharedSecretFromKeyAgreement(
    with: bobKey.publicKey
)

// CRITICAL: Derive a symmetric key via HKDF — never use SharedSecret directly
let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
    using: SHA256.self,
    salt: Data("my-app-salt".utf8),
    sharedInfo: Data("encryption-v1".utf8),
    outputByteCount: 32  // 256-bit key for AES-256 or ChaChaPoly
)

// Now use the derived key for authenticated encryption
let sealed = try ChaChaPoly.seal(plaintext, using: symmetricKey)
```

The `sharedInfo` parameter serves as protocol binding — it ensures keys derived for different purposes within the same application cannot be confused. Use distinct `sharedInfo` values for encryption keys vs authentication keys when deriving multiple subkeys.

### ❌ Wrong: Using SharedSecret directly as an encryption key

```swift
// NEVER DO THIS — SharedSecret is not uniformly distributed
let sharedSecret = try aliceKey.sharedSecretFromKeyAgreement(with: bobPublicKey)

// SharedSecret is NOT a SymmetricKey and cannot be used as one directly.
// Its byte distribution is non-uniform (only ~2^255 of 2^256 values are
// valid P-256 x-coordinates). Skipping HKDF also prevents protocol binding
// and removes the salt's entropy-concentration benefit.

// This forced extraction is dangerous:
let insecureKey = SymmetricKey(data: sharedSecret.withUnsafeBytes { Data($0) })
// ⚠️ Non-uniform key material, no domain separation, no salt
```

---

## HPKE Simplifies Public-Key Encryption (iOS 17+)

Before iOS 17, encrypting data for a recipient's public key required manually implementing ECIES: perform ECDH, derive a key via HKDF, encrypt with AES-GCM, and transmit the ephemeral public key alongside the ciphertext. HPKE (RFC 9180) packages this entire flow into a single API. CryptoKit supports all four RFC modes — Base, Auth, PSK, and AuthPSK — with five built-in cipher suites.

### Built-in Cipher Suites

| Cipher Suite                              | KEM           | KDF         | AEAD              | Min iOS |
| ----------------------------------------- | ------------- | ----------- | ----------------- | ------- |
| `.Curve25519_SHA256_ChachaPoly`           | X25519        | HKDF-SHA256 | ChaCha20-Poly1305 | 17+     |
| `.P256_SHA256_AES_GCM_256`                | P-256         | HKDF-SHA256 | AES-GCM-256       | 17+     |
| `.P384_SHA384_AES_GCM_256`                | P-384         | HKDF-SHA384 | AES-GCM-256       | 17+     |
| `.P521_SHA512_AES_GCM_256`                | P-521         | HKDF-SHA512 | AES-GCM-256       | 17+     |
| `.XWingMLKEM768X25519_SHA256_AES_GCM_256` | X-Wing hybrid | HKDF-SHA256 | AES-GCM-256       | 26+     |

Custom suites can be constructed: `HPKE.Ciphersuite(kem: .P521_HKDF_SHA512, kdf: .HKDF_SHA512, aead: .AES_GCM_256)`.

### ✅ Correct: HPKE encryption and decryption

```swift
import CryptoKit

let ciphersuite = HPKE.Ciphersuite.Curve25519_SHA256_ChachaPoly
let info = Data("MyApp-FileEncryption-v1".utf8)

// Recipient generates a key pair and shares the public key
let recipientPrivateKey = Curve25519.KeyAgreement.PrivateKey()
let recipientPublicKey = recipientPrivateKey.publicKey

// === SENDER ===
// 'var' is required — seal() mutates internal nonce state
var sender = try HPKE.Sender(
    recipientKey: recipientPublicKey,
    ciphersuite: ciphersuite,
    info: info
)
let ciphertext = try sender.seal(
    Data("Confidential document".utf8),
    authenticating: Data("metadata".utf8)  // optional AAD
)
let encapsulatedKey = sender.encapsulatedKey  // MUST be sent with ciphertext

// === RECIPIENT ===
var recipient = try HPKE.Recipient(
    privateKey: recipientPrivateKey,
    ciphersuite: ciphersuite,
    info: info,
    encapsulatedKey: encapsulatedKey  // from sender
)
let plaintext = try recipient.open(
    ciphertext,
    authenticating: Data("metadata".utf8)  // same AAD
)
```

### Three Critical HPKE Details AI Generators Get Wrong

1. **The encapsulated key is not embedded in the ciphertext.** Your protocol must transmit `encapsulatedKey` alongside the ciphertext. Losing it means permanent decryption failure.

2. **`HPKE.Sender` and `HPKE.Recipient` are stateful structs that must be declared with `var`** because `seal()` and `open()` are mutating methods — they increment an internal nonce counter. Using `let` causes a compiler error.

3. **Message ordering matters.** If the sender seals messages A then B, the recipient must open A before B. The internal counter must stay synchronized.

> **Source discrepancy (flagged):** The parallel research source shows `seal()` returning a struct with `.encapsulatedKey` and `.ciphertext` properties. The Claude source shows `encapsulatedKey` as a property on `HPKE.Sender` and `seal()` returning `Data`. Per Apple's documentation, `encapsulatedKey` is a property of `HPKE.Sender` and `seal(_:authenticating:)` returns `Data`. The Claude source is correct.

---

## Post-Quantum Cryptography (iOS 26+)

At WWDC 2025 (session 314, "Get ahead with quantum-secure cryptography"), Apple announced CryptoKit support for NIST's post-quantum standards. The threat model is "harvest now, decrypt later" — adversaries storing encrypted traffic today to decrypt once cryptographically relevant quantum computers exist. iOS 26 enables quantum-secure TLS by default for `URLSession` and `Network.framework`, advertising `X25519MLKEM768` in the TLS ClientHello.

Five new types join CryptoKit, all backed by formally verified implementations proven functionally equivalent to their FIPS specifications:

| Type                  | Algorithm     | Standard                      | Operation          | Secure Enclave | Key/Sig Size                     |
| --------------------- | ------------- | ----------------------------- | ------------------ | -------------- | -------------------------------- |
| `MLKEM768`            | ML-KEM-768    | FIPS 203                      | Key encapsulation  | ✅             | 1,184 B pub / 1,088 B ciphertext |
| `MLKEM1024`           | ML-KEM-1024   | FIPS 203                      | Key encapsulation  | ✅             | 1,568 B pub                      |
| `XWingMLKEM768X25519` | X-Wing hybrid | draft-connolly-cfrg-xwing-kem | Key encapsulation  | ✅             | 1,216 B pub / 1,120 B encap      |
| `MLDSA65`             | ML-DSA-65     | FIPS 204                      | Digital signatures | ✅             | 1,952 B pub / 3,309 B sig        |
| `MLDSA87`             | ML-DSA-87     | FIPS 204                      | Digital signatures | ✅             | 2,592 B pub / 4,627 B sig        |

The size cost of quantum resistance is substantial — an ML-DSA-65 signature is 3,309 bytes versus 64 bytes for Ed25519; an ML-KEM-768 public key is 1,184 bytes versus 32 bytes for X25519. But computational performance is competitive with classical algorithms.

### ✅ Correct: ML-KEM-768 key encapsulation

Key encapsulation differs fundamentally from Diffie-Hellman key agreement. In ECDH, both parties contribute public keys. In KEM, only the recipient has a key pair — the sender calls `encapsulate()` on the public key, which produces both a shared secret and an opaque ciphertext that only the private key can decapsulate.

```swift
import CryptoKit

if #available(iOS 26, macOS 26, *) {
    // Recipient generates a key pair
    let privateKey = try MLKEM768.PrivateKey()
    let publicKey = privateKey.publicKey

    // Sender encapsulates (only needs recipient's public key)
    let encapsulation = try publicKey.encapsulate()
    let senderSharedSecret = encapsulation.sharedSecret     // 32 bytes
    let encapsulatedCiphertext = encapsulation.encapsulated  // 1,088 bytes

    // Recipient decapsulates
    let recipientSharedSecret = try privateKey.decapsulate(encapsulatedCiphertext)

    // senderSharedSecret == recipientSharedSecret
    // Derive a symmetric key via HKDF, as with ECDH
}
```

### ✅ Correct: ML-DSA-65 signing

```swift
if #available(iOS 26, macOS 26, *) {
    let signingKey = try MLDSA65.PrivateKey()
    let verifyingKey = signingKey.publicKey  // 1,952 bytes

    let message = Data("Authenticate this payload".utf8)
    let signature = try signingKey.signature(for: message)  // 3,309 bytes

    let isValid = verifyingKey.isValidSignature(
        signature: signature,
        for: message
    )
}
```

### ✅ Correct: Hybrid post-quantum with HPKE (recommended migration path)

Apple's recommended approach for custom protocols is to switch the HPKE cipher suite to X-Wing, which combines ML-KEM-768 with X25519 so that both algorithms must be broken to compromise the exchange:

```swift
if #available(iOS 26, macOS 26, *) {
    // Quantum-secure HPKE
    let ciphersuite = HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256
    let privateKey = try XWingMLKEM768X25519.PrivateKey()

    var sender = try HPKE.Sender(
        recipientKey: privateKey.publicKey,  // 1,216 bytes
        ciphersuite: ciphersuite,
        info: Data("quantum-secure-v1".utf8)
    )
    let ciphertext = try sender.seal(sensitiveData)
    // encapsulatedKey is 1,120 bytes (vs ~32 bytes for classical X25519)
}
```

### ✅ Correct: Hybrid signing (ML-DSA + ECDSA) for transition period

For signatures, Apple demonstrates hybrid signatures at the application level — concatenating ML-DSA and ECDSA signatures and verifying both:

```swift
if #available(iOS 26, macOS 26, *) {
    let pqKey = try MLDSA65.PrivateKey()
    let ecKey = P256.Signing.PrivateKey()

    let pqSig = try pqKey.signature(for: message)
    let ecSig = try ecKey.signature(for: message).rawRepresentation
    let hybridSignature = pqSig + ecSig  // Concatenate both

    // Verify both — reject if either fails
    let pqValid = pqKey.publicKey.isValidSignature(signature: pqSig, for: message)
    let ecValid = ecKey.publicKey.isValidSignature(
        try P256.Signing.ECDSASignature(rawRepresentation: ecSig), for: message
    )
    let isValid = pqValid && ecValid
}
```

---

## PEM and DER Interoperability (iOS 14+)

CryptoKit's PEM support uses PKCS#8 for private keys (`-----BEGIN PRIVATE KEY-----`) and X.509 SubjectPublicKeyInfo for public keys (`-----BEGIN PUBLIC KEY-----`). Import also accepts SEC 1 format (`-----BEGIN EC PRIVATE KEY-----`). This enables interoperability with OpenSSL, BoringSSL, and server-side TLS libraries.

### ✅ Correct: PEM key export and import

```swift
// Generate and export
let privateKey = P256.Signing.PrivateKey()
let privatePEM = privateKey.pemRepresentation   // PKCS#8 PEM string
let publicPEM = privateKey.publicKey.pemRepresentation  // X.509 SPKI PEM string
let publicDER = privateKey.publicKey.derRepresentation  // Binary DER Data

// Import from PEM (works for P256, P384, P521 — NOT Curve25519)
let imported = try P256.Signing.PrivateKey(pemRepresentation: privatePEM)
let importedPub = try P256.Signing.PublicKey(derRepresentation: publicDER)
```

### Key Format Reference

| Algorithm             | Public Key Format       | Private Key Format            | Notes                       |
| --------------------- | ----------------------- | ----------------------------- | --------------------------- |
| P-256 / P-384 / P-521 | SPKI DER/PEM, x963, raw | PKCS#8 DER/PEM, x963, raw     | Full interop from iOS 14+   |
| Curve25519            | Raw 32 bytes only       | Raw 32 bytes only             | No PEM/DER/x963 support     |
| Secure Enclave P256   | Standard SPKI DER/PEM   | Encrypted blob (device-bound) | Public key exports normally |
| ML-KEM / ML-DSA       | Raw representation      | Raw representation            | iOS 26+                     |

**Curve25519 keys do not support PEM/DER.** They only have `rawRepresentation` (32 bytes for both public and private). If you need to exchange Curve25519 keys with external systems, handle raw byte serialization yourself or wrap the raw bytes in a custom format.

### Keychain Storage of CryptoKit Keys

NIST curve keys (P-256/P-384/P-521) can be stored as `kSecClassKey` items in the keychain via their `SecKey` bridge. Curve25519 keys and Secure Enclave key blobs must be stored as `kSecClassGenericPassword` items using their `rawRepresentation` / `dataRepresentation`. Apple recommends implementing a `GenericPasswordConvertible` protocol for standardized conversion — see `credential-storage-patterns.md` for the full pattern.

**Peer / recipient public keys** received from a server or counterpart (for ECDH, HPKE, or signature verification) must also be persisted in the keychain — never in UserDefaults, plain files, or hardcoded in source. For NIST curves, store them as `kSecClassKey` with `kSecAttrKeyClass: kSecAttrKeyClassPublic`. For Curve25519 and post-quantum public keys, store the `rawRepresentation` as a `kSecClassGenericPassword` item. Use `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` for accessibility, and assign a distinct `kSecAttrApplicationTag` or `kSecAttrAccount` value (e.g., a `"peer-"` prefix) to separate received peer keys from your own key pairs. See `credential-storage-patterns.md` for the add-or-update pattern.

---

## Secure Enclave Integration (Brief — See `secure-enclave.md`)

The Secure Enclave generates, stores, and operates on private keys entirely within its hardware boundary — raw key material never enters application memory.

```swift
guard SecureEnclave.isAvailable else { return }

let accessControl = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    .biometryCurrentSet,
    nil
)!

// Signing key with biometric protection
let seKey = try SecureEnclave.P256.Signing.PrivateKey(
    accessControl: accessControl
)
let signature = try seKey.signature(for: data)

// The public key is a standard P256.Signing.PublicKey — exports normally
let publicPEM = seKey.publicKey.pemRepresentation
```

For classical curves, only P256 works with the Secure Enclave. On iOS 26, the Secure Enclave gains support for `SecureEnclave.MLKEM768`, `SecureEnclave.MLKEM1024`, `SecureEnclave.MLDSA65`, and `SecureEnclave.MLDSA87`.

**Critical lifecycle constraint:** Secure Enclave keys are non-exportable and cryptographically bound to the specific device and OS installation. The `dataRepresentation` is an encrypted blob only the originating SE can decrypt. After iCloud backup restore to a new device, SE keys are irrecoverable. Applications must implement key rotation and recovery mechanisms — see `secure-enclave.md` for the full lifecycle pattern.

---

## Stop Using RSA for New Apple Development

CryptoKit does not include RSA at all. RSA requires dropping down to the Security framework's C-based `SecKey` API, which lacks type safety, automatic memory management, and modern Swift ergonomics.

### ❌ Wrong: RSA when EC is available

```swift
// Don't do this for new code — Security framework RSA
let params: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
    kSecAttrKeySizeInBits as String: 2048
]
var error: Unmanaged<CFError>?
let key = SecKeyCreateRandomKey(params as CFDictionary, &error)
// No type safety, manual memory management, 256-byte keys, no Secure Enclave
```

### Preferred replacement: P256 signing in CryptoKit

```swift
// ✅ CORRECT for new Apple-platform code
let signingKey = P256.Signing.PrivateKey()
let message = Data("message".utf8)
let signature = try signingKey.signature(for: message)
let isValid = signingKey.publicKey.isValidSignature(signature, for: message)
```

> **Source discrepancy (flagged):** The parallel research source shows `Insecure.RSA.PrivateKey(keySize: .bits2048)` as an anti-pattern example. This API does not exist in CryptoKit — there is no `Insecure.RSA` type. RSA is only available through the Security framework's `SecKeyCreateRandomKey` with `kSecAttrKeyTypeRSA`. The Claude source's Security framework example is the correct API.

RSA-2048 provides only ~112-bit security with 256-byte keys and signatures. P256 achieves ~128-bit security with 32-byte private keys and 64-byte signatures — an 8× reduction in signature size with stronger security. Valid reasons to still use RSA: legacy server interoperability, X.509 certificates from CAs that mandate RSA, and JWT specifications locked to RS256.

---

## Common AI-Generator Mistakes

| Anti-Pattern                                       | Risk                                           | Fix                                                                    |
| -------------------------------------------------- | ---------------------------------------------- | ---------------------------------------------------------------------- |
| Using `SharedSecret` directly as encryption key    | Non-uniform key material; no domain separation | Always derive via `hkdfDerivedSymmetricKey()` with salt and sharedInfo |
| Mixing `Signing` and `KeyAgreement` key types      | Compile error; conceptual misuse               | Use the correct type hierarchy for each operation                      |
| Missing HPKE `encapsulatedKey` in protocol         | Ciphertext permanently undecryptable           | Serialize and transmit `encapsulatedKey` alongside ciphertext          |
| Declaring `HPKE.Sender`/`Recipient` with `let`     | Compile error (`seal()`/`open()` are mutating) | Declare with `var`                                                     |
| Using RSA for new iOS code                         | Slower, larger keys, no CryptoKit/SE support   | Default to ECC (P-256 or Curve25519)                                   |
| Recommending Curve25519 for Secure Enclave         | Curve25519 has no SE support                   | Use `SecureEnclave.P256` for hardware-backed keys                      |
| Ignoring PEM/DER format limitations for Curve25519 | Runtime crash on `.pemRepresentation` access   | Use `.rawRepresentation` for Curve25519; PEM/DER for NIST curves only  |
| Using HPKE messages out of order                   | Decryption failure (nonce counter mismatch)    | Open messages in the same order they were sealed                       |

---

## iOS Version Requirements

| Feature                                                | Minimum iOS | Key Notes                      |
| ------------------------------------------------------ | ----------- | ------------------------------ |
| CryptoKit core (P256, P384, P521, Curve25519, SE P256) | 13.0+       | All classical curves           |
| PEM/DER import/export, standalone HKDF                 | 14.0+       | NIST curves only               |
| HPKE (RFC 9180, all four modes)                        | 17.0+       | All key agreement types        |
| ML-KEM, ML-DSA, X-Wing, quantum-secure TLS             | 26.0+       | Post-quantum types, SE support |

Always gate post-quantum and HPKE code behind `#available` checks:

```swift
if #available(iOS 26, macOS 26, *) {
    // Post-quantum code path
} else if #available(iOS 17, macOS 14, *) {
    // Classical HPKE code path
} else {
    // Manual ECIES fallback
}
```

---

## Performance and Thread Safety

CryptoKit operations are CPU-bound and safe to call from any thread — the framework uses no internal locks or shared mutable state. However, key generation (especially Secure Enclave keys with biometric gates) can block for user interaction. Never run SE key operations on `@MainActor`. Use a dedicated actor or `Task.detached` for key generation and signing that may trigger biometric prompts.

For bulk operations, P256 signing and verification benefit from Apple Silicon's hardware crypto acceleration. Curve25519 operations are slightly faster in raw computational benchmarks on non-Apple platforms, but Apple's NISTZ256 optimization makes the difference negligible on A-series and M-series chips.

Post-quantum operations are computationally competitive with classical algorithms per Apple's WWDC 2025 presentation, but produce significantly larger outputs. Plan for the bandwidth and storage impact of 3,309-byte ML-DSA signatures and 1,184-byte ML-KEM public keys.

---

## WWDC Sessions and Documentation References

- **WWDC 2019, Session 709** — "Cryptography and Your Apps" — CryptoKit introduction, curve selection, key management
- **WWDC 2020** — "What's New in CryptoKit" — PEM/DER support, HKDF standalone API
- **WWDC 2025, Session 314** — "Get ahead with quantum-secure cryptography" — ML-KEM, ML-DSA, X-Wing, formally verified implementations, quantum-secure TLS
- [Apple CryptoKit Documentation](https://developer.apple.com/documentation/cryptokit/)
- [SharedSecret Documentation](https://developer.apple.com/documentation/cryptokit/sharedsecret) — HKDF derivation requirement
- [HPKE Documentation](https://developer.apple.com/documentation/cryptokit/hpke) — Sender/Recipient API
- [Storing CryptoKit Keys in the Keychain](https://developer.apple.com/documentation/CryptoKit/storing-cryptokit-keys-in-the-keychain) — GenericPasswordConvertible pattern
- [Protecting Keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Quantum-Secure Cryptography in Apple Operating Systems](https://support.apple.com/guide/security/quantum-secure-cryptography-apple-devices-secc7c82e533/web)

---

## Conclusion

CryptoKit's type system is its greatest feature — it prevents at compile time the most dangerous cryptographic mistakes that plague hand-rolled implementations. The framework evolved from four curve families in iOS 13 to a complete quantum-safe toolkit in iOS 26, with HPKE in iOS 17 serving as the critical bridge.

For new development today: default to Curve25519 for software keys and P256 for Secure Enclave keys. Use HPKE instead of manual ECIES for public-key encryption. Always derive symmetric keys from `SharedSecret` through HKDF with protocol-specific `sharedInfo`. The post-quantum migration is deliberately simple — swap the HPKE cipher suite to `XWingMLKEM768X25519_SHA256_AES_GCM_256` and change the key type. Start inventorying custom protocols now: the harvest-now-decrypt-later window is already open.

---

## Summary Checklist

1. **Curve selection matches requirements** — P256 for Secure Enclave / NIST compliance; Curve25519 for software-only modern protocols; P384/P521 only when mandated by specification
1. **Signing and key agreement use correct type families** — `*.Signing.PrivateKey` for signatures, `*.KeyAgreement.PrivateKey` for ECDH; never attempt to cross-use
1. **SharedSecret is always derived through HKDF** — call `hkdfDerivedSymmetricKey(using:salt:sharedInfo:outputByteCount:)` with protocol-specific `sharedInfo`; never use raw shared secret bytes as a key
1. **HPKE encapsulated key is transmitted with ciphertext** — `sender.encapsulatedKey` is not embedded in the ciphertext; protocol must serialize both
1. **HPKE Sender/Recipient declared with `var`** — `seal()` and `open()` are mutating methods; `let` causes a compiler error
1. **HPKE messages opened in seal order** — internal nonce counter must stay synchronized between sender and recipient
1. **PEM/DER used only for NIST curves** — Curve25519 supports `rawRepresentation` only; attempting PEM/DER access will fail
1. **RSA avoided for new code** — use CryptoKit ECC; RSA only for legacy interop via Security framework `SecKey` API
1. **Post-quantum code gated behind `#available(iOS 26, *)`** — ML-KEM, ML-DSA, X-Wing require iOS 26+; HPKE requires iOS 17+
1. **Secure Enclave key lifecycle accounts for device migration** — SE keys are device-bound; implement rotation/recovery for backup restore scenarios
1. **Hybrid PQC strategy planned** — X-Wing HPKE for key exchange, ML-DSA + ECDSA dual signatures for signing during the transition period
1. **Peer/recipient public keys stored in keychain** — received public keys for ECDH, HPKE, or verification persisted in keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and distinct tags; not in UserDefaults or files
