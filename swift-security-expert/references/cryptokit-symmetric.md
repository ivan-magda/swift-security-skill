# CryptoKit Symmetric Cryptography

> **Scope:** SHA-2/SHA-3 hashing, HMAC authentication, AES-GCM and ChaChaPoly authenticated encryption, SymmetricKey management, nonce handling, key derivation (HKDF + PBKDF2), and CommonCrypto migration. iOS 13+ baseline; SHA-3 requires iOS 18+.
>
> **Key APIs:** `SHA256`, `SHA384`, `SHA512`, `SHA3_256` (iOS 18+), `HMAC`, `AES.GCM.seal/open`, `ChaChaPoly.seal/open`, `SymmetricKey`, `AES.GCM.Nonce`, `HKDF`, `SealedBox`
>
> **Cross-references:** [secure-enclave.md] for hardware-backed asymmetric keys · [cryptokit-public-key.md] for ECDSA/ECDH/HPKE · [credential-storage-patterns.md] for key storage in Keychain · [common-anti-patterns.md] for the top-5 AI mistakes including hardcoded keys and nonce reuse

---

## Hashing: SHA-2 and SHA-3

CryptoKit's hash functions follow a unified `HashFunction` protocol. The SHA-2 family (`SHA256`, `SHA384`, `SHA512`) ships with iOS 13+. The SHA-3 family (`SHA3_256`, `SHA3_384`, `SHA3_512`) requires **iOS 18+ / macOS 15+ / tvOS 18+ / visionOS 2+** (added in 2024, per Apple's SHA3_256 documentation page).

> **Cross-validation note:** One research source claimed SHA-3 requires iOS 26+. This is incorrect. Apple's official documentation lists SHA3_256 availability as iOS 18.0+, macOS 15.0+. iOS 26 introduced post-quantum primitives (ML-KEM, ML-DSA), not SHA-3.

All hash functions produce digest types that conform to `Sequence` (of `UInt8`), `ContiguousBytes`, `Hashable`, and `CustomStringConvertible`. Digest equality checks use **constant-time comparison** internally to prevent timing side-channels.

### One-Shot Hashing

**✅ Correct: SHA-256 hashing with hex output**

```swift
import CryptoKit

let data = "Hello, CryptoKit".data(using: .utf8)!
let digest = SHA256.hash(data: data)

// Convert to hex string — Digest conforms to Sequence
let hexString = digest.map { String(format: "%02x", $0) }.joined()

// Constant-time comparison
let otherDigest = SHA256.hash(data: data)
if digest == otherDigest {
    print("Integrity verified")
}
```

Never rely on `.description` for hex output — Apple warns its format may change between OS versions.

### Streaming Hash for Large Files

**✅ Correct: Incremental hashing to avoid loading entire file into memory**

```swift
var hasher = SHA256()
let fileHandle = try FileHandle(forReadingFrom: fileURL)
while autoreleasepool(invoking: {
    let chunk = fileHandle.readData(ofLength: 1_048_576) // 1 MB chunks
    guard !chunk.isEmpty else { return false }
    hasher.update(data: chunk)
    return true
}) {}
let digest = hasher.finalize()
```

All hash functions support `init()` → `update(data:)` → `finalize()`. The `autoreleasepool` wrapper prevents memory accumulation during chunk reads.

### SHA-3 with Availability Check

**✅ Correct: SHA-3 with fallback (iOS 18+)**

```swift
func computeHash(data: Data) -> String {
    if #available(iOS 18.0, macOS 15.0, *) {
        let digest = SHA3_256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    } else {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
```

SHA-3 uses a completely different internal construction (Keccak sponge) from SHA-2 (Merkle-Damgård). The API surface is identical — only the type name changes. Adopt SHA-3 when compliance standards require it or for defense-in-depth against future SHA-2 structural weaknesses.

### Insecure Hash Functions

**❌ Wrong: Using MD5 or SHA-1 for any security purpose**

```swift
// NEVER — MD5 collision resistance is ~2^18 operations (seconds on commodity hardware)
let broken = Insecure.MD5.hash(data: data)

// SHA-1 fell to chosen-prefix collisions in 2020 (~$45,000 GPU time)
let alsoBroken = Insecure.SHA1.hash(data: data)
```

CryptoKit deliberately places both in the `Insecure` namespace as an API-level warning. Use `SHA256` minimum for all security purposes — it is equally fast on modern hardware and provides actual collision resistance.

**Algorithm selection quick reference:**

| Algorithm | Type            | Availability | Status     | Use When                                   |
| --------- | --------------- | ------------ | ---------- | ------------------------------------------ |
| SHA-256   | `SHA256`        | iOS 13+      | Strong     | Default for integrity, signing, HMAC       |
| SHA-384   | `SHA384`        | iOS 13+      | Strong     | Certificate chains, higher security margin |
| SHA-512   | `SHA512`        | iOS 13+      | Strong     | Large data, performance on 64-bit          |
| SHA3-256  | `SHA3_256`      | iOS 18+      | Strong     | Compliance requiring SHA-3                 |
| SHA3-384  | `SHA3_384`      | iOS 18+      | Strong     | Future-proofing                            |
| SHA3-512  | `SHA3_512`      | iOS 18+      | Strong     | High-security contexts                     |
| MD5       | `Insecure.MD5`  | iOS 13+      | **Broken** | Legacy non-security checksums only         |
| SHA-1     | `Insecure.SHA1` | iOS 13+      | **Broken** | Legacy non-security checksums only         |

---

## HMAC: Message Authentication with Symmetric Keys

HMAC combines a hash function with a secret key to produce an authentication code. CryptoKit's `HMAC<H>` is generic over any `HashFunction`, provides constant-time verification, and supports both one-shot and streaming patterns.

**✅ Correct: HMAC generation and verification**

```swift
import CryptoKit

let key = SymmetricKey(size: .bits256)
let message = "Transfer $500 to account 12345".data(using: .utf8)!

// Generate authentication code
let mac = HMAC<SHA256>.authenticationCode(for: message, using: key)

// Verify — constant-time comparison prevents timing attacks
let isValid = HMAC<SHA256>.isValidAuthenticationCode(
    mac, authenticating: message, using: key
)

// Serialize MAC for transmission
let macData = Data(mac)
```

**Critical:** Always use `isValidAuthenticationCode(_:authenticating:using:)` for verification — never manually compare raw bytes with `==`. CryptoKit's method uses `safeCompare` internally, which runs in constant time regardless of how many bytes match, defeating timing side-channel attacks.

The return type `HMAC<SHA256>.MAC` (alias for `HashedAuthenticationCode<SHA256>`) conforms to `ContiguousBytes`, `Sequence`, `Hashable`, and `CustomStringConvertible`.

**Common HMAC use cases:** API request signing, webhook payload verification, data integrity in transit, token-based authentication schemes. HMAC proves authenticity and integrity — not confidentiality. For encryption, use AES-GCM or ChaChaPoly below.

---

## AES-GCM: Authenticated Encryption in One Operation

AES-GCM is CryptoKit's primary symmetric cipher, providing **Authenticated Encryption with Associated Data (AEAD)** — confidentiality, integrity, and authenticity in a single `seal()` call. This eliminates the historically dangerous pattern of combining AES-CBC + HMAC manually.

### Basic Encryption and Decryption

**✅ Correct: AES-GCM encryption with automatic nonce**

```swift
import CryptoKit

let key = SymmetricKey(size: .bits256)
let plaintext = "Sensitive data".data(using: .utf8)!

// Encrypt — CryptoKit auto-generates a random 12-byte nonce
let sealedBox = try AES.GCM.seal(plaintext, using: key)

// Serialize for storage/transmission: nonce(12) || ciphertext || tag(16)
guard let combined = sealedBox.combined else {
    fatalError("Combined representation unavailable (non-standard nonce size)")
}

// Deserialize and decrypt
let restoredBox = try AES.GCM.SealedBox(combined: combined)
let decrypted = try AES.GCM.open(restoredBox, using: key)
```

The `SealedBox` contains three components: a **12-byte nonce**, the **ciphertext** (same length as plaintext), and a **16-byte authentication tag**. The `combined` property is `Data?` (optional) because non-standard nonce sizes prevent combined representation. For ChaChaPoly, `combined` is non-optional.

### Associated Data (AAD)

**✅ Correct: Binding ciphertext to context with associated data**

```swift
let metadata = "user:42,action:payment".data(using: .utf8)!
let sealedBox = try AES.GCM.seal(plaintext, using: key, authenticating: metadata)

// Decryption requires the same AAD — tampered metadata causes authenticationFailure
let decrypted = try AES.GCM.open(sealedBox, using: key, authenticating: metadata)
```

Associated data is authenticated but **not encrypted**. Use it to bind ciphertext to context (user ID, timestamp, resource identifier) so encrypted data cannot be transplanted to a different context without detection.

### The Catastrophic Danger of Nonce Reuse

**❌ CRITICAL: Never reuse a nonce with the same key**

```swift
// CATASTROPHIC — enables FULL key recovery
let staticNonce = try AES.GCM.Nonce(data: Data(repeating: 0, count: 12))
let box1 = try AES.GCM.seal(message1, using: key, nonce: staticNonce)
let box2 = try AES.GCM.seal(message2, using: key, nonce: staticNonce)
// With C1 and C2, attacker computes: C1 ⊕ C2 = P1 ⊕ P2
```

Nonce reuse in AES-GCM is not "bad practice" — it is a **total cryptographic break** known as the "Forbidden Attack" (Joux, 2006):

1. **Plaintext recovery:** Identical nonce + key produces identical keystream. XORing two ciphertexts yields `P1 ⊕ P2`. If either plaintext is known or guessable, the other is immediately recovered.
2. **Authentication forgery:** GCM's authentication uses GHASH, a polynomial over GF(2^128) with a secret hash key `H = AES_k(0^128)`. Two messages sharing a nonce yield a polynomial equation solvable via Cantor-Zassenhaus root-finding to recover H. Once H is known, the attacker can **forge valid authentication tags for arbitrary messages**.

A USENIX WOOT'16 study found 184 HTTPS servers reusing AES-GCM nonces in production, including financial institutions.

**The fix:** Omit the `nonce:` parameter entirely. CryptoKit generates cryptographically random 12-byte nonces automatically, giving collision probability below 2^-32 after 2^32 encryptions under the same key. Only supply explicit nonces when interoperating with external systems that dictate nonce values.

---

## ChaChaPoly: Software-Friendly AEAD Alternative

ChaCha20-Poly1305 provides equivalent AEAD security with an identical API surface. It exists primarily for **software-only environments** where it delivers constant-time execution without hardware acceleration, eliminating cache-timing side channels that plague software AES implementations.

**✅ Correct: ChaChaPoly encryption**

```swift
let key = SymmetricKey(size: .bits256)
let sealedBox = try ChaChaPoly.seal(plaintext, using: key)

// ChaChaPoly.SealedBox.combined is non-optional (unlike AES.GCM)
let combined = sealedBox.combined

// Decrypt
let restoredBox = try ChaChaPoly.SealedBox(combined: combined)
let decrypted = try ChaChaPoly.open(restoredBox, using: key)
```

The API mirrors AES-GCM exactly — same `seal`/`open` methods, same `SealedBox` structure. Switching between ciphers requires changing only the type name.

### Performance: AES-GCM vs ChaChaPoly on Apple Hardware

On all Apple Silicon (A-series since A7, all M-series), **AES-GCM is significantly faster** due to dedicated hardware AES instructions:

| Metric              | AES-256-GCM                                                   | ChaChaPoly  | Source                  |
| ------------------- | ------------------------------------------------------------- | ----------- | ----------------------- |
| Throughput (M2 Pro) | ~3–4 GB/s                                                     | ~1.5–2 GB/s | OpenSSL benchmarks      |
| Relative speed      | 134%–236% faster                                              | Baseline    | Ashvardanian (2025)     |
| Apple internal use  | Keychain encryption, file Data Protection, Watch↔iPhone comms | —           | Platform Security Guide |

**Default to AES-GCM on Apple hardware.** Choose ChaChaPoly when: targeting platforms without hardware AES acceleration, requiring guaranteed constant-time behavior independent of hardware, or interoperating with ChaCha20-based protocols (WireGuard, some TLS configurations).

### Streaming Encryption Limitation

Neither `seal()` nor `open()` supports streaming — both operate on the full message in memory. For large files, implement a **chunked AEAD scheme** with unique nonces per chunk and a monotonic chunk index in AAD to prevent reordering attacks. Alternatively, use Apple's file-level Data Protection (AES-XTS via the hardware crypto engine) for at-rest file encryption.

---

## SymmetricKey: Creation, Derivation, and Lifecycle

`SymmetricKey` is CryptoKit's opaque key container. It **zeroes memory on deallocation** (confirmed WWDC 2019-709 and Apple documentation), prevents accidental exposure (no `Data` property — only `withUnsafeBytes` access), and validates key sizes at construction.

### Random Key Generation

**✅ Correct: Cryptographically random key**

```swift
let key = SymmetricKey(size: .bits256) // 32 bytes, cryptographically random
// Also available: .bits128, .bits192
```

For quantum resilience, prefer `.bits256`. Grover's algorithm halves effective symmetric key strength — AES-256 retains 128-bit security against quantum adversaries, while AES-128 drops to 64-bit (insufficient).

### Password-Based Key Derivation (PBKDF2 + HKDF)

**❌ Wrong: Raw password as key material**

```swift
// NEVER — passwords have ~20-40 bits of entropy, not 256
let key = SymmetricKey(data: "MyPassword123".data(using: .utf8)!)
// Trivially brute-forceable via dictionary attack — no computational cost barrier, no salt
```

CryptoKit ships HKDF but **not** PBKDF2. For password-based key derivation, use CommonCrypto's `CCKeyDerivationPBKDF` first, then optionally HKDF for subkey derivation:

**✅ Correct: Password → key via PBKDF2 + HKDF**

```swift
import CommonCrypto
import CryptoKit

// Step 1: PBKDF2 stretches the low-entropy password
let password = "MyPassword123"
let salt = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
var derivedBytes = [UInt8](repeating: 0, count: 32)

CCKeyDerivationPBKDF(
    CCPBKDFAlgorithm(kCCPBKDF2),
    password, password.utf8.count,
    Array(salt), salt.count,
    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
    600_000,  // OWASP 2023 recommended minimum for HMAC-SHA256
    &derivedBytes, derivedBytes.count
)

// Step 2: HKDF derives purpose-specific subkeys (domain separation)
let masterKey = SymmetricKey(data: derivedBytes)
let encryptionKey = HKDF<SHA256>.deriveKey(
    inputKeyMaterial: masterKey,
    info: Data("encryption".utf8),
    outputByteCount: 32
)
let authKey = HKDF<SHA256>.deriveKey(
    inputKeyMaterial: masterKey,
    info: Data("authentication".utf8),
    outputByteCount: 32
)
```

> **Iteration count note:** One research source used 100,000 iterations. The OWASP 2023 Password Storage Cheat Sheet recommends **600,000 iterations minimum** for PBKDF2-HMAC-SHA256. Use ≥600,000 for new implementations; only use lower counts if supporting legacy interoperability with documented justification.

**Critical distinction:** HKDF is designed for already-high-entropy input (shared secrets, master keys). It does **not** add computational cost. Never use HKDF alone for passwords — always PBKDF2 first.

### HKDF for High-Entropy Key Derivation

**✅ Correct: Deriving subkeys from a high-entropy master key**

```swift
// When input is already high-entropy (e.g., ECDH shared secret)
let inputKey = SymmetricKey(size: .bits256)
let derivedKey = HKDF<SHA256>.deriveKey(
    inputKeyMaterial: inputKey,
    salt: Data("app-specific-salt".utf8),
    info: Data("aes-encryption-key-v1".utf8),
    outputByteCount: 32
)
```

HKDF follows RFC 5869 and supports one-shot `deriveKey()` and two-phase `extract()` → `expand()`. Use distinct `info` strings for domain separation when deriving multiple subkeys from a single shared secret. Available since iOS 14+.

> **API note:** `HKDF.deriveKey()` does not throw — no `try` required despite some code examples showing it.

### Key Storage and Hardcoding

**❌ Wrong: Hardcoding keys in source code**

```swift
// NEVER — extractable via `strings` command on the binary
let key = SymmetricKey(data: Data(base64Encoded: "c2VjcmV0S2V5MTIzNDU2Nzg5MDEyMzQ1Ng==")!)
```

A Zimperium 2025 study found 48% of mobile apps contain hardcoded secrets. iOS binaries can be decrypted and analyzed with tools like Hopper or IDA Pro. **Store keys in the Keychain** with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, derive them at runtime from user credentials, or fetch from a secure server. See [credential-storage-patterns.md] for detailed patterns.

**SymmetricKey memory behavior:** Keys live in regular process memory (not the Secure Enclave — only asymmetric `SecureEnclave.P256` keys are hardware-backed). CryptoKit automatically overwrites key material during deallocation. For persistent storage, serialize to the Keychain — never UserDefaults or files.

---

## Migrating from CommonCrypto to CryptoKit

CommonCrypto's C API requires manual buffer allocation, unsafe pointer management, and provides no authenticated encryption. CryptoKit replaces all common operations with type-safe Swift that is harder to misuse.

### Hashing: CC_SHA256 → SHA256

```swift
// ❌ Legacy CommonCrypto — unsafe pointers, manual buffer sizing
import CommonCrypto
var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
data.withUnsafeBytes { bytes in
    CC_SHA256(bytes.baseAddress, CC_LONG(data.count), &digest)
}

// ✅ CryptoKit — one line, type-safe
import CryptoKit
let digest = SHA256.hash(data: data)
```

### Encryption: CCCrypt (AES-CBC) → AES.GCM

```swift
// ❌ Legacy CommonCrypto — AES-CBC, unauthenticated, manual IV, buffer math
import CommonCrypto
var outputBuffer = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
var numBytesEncrypted = 0
let status = CCCrypt(
    CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES),
    CCOptions(kCCOptionPKCS7Padding),
    keyBytes, kCCKeySizeAES256, ivBytes,
    dataBytes, data.count,
    &outputBuffer, outputBuffer.count, &numBytesEncrypted
)
// ⚠️ Still need to add HMAC separately for integrity!

// ✅ CryptoKit — one line, authenticated, automatic nonce
import CryptoKit
let sealedBox = try AES.GCM.seal(data, using: key)
```

The critical architectural shift: CommonCrypto's `CCCrypt` provides AES-CBC (unauthenticated). Without manual Encrypt-then-MAC (HMAC), CBC ciphertext is vulnerable to **padding oracle attacks** and silent tampering. CryptoKit's AES-GCM bundles authentication — `open()` throws `CryptoKitError.authenticationFailure` if any byte is modified.

### HMAC: CCHmac → HMAC

```swift
// ❌ Legacy CommonCrypto — C-style pointers
import CommonCrypto
var hmac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),
       keyBytes, keyData.count, dataBytes, data.count, &hmac)

// ✅ CryptoKit — generic, type-safe, constant-time verification built in
import CryptoKit
let mac = HMAC<SHA256>.authenticationCode(for: data, using: key)
let valid = HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: data, using: key)
```

### What to Keep in CommonCrypto

CryptoKit deliberately omits: **PBKDF2** (use `CCKeyDerivationPBKDF`), **AES-CBC** (needed for legacy system interop), **AES-ECB** (almost never appropriate). For everything else, CryptoKit is the correct choice.

---

## AI Code Generator Mistakes

Large language models producing iOS cryptography code frequently introduce these errors:

**1. Using CommonCrypto instead of CryptoKit.** Models trained on older code default to `CC_SHA256` and `CCCrypt`. These require manual memory management and lack authenticated encryption. Always use CryptoKit for iOS 13+ targets.

**2. Reusing or hardcoding nonces.** Generators sometimes create a nonce once and reuse it, or use `Data(repeating: 0, count: 12)`. This enables complete AES-GCM key recovery (see nonce reuse section above). Omit the `nonce:` parameter to use automatic generation.

**3. Using AES-CBC without authentication.** Models produce `CCCrypt`-based AES-CBC without HMAC, leaving ciphertext vulnerable to padding oracle attacks. AES-GCM and ChaChaPoly authenticate by default — no reason for unauthenticated encryption in new code.

**4. Creating SymmetricKey directly from a password string.** `SymmetricKey(data: password.data(using: .utf8)!)` appears constantly. This skips key stretching entirely. Use PBKDF2 (≥600,000 iterations) for passwords, then optionally HKDF for subkey derivation.

**5. Recommending MD5 or SHA-1 for checksums.** Models suggest `Insecure.MD5` for file integrity. SHA-256 is equally fast on modern hardware with actual collision resistance.

**6. Manual SealedBox serialization.** Generators sometimes manually concatenate nonce + ciphertext + tag instead of using `SealedBox.combined`. This introduces serialization bugs — use the built-in `combined` property and `SealedBox(combined:)` initializer.

---

## Quantum Considerations for Symmetric Cryptography

WWDC 2025 session 314 ("Get ahead with quantum-secure cryptography") introduced ML-KEM and ML-DSA for asymmetric crypto (see [cryptokit-public-key.md]). For symmetric crypto, quantum computers weaken effective key strength by roughly half via Grover's algorithm:

- **AES-256:** 128-bit post-quantum security — **sufficient**
- **AES-128:** 64-bit post-quantum security — **insufficient**

**Recommendation:** Use `SymmetricKey(size: .bits256)` exclusively. Quantum-secure TLS 1.3 is enabled by default in iOS 26 for `URLSession` and Network.framework connections.

CryptoKit is built on Apple's **corecrypto** library (FIPS 140-2/140-3 validated, hand-tuned assembly per Apple microarchitecture). Apple's hardware crypto engine sits in the DMA path between flash storage and system memory, performing inline AES-256 encryption at line speed with zero CPU overhead.

---

## OWASP Mapping

CryptoKit symmetric practices address **OWASP Mobile Top 10 M10 (Insufficient Cryptography)**: weak algorithms, insufficient key lengths, improper key management, flawed implementation.

**Relevant MASTG test cases:** MASTG-TEST-0061 (algorithm configuration), MASTG-TEST-0062 (key management), MASTG-TEST-0209 (insufficient key sizes), MASTG-TEST-0210 (broken symmetric algorithms), MASTG-TEST-0211 (broken hashing), MASTG-TEST-0213 (hardcoded keys), MASTG-TEST-0317 (broken encryption modes).

**MASTG knowledge base:** MASTG-KNOW-0066 (CryptoKit), MASTG-KNOW-0067 (CommonCrypto).

**MASWE entries:** MASWE-0010 (improper key derivation), MASWE-0013 (hardcoded cryptographic keys), MASWE-0020 (improper encryption), MASWE-0021 (improper hashing), MASWE-0022 (predictable initialization vectors).

See [compliance-owasp-mapping.md] for the full compliance matrix.

---

## Testing Guidance

| Test Case                                  | What It Proves                 | Expected Outcome                       |
| ------------------------------------------ | ------------------------------ | -------------------------------------- |
| AES-GCM decrypt after ciphertext tampering | Authentication works           | `CryptoKitError.authenticationFailure` |
| AES-GCM decrypt with wrong AAD             | Metadata binding               | `CryptoKitError.authenticationFailure` |
| HMAC verify with wrong key                 | Timing-safe verification       | Returns `false`                        |
| HMAC verify with tampered message          | Integrity detection            | Returns `false`                        |
| SHA-3 availability fallback                | Backward compatibility         | Falls back to SHA-256 on <iOS 18       |
| SealedBox round-trip (combined format)     | Serialization correctness      | Decrypted output matches plaintext     |
| PBKDF2 + HKDF derivation determinism       | Key derivation reproducibility | Same password + salt → same key        |

**CI scanning rules:** Flag `Insecure.MD5`, `Insecure.SHA1`, `CCCrypt`, `SymmetricKey(data:` followed by string literal, and hardcoded base64 key patterns in code review.

---

## WWDC and Reference Citations

- **WWDC 2019-709** — "Cryptography and Your Apps": CryptoKit introduction, SymmetricKey memory zeroing, automatic nonce generation rationale
- **WWDC 2020** — "What's New in CryptoKit": HKDF addition (iOS 14), expanded key agreement
- **WWDC 2025 Session 314** — "Get ahead with quantum-secure cryptography": AES-256 quantum guidance, SHA-3 context, ML-KEM/ML-DSA (asymmetric)
- **Apple CryptoKit Documentation** — https://developer.apple.com/documentation/cryptokit/
- **Apple Platform Security Guide** — corecrypto FIPS validation, hardware crypto engine, file Data Protection
- **OWASP Mobile Top 10 (2024)** — M10: Insufficient Cryptography
- **OWASP MASTG** — iOS cryptographic testing methodology
- **RFC 5869** — HKDF specification
- **Joux (2006)** — "Authentication Failures in NIST version of GCM" (nonce reuse attack)

---

## Conclusion

CryptoKit's design philosophy — authenticated encryption by default, automatic nonce generation, memory zeroing, constant-time comparisons — eliminates the most common categories of cryptographic implementation errors. For new code: `AES.GCM.seal()` with automatic nonces for encryption, `SHA256` (or `SHA3_256` on iOS 18+) for hashing, `HMAC<SHA256>` for authentication, and `SymmetricKey(size: .bits256)` for key generation. Derive keys from passwords with PBKDF2 (≥600,000 iterations, CommonCrypto) followed by HKDF (CryptoKit) — never pass raw passwords to `SymmetricKey(data:)`. Store keys in the Keychain, not source code. Prefer AES-GCM over ChaChaPoly on Apple hardware for the hardware acceleration advantage, but ChaChaPoly remains sound for cross-platform consistency or software-only environments.

---

## Summary Checklist

1. **CryptoKit over CommonCrypto** — All new hashing, HMAC, and encryption uses `import CryptoKit`, not `import CommonCrypto` (except PBKDF2)
2. **SHA-256 minimum** — No `Insecure.MD5` or `Insecure.SHA1` for any security purpose; CI rules flag these
3. **AES-GCM or ChaChaPoly** — All symmetric encryption uses AEAD; no unauthenticated AES-CBC in new code
4. **Automatic nonces** — The `nonce:` parameter is omitted from `seal()` calls unless protocol-mandated; no static or zero nonces
5. **256-bit keys** — `SymmetricKey(size: .bits256)` for quantum resilience; no `.bits128` for security-sensitive data
6. **PBKDF2 before HKDF for passwords** — Password → `CCKeyDerivationPBKDF` (≥600,000 iterations, ≥16-byte random salt) → `SymmetricKey` → optional HKDF for subkeys; never raw password to `SymmetricKey(data:)`
7. **SealedBox.combined for serialization** — Use `.combined` / `SealedBox(combined:)` for storage and network; no manual nonce/ciphertext/tag concatenation
8. **Keys in Keychain** — Symmetric keys persisted via Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; no hardcoded keys in source, no UserDefaults, no plist
9. **Constant-time HMAC verification** — Use `HMAC.isValidAuthenticationCode()`, never manual byte comparison
10. **SHA-3 availability guarded** — `SHA3_256` wrapped in `#available(iOS 18.0, macOS 15.0, *)` with SHA-256 fallback
11. **Associated data for context binding** — AES-GCM `authenticating:` parameter used when ciphertext must be bound to metadata (user ID, resource ID, version)
