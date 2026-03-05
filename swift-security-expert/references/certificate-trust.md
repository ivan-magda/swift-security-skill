# Certificate Trust Evaluation & Pinning

> **Scope**: SecCertificate, SecTrust evaluation, SecIdentity, certificate pinning strategies (leaf / intermediate CA / SPKI hash / NSPinnedDomains), custom trust policies, client certificate authentication (mTLS), ATS interaction, and operational pin management. iOS 12+ through iOS 18, macOS 10.14+ through macOS 15.
>
> **Out of scope**: Network-layer encryption beyond TLS certificate handling, server-side certificate management, App Transport Security as a standalone topic (covered briefly where it intersects pinning).

---

## Core Security Types

| Type             | Purpose                                                           | Key Operations                                                                                                                  |
| ---------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `SecCertificate` | X.509 certificate (DER-encoded)                                   | `SecCertificateCreateWithData`, `SecCertificateCopyKey` (iOS 12+), `SecCertificateCopyData`, `SecCertificateCopySubjectSummary` |
| `SecTrust`       | Trust evaluation context for a certificate chain against policies | `SecTrustCreateWithCertificates`, `SecTrustEvaluateWithError` (iOS 12+), `SecTrustEvaluateAsyncWithError` (iOS 13+)             |
| `SecIdentity`    | Private key + certificate pair for client authentication          | Extracted via `SecPKCS12Import`; used with `URLCredential(identity:certificates:persistence:)`                                  |
| `SecPolicy`      | Validation policy (SSL hostname check, revocation)                | `SecPolicyCreateSSL`, `SecPolicyCreateRevocation`                                                                               |

---

## Trust Evaluation APIs

Three trust evaluation functions exist. Only two are current.

### SecTrustEvaluateAsyncWithError — recommended async API (iOS 13+)

```swift
func SecTrustEvaluateAsyncWithError(
    _ trust: SecTrust,
    _ queue: dispatch_queue_t,
    _ result: @escaping (SecTrust, Bool, CFError?) -> Void
) -> OSStatus
```

The callback receives a Boolean result and optional error. The callback may fire synchronously if the trust object has a cached result. Always dispatch on a **background queue** — evaluation may perform network access for intermediate certificate fetching or revocation checks.

```swift
// ✅ CORRECT: Async trust evaluation with proper error handling
func evaluateTrust(_ trust: SecTrust, completion: @escaping (Bool, Error?) -> Void) {
    let queue = DispatchQueue.global(qos: .userInitiated)
    queue.async {
        let status = SecTrustEvaluateAsyncWithError(trust, queue) { _, result, error in
            completion(result, error as Error?)
        }
        if status != errSecSuccess {
            completion(false, NSError(domain: NSOSStatusErrorDomain, code: Int(status)))
        }
    }
}
```

Apple has **not** added native async/await wrappers to the Security framework through iOS 18. Wrap manually:

```swift
// ✅ CORRECT: Swift concurrency wrapper
func evaluateTrust(_ trust: SecTrust) async throws -> Bool {
    try await withCheckedThrowingContinuation { continuation in
        let queue = DispatchQueue.global(qos: .userInitiated)
        queue.async {
            let status = SecTrustEvaluateAsyncWithError(trust, queue) { _, result, error in
                if result {
                    continuation.resume(returning: true)
                } else {
                    continuation.resume(throwing: error! as Error)
                }
            }
            if status != errSecSuccess {
                continuation.resume(throwing: NSError(
                    domain: NSOSStatusErrorDomain, code: Int(status)))
            }
        }
    }
}
```

### SecTrustEvaluateWithError — synchronous, still current (iOS 12+)

```swift
func SecTrustEvaluateWithError(_ trust: SecTrust, _ error: UnsafeMutablePointer<CFError?>?) -> Bool
```

**Not deprecated.** Valid inside `URLSessionDelegate` callbacks (already off main thread). Apple's warning: do not call from the main run loop — it may require network access.

### SecTrustEvaluate — deprecated since iOS 13

```swift
// ❌ DEPRECATED: Returns opaque SecTrustResultType without error context
func SecTrustEvaluate(_ trust: SecTrust,
                      _ result: UnsafeMutablePointer<SecTrustResultType>) -> OSStatus
```

Returns a `SecTrustResultType` enum requiring manual interpretation. Replaced by `SecTrustEvaluateWithError`. **AI generators frequently produce this pattern — reject on sight.**

### SecTrustResultType reference

For code that must inspect results after evaluation via `SecTrustGetTrustResult`:

| Result                     | Meaning                                      | Action                            |
| -------------------------- | -------------------------------------------- | --------------------------------- |
| `.unspecified`             | Chain validates to implicitly trusted anchor | **Proceed** — most common success |
| `.proceed`                 | User explicitly chose to trust this cert     | **Proceed**                       |
| `.deny`                    | User explicitly marked cert as untrusted     | **Reject** — never override       |
| `.recoverableTrustFailure` | Failed but recovery possible                 | Inspect, possibly reconfigure     |
| `.fatalTrustFailure`       | Fundamental certificate defect               | **Reject**                        |
| `.otherError`              | Non-trust error (revoked, OS error)          | **Reject**                        |
| `.invalid`                 | No evaluation performed yet                  | Call evaluation first             |

Modern `SecTrustEvaluateWithError` collapses this to a Boolean. Treat only `.unspecified` and `.proceed` as success.

---

## Custom Trust Policy Configuration

```swift
// ✅ CORRECT: SSL policy with hostname verification
let policy = SecPolicyCreateSSL(true, "api.example.com" as CFString)
// true = server evaluation; hostname enables SNI matching

var trust: SecTrust?
SecTrustCreateWithCertificates(certificateChain as CFTypeRef, policy, &trust)
```

```swift
// ✅ CORRECT: Custom anchor while preserving system trust store
SecTrustSetAnchorCertificates(trust, [customRootCA] as CFArray)
SecTrustSetAnchorCertificatesOnly(trust, false)  // false = ALSO trust system anchors
```

```swift
// ❌ INCORRECT: Missing SecTrustSetAnchorCertificatesOnly
SecTrustSetAnchorCertificates(trust, [customRootCA] as CFArray)
// Without SecTrustSetAnchorCertificatesOnly(trust, false), ALL system anchors
// are silently disabled — only your custom CA is trusted!
```

```swift
// ❌ INCORRECT: nil hostname disables hostname verification entirely
let policy = SecPolicyCreateSSL(true, nil)
// Any valid certificate for ANY domain now passes — MITM vector
```

---

## Four Pinning Strategies

### Leaf certificate pinning — breaks on every renewal

Commercial TLS certificates expire every 90 days (Let's Encrypt) to 398 days (CA/Browser Forum maximum). When the server renews, the certificate bytes change (new serial, validity dates, signature) and the pin breaks. Users are locked out until an App Store update ships.

```swift
// ❌ DANGEROUS: Leaf pinning that breaks on every certificate renewal
guard let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
      let serverCert = chain.first else {
    completionHandler(.cancelAuthenticationChallenge, nil)
    return
}
let serverCertData = SecCertificateCopyData(serverCert) as Data
let localCertData = // loaded from bundle .cer file

if serverCertData == localCertData {
    completionHandler(.useCredential, URLCredential(trust: serverTrust))
} else {
    // WILL fire when the certificate renews, locking out all users
    completionHandler(.cancelAuthenticationChallenge, nil)
}
```

**Verdict**: never use in production unless you control the full certificate lifecycle AND can update pins without App Store review.

### Intermediate CA pinning — 5–10 year validity window

Pin an intermediate CA certificate. Any leaf issued by that CA passes the check. The server can freely renew its leaf certificate.

```swift
// ✅ CORRECT: Intermediate CA pinning (resilient to leaf renewal)
guard let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate] else {
    completionHandler(.cancelAuthenticationChallenge, nil)
    return
}

let pinnedIntermediateData = // load intermediate CA .cer from bundle

for cert in chain {
    let certData = SecCertificateCopyData(cert) as Data
    if certData == pinnedIntermediateData {
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
        return
    }
}
completionHandler(.cancelAuthenticationChallenge, nil)
```

**Tradeoff**: trusts any certificate from that CA, not just yours. If the CA is compromised, a same-CA certificate could impersonate your server.

### SPKI hash pinning — survives renewal with same key pair

Hashes the SubjectPublicKeyInfo (SPKI) structure. When certificates renew **with the same key pair**, the SPKI stays identical. This is the **recommended programmatic approach**.

**Critical correctness issue**: `SecKeyCopyExternalRepresentation` returns raw key bytes **without** the ASN.1 SPKI header. You must prepend the correct header before hashing. Omitting this produces incorrect hashes that won't match pins generated via OpenSSL.

> ⚠️ **Cross-validation note**: The parallel research source omits the ASN.1 header prepend step and uses deprecated `SecTrustGetCertificateAtIndex`. The code below uses the correct modern APIs with proper SPKI construction.

```swift
// ✅ CORRECT: SPKI hash pinning with ASN.1 header and modern APIs
class SPKIPinningDelegate: NSObject, URLSessionDelegate {

    // ASN.1 headers for reconstructing SPKI from raw key data
    private static let rsa2048Header: [UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]
    private static let ecP256Header: [UInt8] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00
    ]

    private let pinnedHashes: Set<String>  // Base64(SHA256(SPKI))

    init(pinnedHashes: Set<String>) {
        self.pinnedHashes = pinnedHashes
    }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                                  URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod
                == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // Step 1: ALWAYS validate the chain via system trust first
        guard SecTrustEvaluateWithError(serverTrust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Step 2: Walk chain and check SPKI hashes
        guard let chain = SecTrustCopyCertificateChain(serverTrust)
                as? [SecCertificate] else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        for cert in chain {
            if let hash = spkiHash(for: cert), pinnedHashes.contains(hash) {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    private func spkiHash(for certificate: SecCertificate) -> String? {
        guard let publicKey = SecCertificateCopyKey(certificate),
              let keyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              let attrs = SecKeyCopyAttributes(publicKey) as? [CFString: Any],
              let keyType = attrs[kSecAttrKeyType] as? String,
              let keySize = attrs[kSecAttrKeySizeInBits] as? Int else { return nil }

        let header: [UInt8]
        switch (keyType, keySize) {
        case (kSecAttrKeyTypeRSA as String, 2048): header = Self.rsa2048Header
        case (kSecAttrKeyTypeRSA as String, 4096):
            // Add RSA-4096 header for production use
            return nil
        case (kSecAttrKeyTypeECSECPrimeRandom as String, 256):
            header = Self.ecP256Header
        default: return nil
        }

        var spki = Data(header)
        spki.append(keyData)

        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        spki.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(spki.count), &hash)
        }
        return Data(hash).base64EncodedString()
    }
}
```

Generate expected SPKI hashes from the command line:

```bash
# From a PEM certificate file:
openssl x509 -in cert.pem -noout -pubkey | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | openssl enc -base64

# From a live server:
openssl s_client -connect api.example.com:443 </dev/null 2>/dev/null | \
  openssl x509 -pubkey -noout | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | openssl enc -base64
```

### NSPinnedDomains — declarative pinning, zero code (iOS 14+)

Apple's recommended approach. Enforced automatically by `URLSession` via ATS. Uses SPKI hashes.

```xml
<!-- ✅ CORRECT: CA identity pinning with backup pin via NSPinnedDomains -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSPinnedDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <key>NSIncludesSubdomains</key>
            <true/>
            <key>NSPinnedCAIdentities</key>
            <array>
                <dict>
                    <key>SPKI-SHA256-BASE64</key>
                    <string>PrimaryCA_SPKI_Hash_Base64==</string>
                </dict>
                <dict>
                    <!-- Backup CA from a different provider -->
                    <key>SPKI-SHA256-BASE64</key>
                    <string>BackupCA_SPKI_Hash_Base64==</string>
                </dict>
            </array>
        </dict>
    </dict>
</dict>
```

Available keys per pinned domain:

- **`NSPinnedCAIdentities`** — matches any intermediate or root in the chain (logical OR within array)
- **`NSPinnedLeafIdentities`** — matches the leaf certificate only
- **`NSIncludesSubdomains`** — covers first-level subdomains when `true`

If **both** `NSPinnedCAIdentities` and `NSPinnedLeafIdentities` are specified, ATS requires a match in **each** category (AND between categories, OR within each).

**Limitations**: works with `URLSession` and `WKWebView` (iOS 16+ after earlier bugs were fixed). Does not work with `SFSafariViewController`. Pins are visible in `Info.plist` and cannot be updated without an app update.

### Pinning Strategy Decision Matrix

| Strategy         | Resilience                        | Specificity                | Update Frequency     | Best For                         |
| ---------------- | --------------------------------- | -------------------------- | -------------------- | -------------------------------- |
| Leaf certificate | ❌ Breaks every 90–398 days       | Highest — exact cert match | Every renewal        | Never in production              |
| Intermediate CA  | ✅ 5–10 years                     | Medium — all certs from CA | Rarely               | Single-CA-provider apps          |
| SPKI hash (code) | ✅ Survives renewal with same key | High — specific key        | Only on key rotation | Dynamic pinsets, custom logic    |
| NSPinnedDomains  | ✅ Survives renewal with same key | High — SPKI-based          | Only on key rotation | **Default choice for most apps** |

---

## SecCertificate and SecIdentity

### Creating certificates from DER data

```swift
// ✅ CORRECT: Load .cer from app bundle
guard let certURL = Bundle.main.url(forResource: "server", withExtension: "cer"),
      let certData = try? Data(contentsOf: certURL),
      let certificate = SecCertificateCreateWithData(nil, certData as CFData) else {
    fatalError("Failed to load certificate")
}

let summary = SecCertificateCopySubjectSummary(certificate) as String?
let publicKey = SecCertificateCopyKey(certificate)           // iOS 12+
let derBytes  = SecCertificateCopyData(certificate) as Data  // Round-trip to DER
```

`SecCertificateCreateWithData` accepts **DER-encoded** data only — not PEM. For PEM files, strip the `-----BEGIN CERTIFICATE-----` header/footer and Base64-decode.

### Importing PKCS#12 for client certificate authentication

```swift
// ✅ CORRECT: Import .p12 and extract SecIdentity
func importIdentity(from p12Data: Data, password: String) throws -> SecIdentity {
    let options: [String: Any] = [kSecImportExportPassphrase as String: password]
    var rawItems: CFArray?
    let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &rawItems)

    guard status == errSecSuccess,
          let items = rawItems as? [[String: Any]],
          let firstItem = items.first,
          let identity = firstItem[kSecImportItemIdentity as String] as? SecIdentity else {
        throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }
    return identity
}
```

Result dictionary keys from `SecPKCS12Import`:

- **`kSecImportItemIdentity`** (`SecIdentity`) — private key + certificate pair
- **`kSecImportItemCertChain`** (`[SecCertificate]`) — full certificate chain
- **`kSecImportItemTrust`** (`SecTrust`) — pre-configured trust object
- **`kSecImportItemKeyID`** (`Data`) — typically SHA-1 hash of public key

**Never bundle passwords with your app.** Prompt the user or read from the Keychain.

### Client certificate authentication in URLSession

```swift
// ✅ CORRECT: Mutual TLS delegate handling both server trust and client cert
class MutualTLSDelegate: NSObject, URLSessionDelegate {
    private let identity: SecIdentity
    private let certChain: [SecCertificate]?

    init(identity: SecIdentity, certChain: [SecCertificate]? = nil) {
        self.identity = identity
        self.certChain = certChain
    }

    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                                  URLCredential?) -> Void) {
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodClientCertificate:
            let credential = URLCredential(
                identity: identity,
                certificates: certChain,
                persistence: .forSession
            )
            completionHandler(.useCredential, credential)

        case NSURLAuthenticationMethodServerTrust:
            guard let trust = challenge.protectionSpace.serverTrust,
                  SecTrustEvaluateWithError(trust, nil) else {
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
            completionHandler(.useCredential, URLCredential(trust: trust))

        default:
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
```

Client certificate challenges are **session-wide** (`URLSessionDelegate`), not task-specific. Apps must manage certificates within their sandbox — they cannot access system-wide certificates installed via MDM.

### Certificate chain inspection (backward-compatible)

```swift
// ✅ CORRECT: Backward-compatible chain inspection
func certificateChain(from trust: SecTrust) -> [SecCertificate] {
    if #available(iOS 15.0, macOS 12.0, *) {
        return SecTrustCopyCertificateChain(trust) as? [SecCertificate] ?? []
    } else {
        return (0..<SecTrustGetCertificateCount(trust)).compactMap {
            SecTrustGetCertificateAtIndex(trust, $0)
        }
    }
}
```

---

## Anti-Patterns AI Code Generators Produce

| Anti-Pattern                                                                  | Risk                                            | Correct Replacement                                                   |
| ----------------------------------------------------------------------------- | ----------------------------------------------- | --------------------------------------------------------------------- |
| Using deprecated `SecTrustEvaluate`                                           | No error context, deprecated iOS 13             | `SecTrustEvaluateWithError` or `SecTrustEvaluateAsyncWithError`       |
| Disabling ATS globally                                                        | Enables trivial MITM, triggers App Store review | `NSAllowsLocalNetworking` for dev; targeted exceptions for production |
| `SecTrustSetAnchorCertificates` without `SetAnchorCertificatesOnly(_, false)` | Silently disables all system anchors            | Always pair both calls                                                |
| `SecPolicyCreateSSL` with `nil` hostname                                      | Disables hostname verification — MITM vector    | Always pass the actual expected hostname                              |
| Skipping system trust eval before pin checks                                  | Expired/revoked certs pass pin checks           | Always `SecTrustEvaluateWithError` first, then check pins             |
| Using `SecTrustGetCertificateAtIndex`                                         | Deprecated iOS 15                               | `SecTrustCopyCertificateChain` (with backward-compat fallback)        |
| Using `SecTrustCopyPublicKey`                                                 | Deprecated iOS 14                               | `SecCertificateCopyKey` or `SecTrustCopyKey`                          |
| SPKI hashing without ASN.1 header                                             | Produces wrong hash, pins never match           | Prepend correct ASN.1 SPKI header before SHA-256                      |
| Evaluating trust on `.main` queue                                             | UI freezes during network-dependent checks      | Always use background dispatch queue                                  |

```xml
<!-- ❌ DANGEROUS: Never ship this -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>

<!-- ✅ CORRECT: Local networking only for development -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsLocalNetworking</key>
    <true/>
</dict>
```

---

## Backup Pins, Rotation, and Graceful Degradation

**Always include at least two pins.** A single pin means any certificate revocation, CA compromise, or unplanned key rotation bricks your app's networking.

**Backup strategy**: pre-generate a backup key pair, compute its SPKI hash, include it as a pin — without deploying the corresponding certificate. If the primary key is compromised, issue a certificate for the backup key server-side. The app already trusts it.

**When all pins fail**: display a clear error that server credentials could not be verified, switch to offline/cached mode, **never allow the user to bypass the pin**, log for diagnostics. Recovery requires an App Store update (consumer apps) or MDM profile update (managed deployments).

**OWASP's current nuanced position**: pinning should only be done when you control both client and server, can update the pinset securely, and have a clear rotation strategy. Certificate Transparency (enforced on Apple platforms since iOS 12.1.1) plus Apple's revocation infrastructure provides substantial protection without pinning's operational risk.

---

## ATS Interaction Points

ATS enforces TLS 1.2+, 2048-bit RSA or 256-bit ECC keys, SHA-256+ hashing, AES-128/256, and forward secrecy on all `URLSession` connections.

**iOS 17 change**: ATS now requires HTTPS for connections to bare IP addresses (not just domain names).

Keys that trigger additional App Store review: `NSAllowsArbitraryLoads`, `NSAllowsArbitraryLoadsForMedia`, `NSAllowsArbitraryLoadsInWebContent`, `NSExceptionAllowsInsecureHTTPLoads`, `NSExceptionMinimumTLSVersion`.

Use `nscurl --ats-diagnostics https://your-server.com` on macOS to diagnose ATS compatibility.

---

## API Deprecation Timeline

| OS Version           | Year | Key Changes                                                                            |
| -------------------- | ---- | -------------------------------------------------------------------------------------- |
| iOS 12 / macOS 10.14 | 2018 | `SecTrustEvaluateWithError` introduced; Certificate Transparency enforced (iOS 12.1.1) |
| iOS 13 / macOS 10.15 | 2019 | `SecTrustEvaluateAsyncWithError` introduced; `SecTrustEvaluate` deprecated             |
| iOS 14 / macOS 11    | 2020 | **`NSPinnedDomains`** introduced; `SecTrustCopyKey` replaces `SecTrustCopyPublicKey`   |
| iOS 15 / macOS 12    | 2021 | **`SecTrustCopyCertificateChain`** replaces `SecTrustGetCertificateAtIndex`/`Count`    |
| iOS 17 / macOS 14    | 2023 | ATS enforced for IP addresses; EAP-TLS 1.3 support                                     |
| iOS 18 / macOS 15    | 2024 | Swift 6 strict concurrency affects callback-based Security code; no new SecTrust APIs  |

---

## Thread Safety and Performance

- SecTrust objects are thread-safe only **across different instances**. Never access the same `SecTrust` from multiple threads.
- Different `SecTrust` objects can be evaluated concurrently on different threads.
- On iOS, all Certificate/Key/Trust Services functions are thread-safe and reentrant.
- On macOS, trust evaluation can **block on user interaction** (keychain unlock dialogs) — always evaluate on background threads.
- `SecTrust`, `SecCertificate`, and `SecKey` are **not** marked `Sendable`. With Swift 6 strict concurrency, use `@unchecked Sendable` wrappers or explicit actor isolation.

---

## CI/CD Guardrails

- **Fail builds** if `NSAllowsArbitraryLoads` is `true` in production `Info.plist`.
- **Validate** that `SecPolicyCreateSSL` is never called with a `nil` hostname in production code paths.
- **Enforce** that any `NSPinnedDomains` entry contains at least two SPKI hashes (backup pin requirement).
- **Scan** for deprecated APIs: `SecTrustEvaluate(`, `SecTrustGetCertificateAtIndex(`, `SecTrustCopyPublicKey(`.
- **Test** pinning with certificate rotation in staging before production deployment.

---

## Cross-Validation Notes

Both research sources agree on all major recommendations. Key discrepancies in the parallel source (corrected in this file):

1. **Deprecated API in code example**: Parallel source uses `SecTrustGetCertificateAtIndex(trust, 0)` — deprecated iOS 15. Corrected to `SecTrustCopyCertificateChain`.
2. **Missing ASN.1 header**: Parallel source hashes raw key bytes without prepending the SPKI ASN.1 header, producing incorrect hashes. Corrected with explicit header prepend.
3. **Deprecated `SecTrustCopyPublicKey` reference**: Parallel source references this API — deprecated iOS 14. Corrected to `SecCertificateCopyKey`.
4. **Main queue evaluation**: Parallel source evaluates on `.main` queue. Corrected to background queue.

---

## Cross-References

- `keychain-item-classes.md` — `kSecClassCertificate` and `kSecClassIdentity` storage, PKCS#12 import patterns
- `keychain-fundamentals.md` — SecItem CRUD patterns for certificate and identity persistence
- `cryptokit-public-key.md` — PEM/DER key interoperability, curve selection for client certificates
- `compliance-owasp-mapping.md` — M5 (Insecure Communication) trust evaluation requirements

---

## WWDC and Reference Citations

- **WWDC 2017 Session 709** — "Your Apps and Evolving Network Security Standards" (ATS, CT, pinning guidance)
- **Apple Developer Documentation** — "Evaluating a Trust and Parsing the Result", `SecTrustEvaluateAsyncWithError`, `NSPinnedDomains`
- **Apple Platform Security Guide** — Revocation infrastructure, Certificate Transparency
- **Apple News Article** — "Identity Pinning: How to configure server certificates for your app"
- **OWASP Pinning Cheat Sheet** — Strategy recommendations, backup pin guidance
- **OWASP MASTG** — Certificate pinning test cases

---

## Summary Checklist

1. **Trust evaluation uses modern API** — `SecTrustEvaluateWithError` (sync) or `SecTrustEvaluateAsyncWithError` (async); no deprecated `SecTrustEvaluate`
2. **Trust evaluation runs off main thread** — background dispatch queue for async; URLSession delegate callbacks already off-main for sync
3. **Pinning strategy avoids leaf certificates** — use SPKI hash pinning, intermediate CA pinning, or `NSPinnedDomains`; never pin raw leaf certificate bytes in production
4. **At least two pins configured** — primary + backup from different CA or pre-generated backup key pair
5. **System trust evaluated before pin checks** — always call `SecTrustEvaluateWithError` first, then compare SPKI hashes; never skip chain validation
6. **SPKI hashing includes ASN.1 header** — prepend correct algorithm-specific header before SHA-256 hashing raw key bytes from `SecKeyCopyExternalRepresentation`
7. **Custom anchors preserve system trust** — `SecTrustSetAnchorCertificates` paired with `SecTrustSetAnchorCertificatesOnly(_, false)` unless intentionally restricting
8. **SSL policy binds hostname** — `SecPolicyCreateSSL` always receives actual expected hostname, never `nil`
9. **ATS not globally disabled** — no `NSAllowsArbitraryLoads: true` in production; use targeted exceptions (`NSAllowsLocalNetworking`, per-domain exceptions)
10. **Chain inspection uses current APIs** — `SecTrustCopyCertificateChain` (iOS 15+) with fallback to `SecTrustGetCertificateAtIndex` for older targets; `SecCertificateCopyKey` not `SecTrustCopyPublicKey`
11. **Client certificate passwords not bundled** — PKCS#12 passwords prompted at runtime or stored in Keychain, never hardcoded or embedded in app bundle
