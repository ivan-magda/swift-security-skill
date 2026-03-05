# Keychain Item Classes

> Scope: Correct class selection and attribute usage for all five `kSecClass` types, with emphasis on uniqueness rules, AutoFill behavior, and migration safety.

The five `kSecClass` types — GenericPassword, InternetPassword, Key, Certificate, and Identity — each serve distinct roles with unique attribute requirements that AI code generators routinely get wrong. **Choosing the wrong class** causes silent AutoFill failures, query collisions, and subtle security degradation. This reference covers every class with its composite primary key, required and optional attributes, correct Swift patterns, and the specific mistakes to watch for.

The keychain is an encrypted SQLite database optimized for small secrets. Each item class defines a set of attributes forming a **composite primary key** — adding an item whose primary key matches an existing item returns `errSecDuplicateItem` (-25299). Understanding these primary keys is the single most important concept for correct keychain usage.

**Sources:** Apple Keychain Services documentation, TN3137 ("On Mac keychain APIs and implementations"), Quinn "The Eskimo!" DTS posts ("SecItem: Fundamentals," "SecItem: Pitfalls and Best Practices"), Apple Platform Security Guide, WWDC 2022–2024 passkey sessions, OWASP MASVS/MASTG.

---

## Composite Primary Keys by Class

Every `kSecClass` defines a specific attribute set forming its uniqueness constraint. `kSecAttrAccessGroup` and `kSecAttrSynchronizable` participate in the primary key for all classes.

| Class                | Primary Key Attributes                                                                                                                                | Typical Use                                       |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| **GenericPassword**  | `kSecAttrService` + `kSecAttrAccount`                                                                                                                 | App-specific secrets, API tokens, encryption keys |
| **InternetPassword** | `kSecAttrServer` + `kSecAttrProtocol` + `kSecAttrPort` + `kSecAttrPath` + `kSecAttrAccount` + `kSecAttrSecurityDomain` + `kSecAttrAuthenticationType` | Web credentials, server passwords, AutoFill       |
| **Key**              | `kSecAttrApplicationLabel` + `kSecAttrApplicationTag` + `kSecAttrKeyClass` + `kSecAttrKeyType` + `kSecAttrKeySizeInBits` + `kSecAttrEffectiveKeySize` | RSA/EC keys, symmetric keys                       |
| **Certificate**      | `kSecAttrCertificateType` + `kSecAttrIssuer` + `kSecAttrSerialNumber`                                                                                 | X.509 certificates                                |
| **Identity**         | Same as Certificate (virtual join, not a stored item)                                                                                                 | TLS client auth, code signing                     |

Omitting a primary key attribute does not cause an error — the system uses a nil/empty default. But a second add with the same defaults produces `errSecDuplicateItem`, which is a frequent source of confusion.

---

## kSecClassGenericPassword — App-Specific Secrets

GenericPassword is the correct choice for API tokens, OAuth refresh tokens, encryption keys, and any secret that does not represent a web login credential. Its primary key is effectively **`kSecAttrService` + `kSecAttrAccount`**.

**Required for meaningful usage** (not enforced by the API, but omitting them causes collisions): `kSecAttrService` (CFString — typically bundle ID or service identifier) and `kSecAttrAccount` (CFString — the account or key name). The actual secret goes in `kSecValueData` as `Data`.

**Optional metadata attributes:** `kSecAttrLabel` (human-readable name), `kSecAttrDescription` (item kind), `kSecAttrComment` (user-editable note), `kSecAttrCreator` and `kSecAttrType` (FourCharCode as CFNumber), `kSecAttrGeneric` (arbitrary CFData for custom metadata), `kSecAttrIsInvisible`/`kSecAttrIsNegative` (boolean flags). System-managed read-only: `kSecAttrCreationDate`, `kSecAttrModificationDate`.

### The kSecAttrGeneric trap

`kSecAttrGeneric` is **NOT part of the primary key** despite its name suggesting otherwise. Two items with identical `kSecAttrService` + `kSecAttrAccount` but different `kSecAttrGeneric` values still collide — the second add fails with `errSecDuplicateItem`. Yet querying by `kSecAttrGeneric` that does not match returns `errSecItemNotFound` even though an item with that service+account exists. This inconsistency is a major source of bugs.

```swift
// ✅ GenericPassword for an app-specific API token
let addQuery: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.myapp.api",
    kSecAttrAccount as String: "oauth-refresh-token",
    kSecValueData as String: tokenString.data(using: .utf8)!,
    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    kSecUseDataProtectionKeychain as String: true
]
let status = SecItemAdd(addQuery as CFDictionary, nil)
```

**When to choose GenericPassword vs InternetPassword:** If the credential belongs to a web domain and you want AutoFill, use InternetPassword. GenericPassword's `kSecAttrService` is an opaque string with no semantic meaning to the system — it cannot trigger Password AutoFill.

---

## kSecClassInternetPassword — AutoFill and Credential Sharing

InternetPassword exists specifically for credentials associated with network services. Its **7-attribute composite primary key** enables the system to match credentials to domains for Password AutoFill, Safari integration, and cross-device sync.

Primary key attributes: `kSecAttrServer` (hostname), `kSecAttrProtocol` (e.g., `kSecAttrProtocolHTTPS`), `kSecAttrPort` (CFNumber), `kSecAttrPath` (URL path), `kSecAttrAccount` (username), `kSecAttrSecurityDomain` (HTTP realm), `kSecAttrAuthenticationType` (e.g., `kSecAttrAuthenticationTypeHTMLForm`).

**Notable:** `kSecAttrGeneric` and `kSecAttrService` are **NOT available** for InternetPassword — the server/protocol/path attributes serve the equivalent purpose.

### How AutoFill Integration Works

Password AutoFill matches credentials to apps and websites by comparing `kSecAttrServer` against associated domains. Full integration requires three pieces:

1. **Store credentials as InternetPassword** with `kSecAttrServer` set to the website domain
2. **Configure Associated Domains** by adding `webcredentials:<domain>` to the app's entitlements
3. **Host an apple-app-site-association file** at `https://<domain>/.well-known/apple-app-site-association` containing `{"webcredentials": {"apps": ["TEAMID.com.example.app"]}}`

When all three are in place, the iOS QuickType bar automatically suggests matching credentials. Safari stores all web passwords as `kSecClassInternetPassword` — using GenericPassword for web credentials means the system can never suggest them for AutoFill.

```swift
// ✅ InternetPassword enabling AutoFill
let addQuery: [String: Any] = [
    kSecClass as String: kSecClassInternetPassword,
    kSecAttrServer as String: "example.com",
    kSecAttrProtocol as String: kSecAttrProtocolHTTPS,
    kSecAttrPort as String: 443,
    kSecAttrPath as String: "/login",
    kSecAttrAccount as String: "user@example.com",
    kSecAttrAuthenticationType as String: kSecAttrAuthenticationTypeHTMLForm,
    kSecValueData as String: "password123".data(using: .utf8)!,
    kSecUseDataProtectionKeychain as String: true
]
let status = SecItemAdd(addQuery as CFDictionary, nil)
```

```swift
// ❌ GenericPassword for web credentials — AutoFill will never find these
let badQuery: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,       // WRONG CLASS
    kSecAttrService as String: "example.com",             // Opaque to AutoFill
    kSecAttrAccount as String: "user@example.com",
    kSecValueData as String: "password123".data(using: .utf8)!
]
```

### Protocol and Authentication Constants

Protocol constants span **30+ values** including `kSecAttrProtocolHTTPS`, `kSecAttrProtocolHTTP`, `kSecAttrProtocolSSH`, `kSecAttrProtocolFTP`, `kSecAttrProtocolIMAPS`, `kSecAttrProtocolSMTP`, and many more. Authentication types include `kSecAttrAuthenticationTypeHTMLForm`, `kSecAttrAuthenticationTypeHTTPBasic`, `kSecAttrAuthenticationTypeHTTPDigest`, and `kSecAttrAuthenticationTypeDefault`.

### Credential Provider Extensions (iOS 12+)

For third-party password managers, `ASCredentialProviderViewController` enables credential provider extensions. Apps subclass this controller, populate `ASCredentialIdentityStore` with `ASPasswordCredentialIdentity` instances, and override `provideCredentialWithoutUserInteraction(for:)` for tap-to-fill behavior.

---

## kSecClassKey — Cryptographic Key Management

Key items require **`kSecAttrKeyType`** and **`kSecAttrKeySizeInBits`** for generation — omitting either from `SecKeyCreateRandomKey` returns `errSecParam` (-50). The `kSecAttrKeyClass` attribute (`kSecAttrKeyClassPublic`, `kSecAttrKeyClassPrivate`, `kSecAttrKeyClassSymmetric`) is set automatically during generation but must be specified when querying.

### ApplicationTag vs ApplicationLabel — The Critical Distinction

This confusion is the single most common keychain mistake for cryptographic keys, and AI generators get it wrong constantly:

- **`kSecAttrApplicationTag`** (CFData): **Developer-set** binary tag for finding and organizing keys. You choose its content — typically a reverse-DNS string encoded as Data. Part of the primary key. **Use this for lookup.**
- **`kSecAttrApplicationLabel`** (CFData): **System-generated** SHA-1 hash of the public key bytes (the `subjectPublicKey` element per RFC 5280 §4.1). Part of the primary key. **Used internally for identity formation** — it must match a certificate's `kSecAttrPublicKeyHash` to synthesize a `SecIdentity`. Never set this manually for asymmetric keys.
- **`kSecAttrLabel`** (CFString): Human-readable display name. NOT part of the primary key. Shows in Keychain Access on macOS.

### SecKeyCreateRandomKey — The Preferred API

`SecKeyCreateRandomKey` (iOS 10+, macOS 10.12+) generates keys atomically, returns a `SecKey` reference directly, auto-computes `kSecAttrApplicationLabel`, and supports Secure Enclave generation via `kSecAttrTokenID: kSecAttrTokenIDSecureEnclave`. Apple recommends storing **only the private key** and deriving the public key via `SecKeyCopyPublicKey()`.

```swift
// ✅ EC key creation with SecKeyCreateRandomKey
let tag = "com.myapp.keys.signing".data(using: .utf8)!
let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag
    ]
]
var error: Unmanaged<CFError>?
guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
    throw error!.takeRetainedValue() as Error
}
let publicKey = SecKeyCopyPublicKey(privateKey)!
```

```swift
// ✅ Secure Enclave key with biometric protection
var accessError: Unmanaged<CFError>?
guard let accessControl = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .userPresence],
    &accessError
) else { throw accessError!.takeRetainedValue() as Error }

let tag = "com.myapp.keys.se-signing".data(using: .utf8)!
let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
        kSecAttrAccessControl as String: accessControl
    ]
]
var genError: Unmanaged<CFError>?
guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &genError) else {
    throw genError!.takeRetainedValue() as Error
}
```

Direct `SecItemAdd` for keys is appropriate only when importing — Apple's "import, then add" pattern via `SecKeyCreateWithData`. Always create a `SecKey` object first; avoid adding raw key data directly.

### CryptoKit Key Storage Mapping

CryptoKit's NIST keys (P256, P384, P521) map to `SecKey` via `SecKeyCreateWithData` with `kSecAttrKeyTypeECSECPrimeRandom`, stored as `kSecClassKey`. **Non-NIST keys** (Curve25519, SymmetricKey) have no `SecKey` equivalent and must be stored as **`kSecClassGenericPassword`** items with raw key data in `kSecValueData`. Secure Enclave keys (`SecureEnclave.P256.Signing.PrivateKey`) export an encrypted blob that only the originating SE can restore — this blob is also stored as a generic password, not a key item.

---

## kSecClassCertificate — DER-Encoded Certificate Storage

Certificates are **not encrypted** by the keychain (they are public data). The primary key is `kSecAttrCertificateType` + `kSecAttrIssuer` + `kSecAttrSerialNumber`.

Creation follows a two-step pattern: first create a `SecCertificate` from DER data, then add via `kSecValueRef`:

```swift
// ✅ Adding a certificate
guard let certificate = SecCertificateCreateWithData(nil, derData as CFData) else {
    throw CertificateError.invalidDER  // Only accepts DER, not PEM
}
let addQuery: [String: Any] = [
    kSecClass as String: kSecClassCertificate,
    kSecValueRef as String: certificate,
    kSecUseDataProtectionKeychain as String: true
]
let status = SecItemAdd(addQuery as CFDictionary, nil)
```

When you pass a `SecCertificate` via `kSecValueRef`, the system **automatically extracts** `kSecAttrIssuer`, `kSecAttrSerialNumber`, `kSecAttrSubject`, `kSecAttrPublicKeyHash`, `kSecAttrCertificateType`, and `kSecAttrCertificateEncoding` from the certificate data. The critical attribute for identity formation is **`kSecAttrPublicKeyHash`** — the hash of the certificate's public key that must match a private key's `kSecAttrApplicationLabel`.

**Common pitfall (Apple DTS):** `kSecAttrApplicationTag` is **NOT a valid attribute for certificates** (only for keys). Using it with `kSecClassCertificate` causes `errSecParam` (-50) on the data protection keychain or mysterious silent failures on the file-based keychain.

---

## kSecClassIdentity — The Virtual Join

**The keychain does not store digital identities as discrete items.** An identity is a logical join of a certificate and its matching private key, synthesized at query time when `kSecAttrPublicKeyHash` of a certificate matches `kSecAttrApplicationLabel` of a private key — both values being the SHA-1 hash of the public key.

### Why SecItemAdd with kSecClassIdentity Fails

Attempting `SecItemAdd` with `kSecClass: kSecClassIdentity` will fail with `errSecParam` (-50). The system has no "identity table." Identity items appear only when the matching relationship exists between separately stored certificate and key items.

Cascading implications:

- Adding a **certificate** can implicitly create an identity if a matching private key already exists
- Adding a **private key** can implicitly create an identity if a matching certificate exists
- Deleting a certificate or key can implicitly destroy an identity
- The identity "set" changes without any explicit identity operations

```swift
// ❌ Attempting to create an identity directly — fails with errSecParam (-50)
let attributes: [String: Any] = [
    kSecClass as String: kSecClassIdentity,
    kSecAttrLabel as String: "MyInvalidIdentity"
]
let status = SecItemAdd(attributes as CFDictionary, nil)
// status == errSecParam (-50)
```

### Three Correct Approaches to Creating an Identity

**Method 1: PKCS#12 import** (most common for server-issued certificates):

```swift
// ✅ Import identity from .p12 file
let options: [String: Any] = [kSecImportExportPassphrase as String: "p12password"]
var items: CFArray?
let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
guard status == errSecSuccess,
      let results = items as? [[String: Any]],
      let identity = results.first?[kSecImportItemIdentity as String] as? SecIdentity else {
    throw IdentityError.importFailed
}
// Extract components
var certificate: SecCertificate?
SecIdentityCopyCertificate(identity, &certificate)
var privateKey: SecKey?
SecIdentityCopyPrivateKey(identity, &privateKey)
```

**Method 2: Add certificate and key separately** with matching public key hashes. Both items must be in the same keychain implementation — on macOS, both must use `kSecUseDataProtectionKeychain: true` or both must be in the file-based keychain.

**Method 3: macOS-only** — `SecIdentityCreateWithCertificate` searches keychains for a matching private key given a certificate reference.

---

## Correctness Issues AI Generators Get Wrong

### 1. GenericPassword for Everything

AI code almost universally uses `kSecClassGenericPassword` with `kSecAttrService` for web credentials, completely missing AutoFill integration. The correct pattern uses `kSecClassInternetPassword` with `kSecAttrServer` and associated domains.

### 2. Direct Identity Creation

Generated code attempts `SecItemAdd` with `kSecClassIdentity` as if it were a storable item class. Identities must be created through PKCS#12 import or by adding matching certificate and key items separately.

### 3. Missing Key Type Attributes

Code omits `kSecAttrKeyType` from key queries, producing ambiguous matches across RSA and EC keys. Since key type is part of the composite primary key, this is a correctness bug, not a style issue.

### 4. ApplicationTag / ApplicationLabel Confusion

Generated code sets `kSecAttrApplicationLabel` as a human-readable string, not understanding it is an auto-generated public key hash used for identity matching. The developer-set tag for lookup is `kSecAttrApplicationTag`.

### 5. No Duplicate Handling

AI code calls `SecItemAdd` without handling `errSecDuplicateItem`. The correct pattern either attempts update-first-then-add, or catches the duplicate error and calls `SecItemUpdate`:

```swift
// ✅ Update-first pattern (preferred)
var status = SecItemUpdate(searchQuery as CFDictionary, updateAttrs as CFDictionary)
if status == errSecItemNotFound {
    var addQuery = searchQuery
    addQuery.merge(updateAttrs) { _, new in new }
    status = SecItemAdd(addQuery as CFDictionary, nil)
}
```

### 6. Missing kSecUseDataProtectionKeychain on macOS

Without this flag, macOS defaults to the legacy file-based keychain, causing `kSecAttrAccessible`, `kSecAttrAccessGroup`, and biometric access controls to be silently ignored or behave unexpectedly.

### 7. Storing Large Blobs in Keychain

The keychain is designed for small secrets. Storing large data degrades performance due to Secure Enclave decryption latency per item retrieval. Use envelope encryption for anything beyond a few KB.

---

## Modern API Patterns and Platform Differences

### kSecUseDataProtectionKeychain Unifies Cross-Platform Behavior

On **iOS/tvOS/watchOS**, the data protection keychain is the only implementation — this flag is ignored. On **macOS native apps**, `SecItem` defaults to the legacy file-based keychain. Setting `kSecUseDataProtectionKeychain: true` switches to the data protection keychain, giving iOS-identical behavior. On **Mac Catalyst** apps, data protection is the default.

Apple explicitly recommends setting this flag to `true` for all keychain operations. The file-based keychain is on the path to deprecation (`SecKeychainCreate` deprecated in macOS 12).

### TN3137 Key Takeaways

TN3137 documents macOS's **three keychain APIs** (legacy Keychain, SecKeychain, and the recommended SecItem) and **two implementations** (file-based and data protection). Critical routing rule: only `SecItem` can target either implementation; `SecKeychain` always targets file-based. The data protection keychain requires code signing and a provisioning profile on macOS.

Subtle behavioral difference: `SecItemDelete` defaults to `kSecMatchLimitAll` on the data protection keychain (deleting ALL matching items) but `kSecMatchLimitOne` on the file-based keychain — an inconsistency documented in Apple's bug tracker (r. 105800863).

### iCloud Keychain Sync Restrictions

`kSecAttrSynchronizable` must be explicitly set to `true` — items never sync by default. **All five classes** support sync on iOS 14+ / macOS 11+ / watchOS 7+; earlier versions only sync password classes.

Key restrictions:

- Items with "ThisDeviceOnly" accessibility **cannot** sync — combining `kSecAttrSynchronizable: true` with any `ThisDeviceOnly` accessibility returns `errSecParam` (-50)
- Persistent references are unsupported for synchronizable items
- tvOS accepts the attribute but never actually syncs
- Updates and deletes propagate to all copies across devices

---

## Size Limits, Performance, and When to Use Files

Apple describes the keychain as storing **"small secrets"** without publishing a hard size limit. The underlying SQLite supports items up to approximately **16 MB** (`SQLITE_MAX_LENGTH`), but this is emphatically not the intended use.

### Performance Architecture

The keychain has a direct performance implication: **metadata is encrypted with a cached Application Processor key** (enabling fast attribute queries), while **secret values require a Secure Enclave round trip** per access. This means `kSecReturnAttributes`-only queries are substantially faster than `kSecReturnData` queries. Always request only what you need.

Query optimization rules:

1. **Use full composite keys** — broad queries force `securityd` to perform slow database scans
2. **Limit matches** — use `kSecMatchLimitOne` when expecting a single item to terminate search early
3. **Fetch metadata first** — if you only need to check existence, do not request `kSecReturnData`

### Envelope Encryption for Large Data

For data beyond a few kilobytes, use the **DEK/KEK pattern**: store a 32-byte AES-256 Data Encryption Key (DEK) in the keychain, encrypt the actual data with that key, and write the ciphertext to a file protected by `NSFileProtection`. OWASP MASTG recommends this pattern for MASVS L2 compliance.

Accessibility-to-file-protection mapping:

- `kSecAttrAccessibleWhenUnlocked` → `NSFileProtectionComplete`
- `kSecAttrAccessibleAfterFirstUnlock` → `NSFileProtectionCompleteUntilFirstUserAuthentication`

### Querying with kSecReturnAttributes for Metadata Inspection

```swift
// ✅ Inspect all metadata for a GenericPassword item
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.myapp.api",
    kSecReturnAttributes as String: true,
    kSecReturnData as String: true,
    kSecMatchLimit as String: kSecMatchLimitOne
]
var item: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &item)
guard status == errSecSuccess, let attrs = item as? [String: Any] else { return }

// Available metadata in the returned dictionary:
let account = attrs[kSecAttrAccount as String] as? String
let service = attrs[kSecAttrService as String] as? String
let created = attrs[kSecAttrCreationDate as String] as? Date
let modified = attrs[kSecAttrModificationDate as String] as? Date
let accessible = attrs[kSecAttrAccessible as String] as? String
let syncable = attrs[kSecAttrSynchronizable as String] as? Bool
let secretData = attrs[kSecValueData as String] as? Data
```

When both `kSecReturnAttributes` and `kSecReturnData` are true with `kSecMatchLimitOne`, the result is a single dictionary containing all metadata plus the secret data under `kSecValueData`. With `kSecMatchLimitAll`, it is an array of such dictionaries.

---

## Testing Matrix for Class Correctness

| Test Scenario                                            | Expected OSStatus              | Rationale                                         |
| -------------------------------------------------------- | ------------------------------ | ------------------------------------------------- |
| Add `kSecClassIdentity` via `SecItemAdd`                 | `errSecParam` (-50)            | Identities must be imported, not created directly |
| Add `kSecClassKey` without `kSecAttrKeyType`             | `errSecParam` (-50)            | Crypto metadata is strictly required              |
| Add item with identical composite primary key            | `errSecDuplicateItem` (-25299) | Requires `SecItemUpdate` or delete-then-add       |
| Sync `true` + `ThisDeviceOnly` accessibility             | `errSecParam` (-50)            | Contradictory constraints                         |
| Use `kSecAttrApplicationTag` with `kSecClassCertificate` | `errSecParam` (-50)            | Tag is only valid for key items                   |
| Query `kSecClassKey` without `kSecAttrKeyClass`          | May return wrong key class     | Ambiguous match across public/private/symmetric   |

---

## Migration: GenericPassword to InternetPassword

If your application currently stores web credentials as `kSecClassGenericPassword`, migrate to `kSecClassInternetPassword` to enable AutoFill:

```swift
// ✅ Migration pattern: GenericPassword → InternetPassword
func migrateWebCredentials() throws {
    // 1. Query existing GenericPassword items for web credentials
    let oldQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "www.example.com",
        kSecReturnAttributes as String: true,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitAll
    ]

    var items: CFTypeRef?
    let fetchStatus = SecItemCopyMatching(oldQuery as CFDictionary, &items)
    guard fetchStatus == errSecSuccess,
          let results = items as? [[String: Any]] else { return }

    for item in results {
        guard let account = item[kSecAttrAccount as String] as? String,
              let data = item[kSecValueData as String] as? Data else { continue }

        // 2. Add as InternetPassword with proper attributes
        let newQuery: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrServer as String: "www.example.com",
            kSecAttrProtocol as String: kSecAttrProtocolHTTPS,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecUseDataProtectionKeychain as String: true
        ]
        let addStatus = SecItemAdd(newQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else { continue }

        // 3. Delete old GenericPassword item
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "www.example.com",
            kSecAttrAccount as String: account
        ]
        SecItemDelete(deleteQuery as CFDictionary)
    }
}
```

---

## Cross-Reference Index

- **SecItem CRUD operations, query dictionaries, error handling** → `keychain-fundamentals.md`
- **Accessibility constants, SecAccessControl flags** → `keychain-access-control.md`
- **Biometric protection for keys and passwords** → `biometric-authentication.md`
- **Secure Enclave key generation and constraints** → `secure-enclave.md`
- **CryptoKit key types and keychain storage mapping** → `cryptokit-symmetric.md`, `cryptokit-public-key.md`
- **OAuth tokens, API keys, credential lifecycle** → `credential-storage-patterns.md`
- **Access groups, app extensions, sharing** → `keychain-sharing.md`
- **SecCertificate, SecTrust, trust evaluation** → `certificate-trust.md`
- **Legacy migration patterns** → `migration-legacy-stores.md`
- **AI-generated code anti-patterns** → `common-anti-patterns.md`
- **OWASP MASVS/MASTG compliance** → `compliance-owasp-mapping.md`

---

## Conclusion

The keychain's five classes form a precise taxonomy: GenericPassword for app-local secrets, InternetPassword for domain-associated credentials enabling AutoFill, Key for cryptographic material with its tag/label distinction, Certificate for public X.509 data, and Identity as a virtual construct emerging from matching certificate and key items. The most impactful decisions are choosing InternetPassword over GenericPassword for web credentials, always setting `kSecUseDataProtectionKeychain` for cross-platform consistency, understanding that identities cannot be directly created, and recognizing `kSecAttrApplicationTag` (developer-set, for lookup) versus `kSecAttrApplicationLabel` (system-generated, for identity matching) as fundamentally different attributes despite their similar names.

---

## Summary Checklist

1. **Correct class selection** — Use `kSecClassInternetPassword` (not GenericPassword) for any credential associated with a web domain to enable AutoFill
2. **Composite primary key completeness** — Include all primary key attributes for the chosen class to avoid `errSecDuplicateItem` collisions and query misses
3. **kSecAttrGeneric is NOT a primary key** — Do not rely on it for uniqueness in GenericPassword items; it causes asymmetric add/query behavior
4. **ApplicationTag vs ApplicationLabel** — Use `kSecAttrApplicationTag` (developer-set, CFData) for key lookup; never manually set `kSecAttrApplicationLabel` (system-generated hash for identity formation)
5. **Identity creation via import** — Never `SecItemAdd` with `kSecClassIdentity`; use `SecPKCS12Import` or add matching certificate + key pairs separately
6. **Key type and size required** — Always specify `kSecAttrKeyType` and `kSecAttrKeySizeInBits` when creating or querying `kSecClassKey` items
7. **kSecUseDataProtectionKeychain on macOS** — Set to `true` for all operations to get iOS-identical behavior and avoid silent legacy keychain fallback
8. **Sync and accessibility agreement** — Never combine `kSecAttrSynchronizable: true` with "ThisDeviceOnly" accessibility values
9. **Small secrets only** — Use envelope encryption (DEK in keychain, ciphertext in `NSFileProtection`-guarded file) for data beyond a few KB
10. **Certificate attributes** — Never use `kSecAttrApplicationTag` with `kSecClassCertificate`; let the system extract metadata via `kSecValueRef`
11. **Duplicate handling** — Always handle `errSecDuplicateItem` with an update-first-then-add or delete-then-add pattern
