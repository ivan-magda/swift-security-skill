# Keychain Fundamentals

> **Scope:** SecItem\* CRUD operations, query dictionary structure, kSecClass types, OSStatus error handling, actor-based wrapper patterns. This is the foundation file — all other reference files assume familiarity with these patterns.
>
> **Key APIs:** `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete`, `kSecClassGenericPassword`, `kSecClassInternetPassword`, `kSecClassKey`, `kSecClassCertificate`, `kSecClassIdentity`
>
> **Apple Documentation:** [Keychain Services](https://developer.apple.com/documentation/security/keychain_services), [TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains), Quinn "The Eskimo!" DTS posts: "SecItem: Fundamentals" and "SecItem: Pitfalls and Best Practices"

---

## Architecture Overview

The Keychain Services API exposes four C functions that map to database CRUD operations. Every call is an IPC round-trip to the `securityd` daemon, backed by an encrypted SQLite database. This means every call **blocks the calling thread** and must never execute on `@MainActor`.

Internally, keychain items use **two-tier AES-256-GCM encryption** (per the Apple Platform Security Guide): a table-level **metadata key** cached in the Application Processor for fast attribute searches, and a **per-row secret key** requiring a Secure Enclave round-trip for `kSecValueData` decryption. This two-tier design has direct performance implications covered in the Performance section below.

---

## The Four Functions and Their Dictionary Contracts

Each function accepts a specific _type_ of dictionary. Confusing which keys belong in which dictionary is the single most common source of bugs. Quinn (Apple DTS) defines five property groups:

1. **Item class** — `kSecClass`
2. **Item attributes** — `kSecAttrAccount`, `kSecAttrService`, etc.
3. **Search properties** — `kSecMatchLimit`
4. **Return type properties** — `kSecReturnData`, `kSecReturnAttributes`, `kSecReturnRef`, `kSecReturnPersistentRef`
5. **Value type properties** — `kSecValueData`, `kSecValueRef`

| Function                    | Dictionary Type                              | Supports Return Keys?   | Default `kSecMatchLimit` | Since   |
| --------------------------- | -------------------------------------------- | ----------------------- | ------------------------ | ------- |
| `SecItemAdd(_:_:)`          | Add dictionary (class + attrs + values)      | ✅ Optional             | N/A                      | iOS 2.0 |
| `SecItemCopyMatching(_:_:)` | Query + return (all 5 groups)                | ✅ Required for results | `kSecMatchLimitOne`      | iOS 2.0 |
| `SecItemUpdate(_:_:)`       | Pure query (param 1) + update dict (param 2) | ❌                      | **`kSecMatchLimitAll`**  | iOS 2.0 |
| `SecItemDelete(_:)`         | Pure query                                   | ❌                      | **`kSecMatchLimitAll`**  | iOS 2.0 |

**Critical detail:** `kSecMatchLimit` defaults to `kSecMatchLimitOne` for `SecItemCopyMatching` but **`kSecMatchLimitAll` for `SecItemUpdate` and `SecItemDelete`**. An under-specified delete query will wipe every matching item in the keychain.

**Dictionary hygiene:** Use a fresh dictionary for each call. Putting `kSecReturnData` in an add dictionary or `kSecClass` in an update dictionary produces `errSecParam` (-50). Quinn's guidance: "Use a new dictionary for each call. That prevents state from one call accidentally leaking into a subsequent call."

---

## Uniqueness and Primary Keys

For `kSecClassGenericPassword`, uniqueness is determined by the combination of:

- `kSecAttrAccount` + `kSecAttrService` + `kSecAttrAccessGroup` + `kSecAttrSynchronizable`

Other attributes like `kSecAttrGeneric`, `kSecAttrLabel`, or `kSecAttrDescription` **do not participate in uniqueness**. This means a query filtering on non-unique attributes can return `errSecItemNotFound` while a subsequent add still hits `errSecDuplicateItem`.

For `kSecClassInternetPassword`, the uniqueness set includes: `kSecAttrAccount` + `kSecAttrServer` + `kSecAttrProtocol` + `kSecAttrAuthenticationType` + `kSecAttrPort` + `kSecAttrPath` + `kSecAttrSecurityDomain` + `kSecAttrAccessGroup` + `kSecAttrSynchronizable`.

**Immutable attributes:** `kSecAttrAccount` and `kSecClass` cannot be changed via `SecItemUpdate`. To change them, delete and re-add the item (see `keychain-item-classes.md`).

---

## The Add-or-Update Pattern

The most common AI-generated keychain bug is calling `SecItemAdd` without handling `errSecDuplicateItem` (-25299).

❌ **Naive add that silently fails on duplicate:**

```swift
// ❌ WRONG — silently fails if item already exists
func savePassword(_ password: String, account: String) {
    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: "com.example.app",
        kSecAttrAccount: account,
        kSecValueData: Data(password.utf8)
    ]
    SecItemAdd(query as CFDictionary, nil)  // Return value IGNORED!
    // If item exists → errSecDuplicateItem (-25299) — password never saved
}
```

✅ **Correct add-or-update with exhaustive OSStatus handling:**

```swift
// ✅ CORRECT — attempts add, falls back to update on duplicate
func savePassword(_ password: String, account: String) throws {
    let baseQuery: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: "com.example.app",
        kSecAttrAccount: account
    ]

    var addQuery = baseQuery
    addQuery[kSecValueData] = Data(password.utf8)
    addQuery[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

    let addStatus = SecItemAdd(addQuery as CFDictionary, nil)

    switch addStatus {
    case errSecSuccess:
        return

    case errSecDuplicateItem:
        // Item exists — update it
        let updates: [CFString: Any] = [kSecValueData: Data(password.utf8)]
        let updateStatus = SecItemUpdate(
            baseQuery as CFDictionary,
            updates as CFDictionary
        )
        guard updateStatus == errSecSuccess else {
            throw KeychainError(status: updateStatus)
        }

    case errSecInteractionNotAllowed:
        // Device locked — do NOT delete-and-retry!
        throw KeychainError(status: addStatus)

    default:
        throw KeychainError(status: addStatus)
    }
}
```

Key points in this pattern:

- **Separate dictionaries** for add vs. update — the update dictionary contains only the attributes to change, never `kSecClass` or search properties.
- **`errSecInteractionNotAllowed`** (-25308) means the device is locked and data protection prevents access. Never delete items in response to this error; the item is valid but temporarily inaccessible.
- **Prefer update over delete-then-add** — update preserves persistent references and avoids the race condition window between delete and add.

---

## Reading from the Keychain: Return Flags and Type Casting

The second most common bug is calling `SecItemCopyMatching` without `kSecReturn*` flags. The function may return `errSecSuccess` with a `nil` result — this is "success but nil," not a real success.

❌ **Query that returns no data because `kSecReturnData` is missing:**

```swift
// ❌ WRONG — no kSecReturn* flags, result is always nil
func loadPassword(account: String) -> Data? {
    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: "com.example.app",
        kSecAttrAccount: account,
        kSecMatchLimit: kSecMatchLimitOne
        // BUG: Missing kSecReturnData: true
    ]
    var result: CFTypeRef?
    SecItemCopyMatching(query as CFDictionary, &result)
    return result as? Data  // Always nil — no return type was requested
}
```

✅ **Correct query with proper return flags and exhaustive error handling:**

```swift
// ✅ CORRECT — explicitly requests data, handles all error states
func loadPassword(account: String) throws -> Data? {
    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: "com.example.app",
        kSecAttrAccount: account,
        kSecMatchLimit: kSecMatchLimitOne,
        kSecReturnData: true  // ← REQUIRED to get the secret
    ]

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    switch status {
    case errSecSuccess:
        guard let data = result as? Data else {
            throw KeychainError(status: errSecParam)
        }
        return data

    case errSecItemNotFound:
        return nil  // Legitimate "not found" — not an error

    case errSecInteractionNotAllowed:
        throw KeychainError(status: status)

    default:
        throw KeychainError(status: status)
    }
}
```

### Return Type Cheat Sheet

The `CFTypeRef` type depends entirely on which return flags and match limits are set:

```text
kSecReturnData only      + kSecMatchLimitOne  → Data
kSecReturnAttributes     + kSecMatchLimitOne  → [String: Any]
kSecReturnData + Attrs   + kSecMatchLimitOne  → [String: Any]  (data under kSecValueData key)
kSecReturnRef            + kSecMatchLimitOne  → SecKey / SecCertificate / SecIdentity
kSecReturnPersistentRef  + kSecMatchLimitOne  → Data (opaque handle)
Any combination          + kSecMatchLimitAll  → Array of the above type
```

**Note:** Combining `kSecReturnData` with `kSecMatchLimitAll` may be restricted for password classes on some OS versions. For listing items, prefer `kSecReturnAttributes` or `kSecReturnRef` with `kSecMatchLimitAll`, then fetch data per-item as needed.

### String Keys vs. kSec\* Constants

Never use raw string literals (`"svce"`, `"class"`) instead of `kSec*` constants. The constants are `CFString` values with specific internal representations. Two equally valid dictionary key styles exist:

```swift
// Style A: CFString keys (fewer casts at definition, cast once at call site)
let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword]
SecItemAdd(query as CFDictionary, nil)

// Style B: String keys (more common in community code)
let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword]
SecItemAdd(query as CFDictionary, nil)
```

Both are correct. Pick one style and use it consistently across your codebase.

---

## Centralized Query Builder

Both research sources recommend centralizing query construction to prevent flag omissions and key typos:

```swift
enum KeychainQueryBuilder {
    static func buildQuery(
        forClass secClass: CFString = kSecClassGenericPassword,
        account: String? = nil,
        service: String? = nil,
        accessGroup: String? = nil,
        returnData: Bool = false,
        returnAttributes: Bool = false,
        matchLimit: CFString = kSecMatchLimitOne
    ) -> [String: Any] {
        var query: [String: Any] = [kSecClass as String: secClass]

        if let account  { query[kSecAttrAccount as String] = account }
        if let service  { query[kSecAttrService as String] = service }
        if let group    = accessGroup { query[kSecAttrAccessGroup as String] = group }
        if returnData   { query[kSecReturnData as String] = kCFBooleanTrue! }
        if returnAttributes { query[kSecReturnAttributes as String] = kCFBooleanTrue! }
        query[kSecMatchLimit as String] = matchLimit

        return query
    }
}
```

This pattern ensures return flags are set deliberately and provides a single site to audit query construction.

---

## OSStatus Error Handling

Never treat all non-zero `OSStatus` values as fatal errors. Several codes represent expected operational states:

| OSStatus Code | Constant                      | Meaning                                            | Correct Response                           |
| ------------- | ----------------------------- | -------------------------------------------------- | ------------------------------------------ |
| `0`           | `errSecSuccess`               | Operation succeeded                                | Proceed normally                           |
| `-25299`      | `errSecDuplicateItem`         | Item already exists (on add)                       | Fall back to `SecItemUpdate`               |
| `-25300`      | `errSecItemNotFound`          | No matching item found                             | Return `nil` / treat as success for delete |
| `-25308`      | `errSecInteractionNotAllowed` | Device locked, data protection active              | Retry later — **never delete**             |
| `-25293`      | `errSecUserCanceled`          | User cancelled biometric prompt                    | Propagate cancellation to UI               |
| `-50`         | `errSecParam`                 | Invalid parameter / wrong dictionary keys          | Developer error — fix query                |
| `-25244`      | `errSecNoSuchAttr`            | Attribute not supported (data protection keychain) | Check for unsupported attributes           |

Map raw codes to a domain-specific Swift error:

```swift
struct KeychainError: Error, CustomStringConvertible {
    let status: OSStatus

    var description: String {
        let msg = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown"
        return "KeychainError(\(status)): \(msg)"
    }
}
```

**Logging safety:** Log only the query shape and resulting status code. Never log secret data (`kSecValueData`), tokens, or keys.

---

## Actor-Isolated Keychain Manager (iOS 17+ / macOS 14+)

Every `SecItem*` function blocks the calling thread due to IPC to `securityd` and potential Secure Enclave round-trips. For biometry-protected items, the block can last several seconds during user authentication (WWDC 2014 Session 711).

❌ **@MainActor keychain access that blocks the UI:**

```swift
// ❌ WRONG — blocks main thread, freezes UI during securityd IPC
@MainActor
class SettingsViewModel: ObservableObject {
    @Published var token: String = ""

    func loadToken() {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "com.example.app",
            kSecAttrAccount: "authToken",
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data {
            self.token = String(data: data, encoding: .utf8) ?? ""
        }
        // UI frozen for entire duration of securityd IPC + potential SE round-trip
    }
}
```

✅ **Actor-isolated keychain manager with full CRUD:**

```swift
// ✅ CORRECT — dedicated actor keeps all SecItem calls off @MainActor
actor KeychainManager {
    static let shared = KeychainManager()

    private let service: String

    init(service: String = Bundle.main.bundleIdentifier ?? "default") {
        self.service = service
    }

    // MARK: - Save (add-or-update)

    func save(_ data: Data, for key: String,
              accessibility: CFTypeRef = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    ) throws {
        let baseQuery: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: key
        ]

        var addQuery = baseQuery
        addQuery[kSecValueData] = data
        addQuery[kSecAttrAccessible] = accessibility

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)

        switch addStatus {
        case errSecSuccess:
            return
        case errSecDuplicateItem:
            let updates: [CFString: Any] = [kSecValueData: data]
            let updateStatus = SecItemUpdate(
                baseQuery as CFDictionary,
                updates as CFDictionary
            )
            guard updateStatus == errSecSuccess else {
                throw KeychainError(status: updateStatus)
            }
        case errSecInteractionNotAllowed:
            throw KeychainError(status: addStatus)
        default:
            throw KeychainError(status: addStatus)
        }
    }

    // MARK: - Load

    func load(for key: String) throws -> Data? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: key,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            return result as? Data
        case errSecItemNotFound:
            return nil
        case errSecInteractionNotAllowed:
            throw KeychainError(status: status)
        default:
            throw KeychainError(status: status)
        }
    }

    // MARK: - Delete (idempotent)

    func delete(key: String) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: key
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError(status: status)
        }
    }

    // MARK: - List all accounts (attributes only — fast)

    func allAccounts() throws -> [String] {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnAttributes: true  // No kSecReturnData → skips SE round-trip
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let items = result as? [[String: Any]] else { return [] }
            return items.compactMap { $0[kSecAttrAccount as String] as? String }
        case errSecItemNotFound:
            return []
        default:
            throw KeychainError(status: status)
        }
    }
}
```

**Calling from SwiftUI:**

```swift
@MainActor
class AuthViewModel: ObservableObject {
    @Published var isAuthenticated = false

    func loadToken() async {
        do {
            // Crosses actor boundary — suspends, does NOT block MainActor
            let data = try await KeychainManager.shared.load(for: "authToken")
            isAuthenticated = data != nil
        } catch {
            isAuthenticated = false
        }
    }
}
```

### Why Actors over GCD

| Dimension             | Actor (iOS 17+)                   | GCD Serial Queue                        |
| --------------------- | --------------------------------- | --------------------------------------- |
| UI blocking           | Low — compiler-enforced isolation | Low (if dispatched correctly)           |
| Thread safety         | Serialized by actor runtime       | Manual — developer discipline           |
| Readability           | Linear async/await                | Nested completion handlers              |
| Compiler guarantees   | Enforced `Sendable` + isolation   | None — silent data races possible       |
| Swift 6 compatibility | Native — actors are `Sendable`    | Requires manual `@Sendable` annotations |

### Legacy GCD Pattern (iOS 13–16 codebases)

```swift
class LegacyKeychainManager {
    private let queue = DispatchQueue(label: "com.app.keychain",
                                      qos: .userInitiated)

    func load(key: String, completion: @escaping (Result<Data?, Error>) -> Void) {
        queue.async {
            // ... SecItemCopyMatching on background queue ...
            DispatchQueue.main.async { completion(result) }
        }
    }
}
```

---

## Performance Architecture

### Two-Tier Encryption and Query Cost

Because of the two-tier encryption design:

- **`kSecReturnAttributes` only** → uses cached metadata key → **fast** (no Secure Enclave round-trip)
- **`kSecReturnData`** → requires per-row secret key from Secure Enclave → **slower**

For listing operations, always use `kSecReturnAttributes` or `kSecReturnRef` and fetch secret data only for the specific item the user selects.

### Query Specificity

The underlying SQLite database benefits from narrow constraints. A query specifying only `kSecClass: kSecClassGenericPassword` with `kSecMatchLimitAll` performs a **full table scan**. Adding `kSecAttrService` and `kSecAttrAccount` enables indexed lookup. Always include all relevant uniqueness attributes in production queries.

### App Launch Performance

Keychain access during app launch is a measurable performance risk:

- Each call requires IPC to `securityd` plus potential Secure Enclave latency
- Items with `kSecAttrAccessibleWhenUnlocked` may be unavailable before first unlock (iOS can launch apps before the user unlocks — e.g., background refresh, VoIP pushes)
- **Best practice:** Defer keychain reads until actually needed. Never call SecItem synchronously in `application(_:didFinishLaunchingWithOptions:)`.
- Handle `errSecInteractionNotAllowed` gracefully — never destructively.

### Batch Operations

There is **no batch API** for SecItem. Each function operates individually with one partial exception: `SecItemAdd` supports `kSecUseItemList` to add multiple certificates or keys (not passwords) in a single call. For batch reads, `SecItemCopyMatching` with `kSecMatchLimitAll` retrieves all matching items at once.

---

## macOS Keychain Routing (TN3137)

On macOS, the SecItem API can target two different implementations:

| Implementation                 | Activated By                                                                           | Behavior                                                                                                             |
| ------------------------------ | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **Legacy file-based keychain** | Default on macOS (without opt-in)                                                      | Silently ignores unsupported attributes; inconsistent `kSecMatchLimit` defaults; different `SecItemAdd` return types |
| **Data protection keychain**   | `kSecUseDataProtectionKeychain: true` (macOS 10.15+) or `kSecAttrSynchronizable: true` | Parity with iOS; required for iCloud Keychain sync, biometric protection, and Secure Enclave key storage             |

**Modern apps must always target the data protection keychain.** Mac Catalyst and iOS Apps on Mac use it automatically.

```swift
// macOS: Always opt into data protection keychain
var query: [CFString: Any] = [
    kSecClass: kSecClassGenericPassword,
    kSecAttrService: "com.example.app",
    kSecAttrAccount: "token"
]
#if os(macOS)
query[kSecUseDataProtectionKeychain] = true
#endif
```

The file-based keychain's shim layer has documented bugs — it silently ignores unsupported attributes where the data protection keychain correctly returns `errSecNoSuchAttr` (-25244). Debugging keychain issues on macOS often starts with confirming which implementation is in use.

---

## Accessibility and Data Protection Classes

The `kSecAttrAccessible` attribute controls when a keychain item's secret data can be decrypted. Brief guidance here; see `keychain-access-control.md` for full coverage.

| Constant                                           | Available When                   | Survives Backup? | Use Case                                     |
| -------------------------------------------------- | -------------------------------- | ---------------- | -------------------------------------------- |
| `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`     | After unlock, until lock         | No (device-only) | Default for most secrets                     |
| `kSecAttrAccessibleAfterFirstUnlock`               | After first unlock until restart | Yes              | Background processing tokens                 |
| `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`  | Only if passcode set + unlocked  | No               | Highest-sensitivity data (OWASP recommended) |
| `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` | After first unlock until restart | No               | Background + device-only                     |

**Deprecated:** `kSecAttrAccessibleAlways` — deprecated in iOS 12, unsupported on Apple Silicon Macs. Never use.

---

## Cross-References

- **Item class deep dive** (required vs optional attributes per kSecClass) → `keychain-item-classes.md`
- **Access control flags and SecAccessControl** → `keychain-access-control.md`
- **Biometric-gated keychain access** (LAContext integration) → `biometric-authentication.md`
- **Secure Enclave key storage** → `secure-enclave.md`
- **Credential lifecycle patterns** (OAuth tokens, API keys) → `credential-storage-patterns.md`
- **Access groups and sharing** → `keychain-sharing.md`
- **Testing keychain code** (mocks, CI/CD) → `testing-security-code.md`
- **Common anti-patterns** (comprehensive catalog) → `common-anti-patterns.md`

---

## Authoritative References

| Source                                                                                                                          | Relevance                                          |
| ------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| [Keychain Services](https://developer.apple.com/documentation/security/keychain_services)                                       | Main API landing page                              |
| [TN3137: On Mac Keychain APIs and Implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains) | macOS data protection vs file-based routing        |
| Quinn "The Eskimo!" — "SecItem: Fundamentals" / "SecItem: Pitfalls and Best Practices"                                          | Most practical DTS reference, updated through 2025 |
| [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web) — Keychain Data Protection chapter        | Two-tier encryption architecture                   |
| WWDC 2014 Session 711 — "Keychain and Authentication with Touch ID"                                                             | Touch ID/keychain integration patterns             |
| WWDC 2019 Session 516 — "What's New in Authentication"                                                                          | Modern credential management                       |

---

## Contradictions Between Research Sources

During cross-validation of research inputs, the following discrepancies were noted:

1. **Dictionary key type convention:** Claude source uses `[CFString: Any]`; Parallel source uses `[String: Any]` with `kSec* as String` casts. **Resolution:** Both are correct. The `[CFString: Any]` style is slightly more concise; the `[String: Any]` style is more common in community code. This file uses `[CFString: Any]` for conciseness but shows both styles in the String Keys section.

2. **Default accessibility recommendation:** Claude source cites OWASP recommending `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` for highly sensitive data; Parallel source defaults to `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. **Resolution:** Both are valid for different threat models. `WhenPasscodeSet` is strongest but items are deleted if the user removes their passcode. `WhenUnlockedThisDeviceOnly` is the safe general default for foreground-only access. The actor manager example uses `AfterFirstUnlockThisDeviceOnly` for background compatibility while remaining device-bound.

3. **`kSecReturnData` + `kSecMatchLimitAll` restriction:** Parallel source claims this combination is restricted for password classes. Claude source does not mention this. **Resolution:** This restriction exists in some OS versions / keychain implementations. Safest practice is to use `kSecReturnRef` or `kSecReturnAttributes` with `LimitAll`, then fetch data per-item. Noted in the Return Type Cheat Sheet.

---

## Summary Checklist

Before shipping keychain code, verify:

1. **OSStatus checked on every call** — exhaustive `switch` covering at minimum `errSecSuccess`, `errSecDuplicateItem`, `errSecItemNotFound`, `errSecInteractionNotAllowed`; no ignored return values
2. **Add-or-update pattern implemented** — `SecItemAdd` catches `-25299` and falls back to `SecItemUpdate`; duplicate saves never crash or silently fail
3. **Return flags explicitly set** — every `SecItemCopyMatching` call includes at least one `kSecReturn*` flag; no "success but nil" bugs
4. **CFTypeRef cast matches flags** — cast type corresponds to the combination of return flags and match limit (see Return Type Cheat Sheet)
5. **Zero SecItem calls on @MainActor** — all keychain access isolated in a dedicated `actor` (iOS 17+) or serial `DispatchQueue` (iOS 13–16)
6. **Fresh dictionaries per call** — no dictionary reuse across SecItem functions; add dict, query dict, and update dict are separate
7. **kSec\* constants used** — no raw string literals for dictionary keys; using either `[CFString: Any]` or `[String: Any]` with `as String` casts
8. **Queries are specific** — `kSecAttrService` + `kSecAttrAccount` included for GenericPassword; `kSecMatchLimitOne` used unless enumeration is needed
9. **Delete treats not-found as success** — `errSecItemNotFound` on delete is a valid postcondition, not an error
10. **macOS targets data protection keychain** — `kSecUseDataProtectionKeychain: true` set for macOS targets (automatic for Catalyst/iOS-on-Mac)
11. **errSecInteractionNotAllowed handled non-destructively** — device-locked state triggers retry-later logic, never delete-and-recreate
