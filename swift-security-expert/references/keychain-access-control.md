# Keychain Access Control

> Scope: Selecting `kSecAttrAccessible` classes and `SecAccessControl` flags to enforce the correct lock-state and user-presence guarantees for keychain items.

Data protection classes (`kSecAttrAccessible`) and runtime authentication gates (`SecAccessControl`) form the two-layer security model protecting every keychain item. The first controls **when** an item's class key is available in memory based on device state; the second controls **how** the user must authenticate at access time. Both must be satisfied for a read to succeed. Getting this wrong is the single most common cause of production keychain failures — background operations that silently return `nil`, items that vanish after device migration, or credentials left decryptable at rest.

Sources: Apple Platform Security Guide (2024–2026 editions), Apple Keychain Services documentation, TN3137, WWDC 2014 Session 711 ("Keychain and Authentication with Touch ID"), WWDC 2015 Session 706, SecAccessControl documentation, OWASP MASTG.

---

## The "When" Layer: Seven Accessibility Constants

Every keychain item is encrypted with a class key derived from the device's hardware UID and (for most classes) the user's passcode. The `kSecAttrAccessible` attribute selects which class key protects the item, determining when the system can decrypt it. **If you omit `kSecAttrAccessible`, the default is `kSecAttrAccessibleWhenUnlocked`** — confirmed by Apple documentation. This default breaks all background operations.

### The Protection Spectrum

Listed from most restrictive to least:

**`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`** (iOS 8+) — the highest-security class. Items are accessible only while unlocked, and only if a device passcode is currently set. Two unique behaviors: (1) `SecItemAdd` fails on devices without a passcode, (2) **removing the passcode permanently deletes all items in this class** — class keys are discarded, data is unrecoverable. No non-`ThisDeviceOnly` variant exists. Items don't sync to iCloud Keychain, aren't backed up, and aren't in escrow keybags.

**`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`** — Items decryptable only while unlocked. Device-bound: excluded from backups and device migration.

**`kSecAttrAccessibleWhenUnlocked`** ⭐ (system default) — Same lock-state behavior as above, but items migrate with encrypted backups. Maps to `NSFileProtectionComplete`. Class key is discarded from memory shortly after the device locks (~10 seconds with Require Password set to Immediately).

**`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`** — **The correct choice for background operations.** After the user unlocks the device once following a restart, the class key remains in memory until the next restart — even while locked. Device-bound.

**`kSecAttrAccessibleAfterFirstUnlock`** — Same background accessibility, but items migrate with encrypted backups. Apple uses this for system Wi-Fi passwords, mail accounts, and iCloud tokens. Maps to `NSFileProtectionCompleteUntilFirstUserAuthentication`.

**`kSecAttrAccessibleAlwaysThisDeviceOnly`** ⚠️ DEPRECATED — Deprecated in iOS 12 / macOS 10.14. Apple announced intent at WWDC 2015 Session 706.

**`kSecAttrAccessibleAlways`** ⚠️ DEPRECATED — Same deprecation. Items encrypted with only the device UID (no passcode involvement), equivalent to `NSFileProtectionNone`.

> **Cross-validation note — deprecated "Always" runtime behavior:** One research source reports these constants "still function at runtime" with original semantics on iOS 15–18. The other reports modern iOS silently remaps them to `AfterFirstUnlock` behavior. The practical guidance is identical either way: **migrate immediately to `kSecAttrAccessibleAfterFirstUnlock`**. Block these constants in CI linting. Do not rely on any specific runtime behavior for deprecated constants across OS versions.

### Quick Reference Table

| Constant                         | Accessible When         | Survives Lock | Migrates in Backup | Special                         |
| -------------------------------- | ----------------------- | ------------- | ------------------ | ------------------------------- |
| `WhenPasscodeSetThisDeviceOnly`  | Unlocked + passcode set | No            | No                 | **Deleted on passcode removal** |
| `WhenUnlockedThisDeviceOnly`     | Unlocked                | No            | No                 | —                               |
| `WhenUnlocked` ⭐ default        | Unlocked                | No            | Yes                | —                               |
| `AfterFirstUnlockThisDeviceOnly` | After first unlock      | Yes           | No                 | Background-safe                 |
| `AfterFirstUnlock`               | After first unlock      | Yes           | Yes                | Background-safe + migratable    |
| `AlwaysThisDeviceOnly` ⚠️        | Always¹                 | Yes           | No                 | Deprecated iOS 12               |
| `Always` ⚠️                      | Always¹                 | Yes           | Yes                | Deprecated iOS 12               |

¹ Behavior may be remapped to `AfterFirstUnlock` on modern iOS versions.

### Lock-State Spectrum Explained

After a device restart, the system is in **Before First Unlock (BFU)** state. Only items with the deprecated `Always` class are supposed to be accessible. Even `AfterFirstUnlock` items are locked.

Once the user enters their passcode, the device enters **After First Unlock (AFU)** state. `AfterFirstUnlock` class keys load into memory and remain there through subsequent lock/unlock cycles until the next restart. `WhenUnlocked` class keys are available only during active unlocked periods and discarded each time the device locks.

> **iOS 15+ caveat — app pre-warming:** iOS can launch your process before first unlock for faster app startup. This means even `AfterFirstUnlock` items may be temporarily unavailable during pre-warm. Check `UIApplication.shared.isProtectedDataAvailable` before accessing keychain items, and defer if it returns `false`.

---

## The "How" Layer: SecAccessControl Flags

`SecAccessControl` adds runtime authentication requirements on top of data-at-rest protection. It is created via `SecAccessControlCreateWithFlags`, which embeds the accessibility level inside the control object:

```swift
func SecAccessControlCreateWithFlags(
    _ allocator: CFAllocator?,       // Pass nil
    _ protection: CFTypeRef,          // A kSecAttrAccessible constant
    _ flags: SecAccessControlCreateFlags,
    _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
) -> SecAccessControl?
```

### Available Flags

**Authentication constraints:**

- **`.userPresence`** (iOS 8+) — Biometry OR passcode. Does not require biometry enrollment; auto-falls back to passcode. Equivalent to `[.biometryAny, .or, .devicePasscode]` but handles no-biometry gracefully.
- **`.biometryAny`** (iOS 11.3+, was `.touchIDAny`) — Requires biometric authentication. Item **survives** enrollment changes (new fingerprints, Face ID re-enrollment).
- **`.biometryCurrentSet`** (iOS 11.3+, was `.touchIDCurrentSet`) — Requires biometric authentication. Item **invalidated** on enrollment changes. Most secure biometric option — blocks an attacker who enrolls their own biometrics.
- **`.devicePasscode`** (iOS 9+) — Requires device passcode entry only.

**Logical combinators:**

- **`.or`** — At least one constraint must be satisfied.
- **`.and`** — All constraints must be satisfied.

**Additional:**

- **`.privateKeyUsage`** (iOS 9+) — Required for Secure Enclave private key operations (signing, key agreement).
- **`.applicationPassword`** (iOS 9+) — Adds an app-provided password to key derivation. Not a constraint — an additional encryption layer.

### Flag Compatibility Matrix

| Flag                   | Works in Background?     | Typical Pairing                           | Failure if Misused                           |
| ---------------------- | ------------------------ | ----------------------------------------- | -------------------------------------------- |
| `.userPresence`        | No                       | Foreground + `WhenUnlocked`               | `-25308` in background                       |
| `.biometryAny`         | No                       | Foreground secrets                        | `errSecAuthFailed` if no biometrics enrolled |
| `.biometryCurrentSet`  | No                       | `WhenPasscodeSetTDO` for highest security | Auth fails on enrollment change              |
| `.devicePasscode`      | No                       | Compliance flows                          | `-25308` without UI                          |
| `.privateKeyUsage`     | Yes (for key ops)        | Secure Enclave keys                       | —                                            |
| `.applicationPassword` | Yes (if password cached) | Niche models                              | Password lifecycle management                |

### Composing Constraints

Since `SecAccessControlCreateFlags` is an `OptionSet`, compose with array literal syntax:

```swift
// Biometry OR passcode — most common pattern
let flags: SecAccessControlCreateFlags = [.biometryCurrentSet, .or, .devicePasscode]

// Biometry AND passcode — both required (rare, high security)
let flags: SecAccessControlCreateFlags = [.biometryAny, .and, .devicePasscode]

// Biometry OR passcode, plus application password encryption
let flags: SecAccessControlCreateFlags = [.biometryAny, .or, .devicePasscode, .applicationPassword]
```

> **Critical rule: `.or` / `.and` is required between authentication flags.** Combining `.biometryCurrentSet` and `.devicePasscode` without a logical operator causes `SecAccessControlCreateWithFlags` to return `nil` with `errSecParam` (-50). Both sources confirm this behavior.

---

## The Cardinal Rule: Never Set Both Attributes

`kSecAttrAccessible` and `kSecAttrAccessControl` are **mutually exclusive** in the query dictionary. When you use `SecAccessControlCreateWithFlags`, the accessibility level is embedded inside the `SecAccessControl` object via the `protection` parameter. Setting both in the same `SecItemAdd` query causes **`errSecParam` (-50)**.

```swift
// ❌ WRONG — sets accessibility twice, causes errSecParam (-50)
var error: Unmanaged<CFError>?
let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly, // ← accessibility set HERE
    [.biometryCurrentSet, .or, .devicePasscode],
    &error
)!

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "credential",
    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, // ❌ CONFLICT
    kSecAttrAccessControl as String: access, // ← already contains accessibility
    kSecValueData as String: secretData
]
// SecItemAdd returns errSecParam (-50)
```

```swift
// ✅ CORRECT — accessibility set only inside SecAccessControl
var error: Unmanaged<CFError>?
guard let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.biometryCurrentSet, .or, .devicePasscode],
    &error
) else { throw KeychainError.accessControlCreationFailed(error?.takeRetainedValue()) }

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "credential",
    kSecAttrAccessControl as String: access, // Contains accessibility + auth flags
    kSecValueData as String: secretData
]
```

---

## Decision Matrix: Choosing the Right Accessibility Level

### `WhenPasscodeSetThisDeviceOnly` — Data that should self-destruct

Use for your most sensitive credentials. Pair with `.biometryCurrentSet` via `SecAccessControl`. Accept the tradeoff: items are permanently destroyed on passcode removal and never survive device migration. Your app **must** handle item absence gracefully and guide users through re-authentication.

**Use cases:** Banking session tokens, password manager vault keys, healthcare credentials, E2E encryption private keys.

### `WhenUnlockedThisDeviceOnly` — Standard device-bound credentials

Credentials that should be device-bound but don't need passcode-deletion behavior. Re-authenticate after device migration.

**Use cases:** OAuth access tokens (refreshable), app-specific API keys, cached credentials, device registration tokens.

### `AfterFirstUnlockThisDeviceOnly` — Background operations (most common for services)

The correct choice for **any keychain item accessed by background code** — push notification handlers, WidgetKit timeline providers, background fetch, VPN extensions, notification service extensions. Device-bound.

**Use cases:** Push notification decryption keys, VPN credentials, background sync tokens, watch connectivity tokens.

### `AfterFirstUnlock` — Background + backup migration

Same background accessibility, plus items migrate with encrypted backups. Use when background access and device-transfer continuity are both needed.

**Use cases:** Enterprise VPN credentials, email account credentials, Wi-Fi configuration passwords.

### Dual-Item Strategy for Mixed Contexts

If a credential needs both background access (no UI) and foreground biometric protection (with UI), **store two separate items**: a background-capable token with `AfterFirstUnlockThisDeviceOnly` (no `SecAccessControl` user-presence flags) and a stronger foreground-only item with `WhenUnlockedThisDeviceOnly` + biometric `SecAccessControl`. This avoids the logical contradiction of biometric flags on background-accessible items.

---

## Common AI-Generated Mistakes

### Mistake 1: Omitting `kSecAttrAccessible` (inheriting the wrong default)

The most pervasive error. AI code generators produce keychain wrappers that never set `kSecAttrAccessible`, inheriting `WhenUnlocked`. Works during development (device unlocked while testing), fails in production when background extensions execute while locked — `errSecInteractionNotAllowed` (-25308), often silently swallowed.

```swift
// ❌ WRONG — omits kSecAttrAccessible, defaults to WhenUnlocked
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "authToken",
    kSecAttrService as String: "com.example.app",
    kSecValueData as String: tokenData
    // Missing: kSecAttrAccessible — background extensions WILL fail with -25308
]
```

```swift
// ✅ CORRECT — explicit accessibility for background use
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: "authToken",
    kSecAttrService as String: "com.example.app",
    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    kSecValueData as String: tokenData
]
```

### Mistake 2: Using deprecated `kSecAttrAccessibleAlways`

Compiles with a warning on iOS 12+, runs at runtime — arguably worse than a hard failure. No meaningful lock-state protection.

```swift
// ❌ WRONG — deprecated since iOS 12
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccessible as String: kSecAttrAccessibleAlways, // ⚠️ Deprecated
    kSecValueData as String: tokenData
]
// Replacement: kSecAttrAccessibleAfterFirstUnlock
```

### Mistake 3: Not handling `ThisDeviceOnly` item loss after device migration

Items with `ThisDeviceOnly` are cryptographically bound to the hardware UID. They are excluded from all backups, iCloud sync, and Quick Start device-to-device migration. After restoring to a new device, these items silently disappear — `errSecItemNotFound` (-25300). AI-generated code rarely implements re-authentication flows for this scenario.

### Mistake 4: Biometric flags on background-accessible protection levels

Setting `.biometryCurrentSet` with `kSecAttrAccessibleAfterFirstUnlock` is technically valid at the API level but creates a **logical contradiction**: `AfterFirstUnlock` implies background access while locked, but biometric auth requires an interactive prompt. Result: `errSecInteractionNotAllowed` in background contexts, defeating the purpose.

### Mistake 5: Conflicting flags without logical operator

Combining `.biometryCurrentSet` and `.devicePasscode` without `.or` or `.and` causes `SecAccessControlCreateWithFlags` to return `nil` / `errSecParam` (-50).

```swift
// ❌ WRONG — missing logical operator
let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlocked,
    [.biometryCurrentSet, .devicePasscode], // Missing .or or .and
    &error
)
// Returns nil, error contains errSecParam
```

```swift
// ✅ CORRECT — explicit .or between constraints
let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlocked,
    [.biometryCurrentSet, .or, .devicePasscode],
    &error
)
```

---

## Code Patterns

✅ The first two examples are correct patterns for foreground and background access. The third example is intentionally incorrect.

### Biometric protection with highest security

```swift
func saveBiometricProtectedItem(data: Data, account: String, service: String) throws {
    var error: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        [.biometryCurrentSet, .or, .devicePasscode],
        &error
    ) else {
        throw KeychainError.accessControlCreationFailed(error?.takeRetainedValue())
    }

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service,
        kSecAttrAccessControl as String: accessControl,
        kSecValueData as String: data
    ]

    let status = SecItemAdd(query as CFDictionary, nil)
    switch status {
    case errSecSuccess: return
    case errSecDuplicateItem:
        // Must delete + re-add: SecItemUpdate cannot change SecAccessControl
        let searchQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: service
        ]
        let deleteStatus = SecItemDelete(searchQuery as CFDictionary)
        guard deleteStatus == errSecSuccess else {
            throw KeychainError.fromStatus(deleteStatus)
        }
        let readdStatus = SecItemAdd(query as CFDictionary, nil)
        guard readdStatus == errSecSuccess else {
            throw KeychainError.fromStatus(readdStatus)
        }
    default:
        throw KeychainError.fromStatus(status)
    }
}
```

> **Important:** `SecItemUpdate` **cannot** change a `SecAccessControl` attribute on an existing item. To change access control, you must delete and re-add. Both sources confirm this.

### Background-accessible token (push notifications, VPN, widgets)

```swift
func saveBackgroundToken(_ token: Data, account: String, service: String) throws {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        kSecValueData as String: token
    ]

    let status = SecItemAdd(query as CFDictionary, nil)
    switch status {
    case errSecSuccess: return
    case errSecDuplicateItem:
        let updateAttrs: [String: Any] = [kSecValueData as String: token]
        let searchQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: service
        ]
        let updateStatus = SecItemUpdate(searchQuery as CFDictionary, updateAttrs as CFDictionary)
        guard updateStatus == errSecSuccess else {
            throw KeychainError.fromStatus(updateStatus)
        }
    default:
        throw KeychainError.fromStatus(status)
    }
}
```

### Accessing a `WhenUnlocked` item from a background extension

```swift
// Runs in WidgetKit TimelineProvider or NotificationServiceExtension while locked — WILL fail
func fetchTokenInBackground() -> String? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "authToken",
        kSecAttrService as String: "com.example.app",
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne
        // Item stored with default WhenUnlocked — inaccessible while locked
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    // status == errSecInteractionNotAllowed (-25308) when device is locked
    guard status == errSecSuccess, let data = result as? Data else {
        return nil // ❌ Silent failure — no logging, no error propagation
    }
    return String(data: data, encoding: .utf8)
}
```

---

## macOS: `kSecUseDataProtectionKeychain`

macOS has **two keychain implementations** (per TN3137): the legacy file-based keychain (`~/Library/Keychains/login.keychain-db`) and the modern Data Protection keychain. The `SecItem` API defaults to the **legacy** keychain on macOS.

Set `kSecUseDataProtectionKeychain: true` in every macOS keychain query to target the modern keychain. Without it:

- `SecAccessControl` flags fail with `errSecParam` (-50)
- iCloud Keychain sync doesn't work
- Secure Enclave integration is unavailable
- Biometric protection (Touch ID) won't function

```swift
// ✅ macOS: always include kSecUseDataProtectionKeychain
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: account,
    kSecAttrService as String: service,
    kSecUseDataProtectionKeychain as String: true, // ← Critical on macOS
    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    kSecValueData as String: data
]
```

On iOS, tvOS, and watchOS, this flag is ignored (those platforms always use Data Protection). The Data Protection keychain requires a user login context — `launchd` daemons running outside a user session must use the legacy keychain. Mac Catalyst and iOS-on-Mac apps automatically use Data Protection.

---

## NSFileProtection Sidebar

The keychain and file system share the same Data Protection architecture but expose it through different APIs. Use the keychain for small discrete secrets (passwords, tokens, keys). Use `NSFileProtection` for larger data (documents, databases, images).

**`NSFileProtectionComplete`** (Class A) = `kSecAttrAccessibleWhenUnlocked`. File inaccessible while locked. Class key discarded ~10 seconds after lock.

**`NSFileProtectionCompleteUnlessOpen`** (Class B) = **No keychain equivalent.** Uses asymmetric ECDH (Curve25519) to allow already-opened files to continue being written while locked. Designed for background downloads (e.g., mail attachment download continues writing to an already-open file).

**`NSFileProtectionCompleteUntilFirstUserAuthentication`** (Class C) = `kSecAttrAccessibleAfterFirstUnlock`. The default for third-party app files when no explicit protection is set. Available after first unlock.

**`NSFileProtectionNone`** (Class D) = deprecated `kSecAttrAccessibleAlways`. Protected only by device UID.

**Recommended layered approach:** Store encryption keys in the keychain with `WhenUnlockedThisDeviceOnly`, then use those keys to encrypt larger files on disk with `NSFileProtectionComplete` as an additional layer.

---

## Error Codes Reference

| Code       | Constant                      | Meaning                              | Common Root Cause                                                                                                                                   |
| ---------- | ----------------------------- | ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **-25308** | `errSecInteractionNotAllowed` | Item not accessible in current state | Device locked + `WhenUnlocked` item; BFU state + `AfterFirstUnlock` item; biometric flag in background                                              |
| **-50**    | `errSecParam`                 | Invalid parameters                   | Both `kSecAttrAccessible` and `kSecAttrAccessControl` set; conflicting flags without `.or`/`.and`; missing `kSecUseDataProtectionKeychain` on macOS |
| **-25293** | `errSecAuthFailed`            | Authentication failed                | Biometric auth failed; enrollment changed with `.biometryCurrentSet`; no biometrics enrolled                                                        |
| **-25300** | `errSecItemNotFound`          | Item not in keychain                 | Item never stored; `ThisDeviceOnly` lost after migration; `WhenPasscodeSet` deleted on passcode removal                                             |
| **-25299** | `errSecDuplicateItem`         | Item already exists                  | `SecItemAdd` when matching primary keys exist — use add-or-update pattern                                                                           |
| **-128**   | `errSecUserCanceled`          | User canceled prompt                 | User tapped Cancel on biometric/passcode dialog                                                                                                     |
| **-34018** | `errSecMissingEntitlement`    | Missing entitlement                  | Keychain access group not in entitlements; common on iOS Simulator                                                                                  |

The most insidious is `-25308` — it surfaces in production but rarely during development because developers test with unlocked devices. Always handle it by deferring the operation and retrying when `UIApplication.shared.isProtectedDataAvailable` is `true`.

---

## iOS Version Timeline

**iOS 8 (2014):** `WhenPasscodeSetThisDeviceOnly` introduced. `SecAccessControlCreateWithFlags` added. `.userPresence` flag.

**iOS 9 (2015):** `.devicePasscode`, `.applicationPassword`, `.privateKeyUsage` flags added. Apple announced intent to deprecate `Always` at WWDC 2015 Session 706.

**iOS 11.3 (2018):** `.touchIDAny` → `.biometryAny`; `.touchIDCurrentSet` → `.biometryCurrentSet` (unified naming for Face ID).

**iOS 12 (2018):** `kSecAttrAccessibleAlways` and `AlwaysThisDeviceOnly` formally deprecated. Both still compile and run for backward compatibility.

**iOS 15 (2021):** MDM-installed keychain items changed default from "always" to "after first unlock, nonmigratory." App pre-warming can launch processes before first unlock, making `AfterFirstUnlock` items temporarily unavailable.

**iOS 16 (2022):** Passkeys launched (FIDO2/WebAuthn key pairs synced via E2E encrypted iCloud Keychain). No changes to access control APIs.

**iOS 17 (2023):** Enterprise passkey support. No `kSecAttrAccessible` or `SecAccessControl` changes.

**iOS 18 (2024):** Standalone Passwords app. No keychain data protection API changes.

**iOS 26 (2025):** Stolen Device Protection enabled by default — requires biometric auth (no passcode fallback) for stored passwords when away from familiar locations. Secure passkey import/export via FIDO Alliance standard. No changes to `kSecAttrAccessible` constants.

---

## Testing Requirements

All data protection testing **must** use physical devices with passcodes enabled. The iOS Simulator does not enforce `kSecAttrAccessible` or `NSFileProtection`, creating a false sense of security.

**Critical test scenarios:**

1. **Reboot / BFU state:** Reboot device, attempt keychain access before unlocking. `AfterFirstUnlock` items should return `-25308` or `-25300`. Unlock once, lock again, test background access — should succeed.

2. **Lock timing:** Store a `WhenUnlocked` item. Lock the device. Attempt read immediately — expect `-25308`.

3. **Passcode removal:** Store a `WhenPasscodeSetThisDeviceOnly` item. Remove passcode in Settings. Verify item is deleted (`-25300`).

4. **Biometric enrollment change:** Store an item with `.biometryCurrentSet`. Add a new fingerprint or Face ID appearance. Verify authentication fails (`-25293`).

5. **Backup/restore migration:** Back up device, restore to a different physical device. Verify all `ThisDeviceOnly` items are absent (`-25300`).

6. **Background extension access:** Trigger a notification service extension or widget timeline update while the device is locked. Verify `AfterFirstUnlock` items are readable and `WhenUnlocked` items are not.

---

## Cross-References

- `keychain-fundamentals.md` — SecItem CRUD patterns, add-or-update, OSStatus handling
- `biometric-authentication.md` — Biometric flag selection (`.biometryCurrentSet`, `.biometryAny`, `.userPresence`) and keychain-bound patterns
- `secure-enclave.md` — Hardware-backed keys with `SecAccessControl` and `.privateKeyUsage`
- `keychain-item-classes.md` — Class-specific accessibility considerations and primary key composition
- `common-anti-patterns.md` — Anti-pattern #5 (missing `kSecAttrAccessible`), #3 (LAContext-only gate)
- `compliance-owasp-mapping.md` — M9 (Insecure Data Storage) accessibility requirements

---

## Summary Checklist

1. **Always set `kSecAttrAccessible` explicitly** — never rely on the `WhenUnlocked` default; choose the level matching your access context (foreground vs background)
2. **Never set both `kSecAttrAccessible` and `kSecAttrAccessControl`** in the same query dictionary — accessibility belongs inside `SecAccessControlCreateWithFlags`
3. **Use `AfterFirstUnlockThisDeviceOnly`** for any item accessed by background extensions, widgets, VPN, or push notification handlers
4. **Pair `WhenPasscodeSetThisDeviceOnly` with `.biometryCurrentSet`** for highest-security items, and handle item deletion on passcode removal gracefully
5. **Include `.or` or `.and`** when combining multiple authentication flags — omitting the operator causes `errSecParam` (-50)
6. **Set `kSecUseDataProtectionKeychain: true`** on all macOS keychain queries to target the modern Data Protection keychain
7. **Implement re-authentication flows** for `ThisDeviceOnly` items that will be absent after device migration or backup restore
8. **Check `isProtectedDataAvailable`** before keychain access in app launch paths — iOS 15+ pre-warming can start your process before first unlock
9. **Delete and re-add** (not update) when changing `SecAccessControl` on an existing item — `SecItemUpdate` cannot modify access control attributes
10. **Test on physical devices** across lock/unlock, reboot, passcode removal, and biometric enrollment change scenarios — the Simulator does not enforce data protection
11. **Block deprecated `kSecAttrAccessibleAlways` constants** in CI/CD linting and migrate existing items to `AfterFirstUnlock` on next foreground authentication
