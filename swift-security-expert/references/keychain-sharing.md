# Keychain Sharing: Access Groups, Extensions, and Cross-Device Sync

> Scope: Access-group design and entitlement correctness for sharing keychain items across app targets, extensions, and devices.

Keychain access groups are the sole mechanism for sharing credentials between apps and extensions on Apple platforms. Correct configuration requires exact Team ID prefixes, per-target entitlements, and explicit `kSecAttrAccessGroup` usage in code — three requirements that most AI-generated code gets wrong. This reference covers access group mechanics, the two entitlement systems, correct and incorrect Swift patterns, macOS-specific requirements, iCloud sync, platform edge cases, and debugging strategies. All guidance reflects current behavior through iOS 18, macOS Sequoia 15, and the 2025–2026 developer landscape.

**Authoritative sources:** Apple "Sharing Access to Keychain Items Among a Collection of Apps" documentation, TN3137 "On Mac Keychain APIs and Implementations," Apple Platform Security Guide (iCloud Keychain syncing), Quinn "The Eskimo!" DTS forum posts "SecItem: Fundamentals" and "SecItem: Pitfalls and Best Practices" (updated May 2025), Configuring Keychain Sharing documentation.

---

## How Access Groups Work

Every app belongs to one or more **access groups** — string identifiers that tag which processes can read and write specific keychain items. An app can belong to many groups, but each keychain item belongs to **exactly one**. The `securityd` daemon enforces access by checking the calling process's entitlements against the item's group at runtime.

The system constructs a virtual array of access groups for each app by concatenating three sources **in this exact order**:

1. **Keychain access groups** from the `keychain-access-groups` entitlement
2. **Application identifier** — automatically generated as `TeamID.BundleID` (e.g., `SKMME9E2Y8.com.example.MyApp`)
3. **App groups** from the `com.apple.security.application-groups` entitlement (iOS 8+)

**The first item in this concatenated list becomes the default access group.** When `SecItemAdd` is called without specifying `kSecAttrAccessGroup`, the item lands in that default group. When `SecItemCopyMatching` is called without specifying a group, the search spans **all** groups the app belongs to. This ordering means a keychain access group can be the default (it appears first), but an app group can never be the default because the application identifier always precedes it.

Example for an app with one keychain group and one app group:

```text
[SKMME9E2Y8.com.example.SharedItems,    ← keychain access group (default)
 SKMME9E2Y8.com.example.MyApp,          ← application identifier (automatic)
 group.com.example.AppSuite]             ← app group
```

**Sharing is restricted to a single development team.** Apps from different developer teams cannot share keychain items through access groups. The Team ID prefix on every group identifier, enforced through code-signed provisioning profiles, prevents cross-team access. The only way different developers' apps can share credentials is through iCloud Keychain + Associated Domains (password autofill based on web domain ownership), which is an entirely different mechanism.

---

## Two Entitlements, Two Formats, Different Purposes

The most common developer mistake is **confusing Keychain Sharing with App Groups**. These are separate capabilities with different entitlement keys, different identifier formats, and different scopes.

### Keychain Sharing (`keychain-access-groups`)

This entitlement exists solely for sharing keychain items between apps. Identifiers are prefixed with the Team ID:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <string>$(AppIdentifierPrefix)com.example.SharedItems</string>
    </array>
</dict>
</plist>
```

The `$(AppIdentifierPrefix)` build variable resolves at signing time to the Team ID followed by a dot (e.g., `SKMME9E2Y8.`). In code, the fully resolved string is required — `"SKMME9E2Y8.com.example.SharedItems"` — not just `"com.example.SharedItems"`.

### App Groups (`com.apple.security.application-groups`)

App Groups share more than keychain items: shared file containers, `UserDefaults(suiteName:)`, and IPC. The identifier uses a `group.` prefix with **no Team ID**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.com.example.AppSuite</string>
    </array>
</dict>
</plist>
```

Since iOS 8, app group names double as keychain access groups — `"group.com.example.AppSuite"` can be used as the `kSecAttrAccessGroup` value. However, App Groups appear last in the access group array and **can never be the default group for new items**. A critical macOS caveat: **app groups cannot be used as keychain access groups on macOS** — this is an iOS/iPadOS-only feature.

### Comparison Table

| Aspect                     | Keychain Sharing                           | App Groups                                                   |
| -------------------------- | ------------------------------------------ | ------------------------------------------------------------ |
| **Entitlement key**        | `keychain-access-groups`                   | `com.apple.security.application-groups`                      |
| **Format**                 | `$(AppIdentifierPrefix)com.example.shared` | `group.com.example.shared`                                   |
| **Team ID prefix**         | Yes (automatic via build variable)         | No (`group.` prefix instead)                                 |
| **Shares**                 | Keychain items only                        | Containers, UserDefaults, IPC, and keychain items (iOS only) |
| **Can be default group**   | Yes (if first in array)                    | No                                                           |
| **macOS keychain sharing** | Yes (with data protection keychain)        | No                                                           |

Both entitlements can be used simultaneously. If only keychain sharing is needed, use Keychain Sharing. If App Groups are already in use for shared UserDefaults or file containers, they can piggyback for keychain sharing on iOS — but always specify `kSecAttrAccessGroup` explicitly.

---

## Code Patterns: Correct and Incorrect

### Storing an item with an explicit access group

```swift
import Security

let teamID = "SKMME9E2Y8"
let accessGroup = "\(teamID).com.example.SharedItems"

let password = "s3cretT0ken".data(using: .utf8)!
let addQuery: [String: Any] = [
    kSecClass as String:            kSecClassGenericPassword,
    kSecAttrService as String:      "com.example.authService",
    kSecAttrAccount as String:      "user@example.com",
    kSecAttrAccessGroup as String:  accessGroup,
    kSecAttrAccessible as String:   kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    kSecValueData as String:        password
]

let status = SecItemAdd(addQuery as CFDictionary, nil)
guard status == errSecSuccess else {
    print("Keychain add failed: \(status)")  // -34018 = missing entitlement
    return
}
```

The Team ID must be the **literal 10-character string** from the Apple Developer account, not a build variable — `$(AppIdentifierPrefix)` only works in entitlements plists, not in Swift code.

### Access group without Team ID prefix (most common AI mistake)

```swift
// ❌ WRONG — Missing Team ID prefix
let accessGroup = "com.example.SharedItems"

let addQuery: [String: Any] = [
    kSecClass as String:            kSecClassGenericPassword,
    kSecAttrService as String:      "com.example.authService",
    kSecAttrAccount as String:      "user@example.com",
    kSecAttrAccessGroup as String:  accessGroup,  // Will fail!
    kSecValueData as String:        password
]
// Returns errSecMissingEntitlement (-34018) on iOS 13+
// Returns errSecItemNotFound (-25300) on older versions
```

Xcode's Keychain Sharing UI shows `com.example.SharedItems` without the prefix, which misleads developers and AI generators alike. **In code, the full `TEAMID.com.example.SharedItems` string is always required.**

### App extension reading a shared keychain item

The extension target must have its own Keychain Sharing capability with the same group:

```swift
// In a widget extension, share extension, or other app extension
let teamID = "SKMME9E2Y8"
let accessGroup = "\(teamID).com.example.SharedItems"

let readQuery: [String: Any] = [
    kSecClass as String:            kSecClassGenericPassword,
    kSecAttrService as String:      "com.example.authService",
    kSecAttrAccount as String:      "user@example.com",
    kSecAttrAccessGroup as String:  accessGroup,
    kSecReturnData as String:       true
]

var result: AnyObject?
let status = SecItemCopyMatching(readQuery as CFDictionary, &result)
if status == errSecSuccess, let data = result as? Data {
    let token = String(data: data, encoding: .utf8)
    // Use the shared token
}
```

### Extension that fails because it lacks the entitlement

```swift
// ❌ This code is syntactically correct, but the extension target is
// missing the Keychain Sharing capability in Xcode → Signing & Capabilities.
// The main app has it, but extensions are SEPARATE executable targets.
// Result: errSecMissingEntitlement (-34018)
```

**Each executable target — main app, widget extension, share extension, notification extension — needs its own Keychain Sharing entitlement.** Frameworks do not have entitlements; only the targets linking them do. In Xcode: select the extension target → Signing & Capabilities → + Capability → Keychain Sharing → add the same group name.

### iCloud Keychain sync with `kSecAttrSynchronizable`

```swift
let syncQuery: [String: Any] = [
    kSecClass as String:                kSecClassGenericPassword,
    kSecAttrService as String:          "com.example.authService",
    kSecAttrAccount as String:          "user@example.com",
    kSecAttrAccessGroup as String:      "\(teamID).com.example.SharedItems",
    kSecAttrSynchronizable as String:   kCFBooleanTrue!,
    kSecAttrAccessible as String:       kSecAttrAccessibleAfterFirstUnlock,
    kSecValueData as String:            password
]
let status = SecItemAdd(syncQuery as CFDictionary, nil)
```

**Critical constraints:**

- Synchronizable items **cannot** use `kSecAttrAccessible` values ending in `ThisDeviceOnly` — the item would never sync. Attempting this silently fails to sync across devices.
- When querying for synchronizable items, include `kSecAttrSynchronizable: true` or `kSecAttrSynchronizableAny` — otherwise the search excludes them.
- The user must have iCloud Keychain enabled and be signed into the same Apple ID on all target devices.
- Synchronization is orthogonal to on-device sharing: an item can be both in a shared access group and synchronizable across devices.

```swift
// ✅ Query that finds both sync and non-sync items
let findQuery: [String: Any] = [
    kSecClass as String:                kSecClassGenericPassword,
    kSecAttrService as String:          "com.example.authService",
    kSecAttrSynchronizable as String:   kSecAttrSynchronizableAny,
    kSecReturnData as String:           true
]
```

### Assuming items sync by default

```swift
// ❌ WRONG — This item will NOT sync to iCloud Keychain.
// kSecAttrSynchronizable defaults to false when omitted.
let addQuery: [String: Any] = [
    kSecClass as String:       kSecClassGenericPassword,
    kSecAttrService as String: "com.example.authService",
    kSecAttrAccount as String: "user@example.com",
    kSecValueData as String:   password
    // No kSecAttrSynchronizable → stays on this device only
]
```

iCloud Keychain sync is **strictly opt-in per item**. Omitting `kSecAttrSynchronizable` or setting it to `false` means the item exists only on the current device. Synchronized items benefit from end-to-end encryption — Apple cannot decrypt the data.

---

## Cross-Target Entitlements Setup

Extensions are separate sandboxed executable targets that do **not** inherit capabilities from their containing app.

### Xcode Configuration Steps

1. Select the main application target → Signing & Capabilities → + Capability → Keychain Sharing.
2. Add the desired group identifier (e.g., `com.example.shared`). Xcode auto-prefixes with Team ID in the entitlements file.
3. **Repeat for every extension target** — select the extension target, add Keychain Sharing, add the **exact same** group identifier.
4. For App Groups: add the App Groups capability to each target and use the same `group.` identifier.

### Required Entitlements Matrix

| Target                | `keychain-access-groups`    | `application-groups`         | Notes                                |
| --------------------- | --------------------------- | ---------------------------- | ------------------------------------ |
| **Main app**          | `TEAMID.com.example.shared` | `group.com.example.appsuite` | First entry defines default group    |
| **Share extension**   | `TEAMID.com.example.shared` | `group.com.example.appsuite` | Must match exactly                   |
| **Widget extension**  | `TEAMID.com.example.shared` | `group.com.example.appsuite` | Independent signing and provisioning |
| **Notification ext.** | `TEAMID.com.example.shared` | `group.com.example.appsuite` | Same rules apply                     |

---

## The macOS Keychain Split

macOS maintains **two completely separate keychain implementations**, and confusing them is a source of endless bugs. Per Apple's TN3137:

**File-based keychain** — the legacy system dating back to Mac OS X. Uses Access Control Lists (`SecAccess`), stores items in `.keychain-db` files, and is the default target for `SecItem` API calls on macOS. Does not support iCloud Keychain, biometrics, Secure Enclave keys, or access groups.

**Data protection keychain** — originated on iOS and arrived on macOS via iCloud Keychain in 10.9. Uses keychain access groups + `SecAccessControl`, supports iCloud sync, Touch ID/Face ID, and Secure Enclave. Available only in user-login contexts — **`launchd` daemons cannot use it**.

### Cross-platform macOS support with `kSecUseDataProtectionKeychain`

```swift
var query: [String: Any] = [
    kSecClass as String:                        kSecClassGenericPassword,
    kSecAttrService as String:                  "com.example.authService",
    kSecAttrAccount as String:                  "user@example.com",
    kSecAttrAccessGroup as String:              "\(teamID).com.example.SharedItems",
    kSecUseDataProtectionKeychain as String:     true,
    kSecValueData as String:                     password
]
let status = SecItemAdd(query as CFDictionary, nil)
```

On macOS, `kSecAttrAccessGroup` **is silently ignored** unless the data protection keychain is targeted. Setting `kSecUseDataProtectionKeychain` to `true` opts into iOS-style keychain behavior. On iOS, tvOS, and watchOS this key is ignored (those platforms always use data protection).

Two ways to target the data protection keychain on macOS: set `kSecUseDataProtectionKeychain` to `true`, or set `kSecAttrSynchronizable` to `true` (which also enables iCloud sync). Mac Catalyst and iOS Apps on Mac use data protection exclusively — the flag is ignored there.

| Platform/Runtime   | Default keychain  | Access groups supported | Required flag                         |
| ------------------ | ----------------- | ----------------------- | ------------------------------------- |
| **iOS/iPadOS**     | Data Protection   | Yes                     | None                                  |
| **Mac Catalyst**   | Data Protection   | Yes                     | None                                  |
| **macOS (AppKit)** | Legacy file-based | No (by default)         | `kSecUseDataProtectionKeychain: true` |

Apple's TN3137 states the file-based keychain is **"on the road to deprecation."** `SecKeychainCreate` was deprecated in the macOS 12 SDK. New code should target data protection exclusively, with the sole exception of `launchd` daemons that lack a user context.

---

## Migrating Items Between Access Groups

`kSecAttrAccessGroup` is **immutable** for an existing keychain item — it cannot be changed via `SecItemUpdate`. Migration requires a read-add-delete sequence:

1. **Read**: Retrieve the complete item from its original access group via `SecItemCopyMatching`.
2. **Add**: Call `SecItemAdd` with the new `kSecAttrAccessGroup`.
3. **Delete**: Only after `SecItemAdd` returns `errSecSuccess`, delete the original item via `SecItemDelete`.

If the add operation fails, the original item remains untouched, preventing data loss. This pattern is safe because it never deletes until the new copy is confirmed.

---

## Lifecycle Edge Cases

### Keychain items persist after app uninstall

This behavior is undocumented but has been consistent since iOS's early days. Apple attempted to delete keychain items on app removal in iOS 10.3 beta but rolled it back before release due to compatibility issues. Quinn "The Eskimo!" has warned this behavior **could change without notice**. If shared keychain items exist between App A and App B, deleting App A leaves all shared items intact for App B. Even deleting all apps in a shared group does not remove orphaned items — only a factory reset clears them reliably.

A common workaround for detecting fresh installs (since `UserDefaults` _are_ wiped on uninstall):

```swift
func clearKeychainOnFreshInstall() {
    let hasLaunchedBefore = UserDefaults.standard.bool(forKey: "hasLaunchedBefore")
    if !hasLaunchedBefore {
        // Scope deletion to specific service/group to avoid nuking shared items
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.example.authService"
        ]
        SecItemDelete(query as CFDictionary)
        UserDefaults.standard.set(true, forKey: "hasLaunchedBefore")
    }
}
```

> For the complete versioned migration approach and fresh-install detection pattern, see `migration-legacy-stores.md` § First-Launch Keychain Cleanup.
> Key point: The pattern above handles the basic sharing-context case; the canonical file covers multi-version migration coordination, safe deletion ordering, and CI implications.

### App transfers between teams break keychain access

Items are tied to the original Team ID. If an app is transferred to another developer account, keychain items stored under the old Team ID become inaccessible. Recommended workaround: transfer the app back, release an update that exports/migrates keychain data to an external store, then transfer again.

### Cross-developer sharing is impossible via access groups

The Team ID prefix enforcement, through code-signed provisioning profiles, prevents apps from different teams from accessing each other's keychain items. Cross-developer credential sharing requires iCloud Keychain + Associated Domains (password autofill based on web domain ownership).

---

## Platform-Specific Patterns

### watchOS

watchOS 2+ runs a **separate keychain** not connected to the paired iPhone's keychain through access groups. Sharing credentials between iPhone and Watch requires either iCloud Keychain sync (`kSecAttrSynchronizable: true`, available since watchOS 6.2) or WatchConnectivity data transfer. For watchOS apps, add Keychain Sharing to the **WatchKit Extension target**, not the WatchKit App target.

### Widget Extensions (WidgetKit)

Widget extensions follow the same rules as all app extensions — add Keychain Sharing or App Groups capabilities to the widget extension target independently. Widgets commonly need auth tokens for network requests. Store these in the shared keychain group rather than `UserDefaults(suiteName:)`, which lacks keychain-level encryption. App Group shared containers use only standard filesystem encryption (`NSFileProtectionCompleteUntilFirstUserAuthentication`), making the keychain the more secure choice for sensitive credentials.

---

## Build and Distribution Considerations

The entitlement format and Team ID prefix rules are consistent across all build configurations: development, Ad Hoc, TestFlight, and App Store distribution. The Team ID is inherent to the developer account and does not change between configurations.

However, the specific **provisioning profile** for each distribution type dictates which entitlements are allowed and embeds the correct `AppIdentifierPrefix`. Verify that the provisioning profile for each build type correctly authorizes the required access groups.

**Legacy account caveat:** Most modern accounts use the Team ID as the App ID prefix, but legacy accounts (pre-June 2011) may have per-app prefixes that differ from the Team ID. Adding capabilities like Associated Domains to one target but not another has been reported to change the prefix, causing `-34018` errors. Ensure all targets sharing a keychain group have identical capabilities.

---

## Debugging When Keychain Sharing Breaks

### Essential Error Codes

| Code       | Constant                      | Meaning                                                          |
| ---------- | ----------------------------- | ---------------------------------------------------------------- |
| **0**      | `errSecSuccess`               | Operation succeeded                                              |
| **-25299** | `errSecDuplicateItem`         | Item exists; use `SecItemUpdate` instead                         |
| **-25300** | `errSecItemNotFound`          | No match found; also returned pre-iOS 13 for unauthorized groups |
| **-34018** | `errSecMissingEntitlement`    | App lacks entitlement for the specified access group             |
| **-25308** | `errSecInteractionNotAllowed` | Device locked and item requires `WhenUnlocked` access            |
| **-50**    | `errSecParam`                 | Invalid parameter (missing `kSecClass`, wrong value types)       |

Starting with **iOS 13**, querying an unauthorized access group returns the explicit `errSecMissingEntitlement` (-34018) instead of the ambiguous `errSecItemNotFound`. This makes debugging significantly easier on modern OS versions.

### Debugging Checklist

**1. Verify entitlements on the built binary** — not the `.entitlements` source file:

```bash
codesign -d --entitlements :- /path/to/YourApp.app
codesign -d --entitlements :- /path/to/YourExtension.appex
```

Compare the `keychain-access-groups` arrays — they must contain a common group.

**2. Inspect the provisioning profile:**

```bash
security cms -D -i YourApp.app/embedded.mobileprovision
```

Verify that `keychain-access-groups`, `com.apple.security.application-groups`, and `com.apple.developer.team-identifier` are present and correct.

**3. Test on a physical device.** The iOS Simulator does not use real provisioning profiles and may not surface entitlement issues. Keychain Sharing behavior in the Simulator can differ from device behavior.

**4. Monitor system logs.** Open Console.app, select the connected device, filter for "keychain", and reproduce the issue. The system logs explicit messages when an entitlement check fails, identifying the missing group.

**5. Check for App ID prefix mismatches** across all sharing targets — especially if any target has different capabilities enabled.

### Test Matrix

| Scenario                                   | Main App | Share Ext | Widget Ext | Expected                                  |
| ------------------------------------------ | :------: | :-------: | :--------: | ----------------------------------------- |
| Write/read in `TeamID.com.example.shared`  |   Pass   |   Pass    |    Pass    | All targets see same item                 |
| Write/read in `group.com.example.appsuite` |   Pass   |   Pass    |    Pass    | Only when `kSecAttrAccessGroup` specified |
| iCloud sync (non-`ThisDeviceOnly`)         |   Pass   |    N/A    |    N/A     | Item appears on second device             |
| Missing entitlement in extension           |   N/A    |   Fail    |    N/A     | `-34018` or `-25300`                      |

---

## Security Threat Model Notes

- **End-to-end encryption:** Synchronized iCloud Keychain items are encrypted end-to-end; Apple cannot decrypt them.
- **Malicious device risk:** A device joined to the user's iCloud account could potentially access or poison synchronized keychain items. Always scope secrets minimally and validate data retrieved from shared or synchronized keychains.
- **Over-sharing risk:** Items placed in a shared access group are readable by all apps in that group. Use the narrowest possible access group — do not share an access group across apps that do not need the same credentials.
- **Orphaned items:** After all apps in a shared group are uninstalled, keychain items remain on-device until factory reset. Consider this when storing highly sensitive data.

---

## What Changed in 2024–2026

The core `SecItem` API has **not changed**. No new keychain-sharing-specific APIs were introduced in iOS 17, 18, or macOS 14/15. Apple still has not shipped a Swift-native keychain wrapper; the C-based Security framework remains the only official interface.

The **Passwords app** introduced in iOS 18 and macOS Sequoia (WWDC 2024) provides a dedicated user-facing interface for managing passwords, passkeys, and verification codes. This is a UI layer over iCloud Keychain — it does not affect the `SecItem` API or access group mechanics.

**Passkey enhancements** continued through WWDC 2024–2025, including automatic passkey upgrades and credential import/export APIs (`ASCredentialExportManager`). These operate at the credential-manager level and do not introduce new keychain-sharing mechanisms.

`kSecAttrAccessibleAlways` and `kSecAttrAccessibleAlwaysThisDeviceOnly` remain deprecated since iOS 12. Use `kSecAttrAccessibleAfterFirstUnlock` or the more restrictive `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`.

---

## Cross-References

- `keychain-fundamentals.md` — SecItem CRUD patterns, `kSecUseDataProtectionKeychain` on macOS, query dictionary construction
- `keychain-access-control.md` — Accessibility constants for shared items, `ThisDeviceOnly` vs syncable implications
- `keychain-item-classes.md` — Composite primary keys and how `kSecAttrAccessGroup` interacts with each `kSecClass`
- `common-anti-patterns.md` — Anti-pattern #5 (missing `kSecAttrAccessible`), which compounds in shared contexts
- `credential-storage-patterns.md` — OAuth token sharing between app and extensions

---

## Conclusion

Keychain sharing on Apple platforms is a precise, entitlement-driven system where small configuration errors — a missing Team ID prefix, a capability not added to an extension target, a forgotten `kSecUseDataProtectionKeychain` on macOS — produce cryptic errors with no runtime warnings. The access group array's three-source concatenation order determines defaults and search scope in ways that catch developers off guard.

Three rules prevent most issues: always include the full Team ID prefix in code (`TEAMID.com.example.shared`, never just `com.example.shared`); add Keychain Sharing to every executable target that needs access, not just the main app; and set `kSecUseDataProtectionKeychain` to `true` on macOS for iOS-consistent behavior. For iCloud sync, remember that `kSecAttrSynchronizable` defaults to `false` and that queries must explicitly opt in to find synchronizable items.

---

## Summary Checklist

1. **Team ID prefix in code** — Access group strings in Swift must use the fully resolved `TEAMID.com.example.shared` format; `$(AppIdentifierPrefix)` only works in entitlements plists.
2. **Per-target entitlements** — Every executable target (main app, each extension) must independently have the Keychain Sharing capability added in Xcode with the same group identifier.
3. **Keychain Sharing vs App Groups** — These are separate entitlements with different formats (`keychain-access-groups` with Team ID prefix vs `com.apple.security.application-groups` with `group.` prefix). App Groups cannot serve as keychain access groups on macOS.
4. **Default access group awareness** — The first entry in the concatenated access group array (keychain groups → app identifier → app groups) becomes the default. App Groups can never be the default.
5. **Explicit `kSecAttrAccessGroup`** — Always specify the access group in both `SecItemAdd` and `SecItemCopyMatching` calls. Omitting it on add uses the default group (which may be unexpected); omitting it on query searches all groups (which may be slow or overly broad).
6. **iCloud sync is opt-in** — `kSecAttrSynchronizable` defaults to `false`. Sync requires non-`ThisDeviceOnly` accessibility, and queries must include `kSecAttrSynchronizable: true` or `kSecAttrSynchronizableAny` to find synced items.
7. **macOS data protection keychain** — Set `kSecUseDataProtectionKeychain: true` on all macOS `SecItem` calls. Without it, `kSecAttrAccessGroup` is silently ignored and the legacy file-based keychain is used.
8. **Items persist after uninstall** — Keychain items survive app deletion. Use a `UserDefaults` flag to detect fresh installs and clean up stale items. Scope deletion carefully to avoid nuking shared items.
9. **`kSecAttrAccessGroup` is immutable** — Moving an item between groups requires a read-add-delete sequence, not an update.
10. **Verify built binary entitlements** — Use `codesign -d --entitlements :-` on the built `.app`/`.appex` to confirm entitlements, not the source `.entitlements` file. Test on physical devices; the Simulator may not surface entitlement issues.
11. **watchOS is isolated** — The Apple Watch has a separate keychain not connected via access groups. Use iCloud Keychain sync or WatchConnectivity for cross-device credential sharing.
