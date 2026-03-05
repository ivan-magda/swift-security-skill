# Biometric Authentication

> **Domain scope:** SecAccessControl + LAContext integration, the LAContext-only bypass vulnerability, hardware-bound biometric gating, fallback behavior, UI customization, enrollment change detection, thread safety.
>
> **Risk level:** CRITICAL — #1 most dangerous AI-generated pattern. `LAContext.evaluatePolicy()` used alone is trivially bypassable at runtime.

---

## The Boolean Gate Vulnerability

The most dangerous pattern AI coding assistants generate for iOS biometric authentication is `LAContext.evaluatePolicy()` used as a standalone authentication gate. This pattern appears in virtually every tutorial, Stack Overflow answer, and AI training corpus — and it is **trivially bypassable**.

The attack requires no exploit. An attacker uses Frida or objection to hook the Objective-C callback and force `success = true`, bypassing Face ID or Touch ID entirely. The formal weakness classification is CWE-288: Authentication Bypass Using an Alternate Path or Channel.

OWASP MASTG explicitly fails any app relying solely on `evaluatePolicy` (test MASTG-TEST-0266, requirements MSTG-AUTH-8 and MSTG-AUTH-12). The standard states: biometric authentication must not be event-bound (returning `true`/`false`); it must be based on unlocking the keychain/keystore.

### The Dangerous Pattern — Boolean Gate

```swift
// ❌ DANGEROUS: Trivially bypassable with Frida — do NOT use for security
import LocalAuthentication

func authenticateUser() {
    let context = LAContext()
    var error: NSError?

    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Authenticate to access your account"
        ) { success, authError in
            DispatchQueue.main.async {
                if success {
                    self.isAuthenticated = true   // ← Just a boolean in hookable memory
                    self.showProtectedContent()   // ← No secret unlocked, no key released
                }
            }
        }
    }
}
```

**Why this fails:** `evaluatePolicy()` asks the OS "did the user authenticate?" and receives a boolean answer in user-space. No cryptographic material is involved. No secret is decrypted. The entire security model rests on a boolean that exists in hookable memory.

### How Attackers Bypass It

The objection tool (built on Frida) provides a one-command bypass:

```bash
objection -g "com.example.targetapp" explore
ios ui biometrics_bypass
```

The hook listens for invocations of `-[LAContext evaluatePolicy:localizedReason:reply:]`, intercepts the reply block, and replaces the `success` boolean with `true`. The equivalent raw Frida script:

```javascript
// Frida script — forces evaluatePolicy success = true
if (ObjC.available) {
  var hook = ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"];
  Interceptor.attach(hook.implementation, {
    onEnter: function (args) {
      var block = new ObjC.Block(args[4]);
      const callback = block.implementation;
      block.implementation = function (error, value) {
        const result = callback(1, null); // 1 = true, null = no error
        return result;
      };
    },
  });
}
```

The objection wiki confirms the attack boundary: this bypass **does not work** against keychain items protected with access control flags like `.biometryCurrentSet` or `.biometryAny`. That boundary is the entire basis of the secure pattern.

✅ Correct pattern in this threat model: use biometrics only to unlock keychain-protected secrets (`SecAccessControl` + `SecItemCopyMatching`), never as a standalone boolean gate.

---

## The Secure Pattern — Hardware-Bound Secrets

The correct architecture stores a secret in the iOS keychain with biometric access control. The secret's encryption key is held by the Secure Enclave — a dedicated processor running its own microkernel (sepOS), with its own encrypted memory, completely isolated from the application processor.

When the app requests the secret, the Secure Enclave independently verifies the biometric match and only then releases the decryption key. There is no boolean to hook. The data physically cannot be read without valid biometric authentication.

WWDC 2014 Session 711 ("Keychain and Authentication with Touch ID") drew the critical distinction:

- **`evaluatePolicy`**: "Trust the OS" — vulnerable if runtime is compromised
- **Keychain + SecAccessControl**: "Trust the Secure Enclave" — ACLs evaluated inside hardware

### Step 1 — Create the Access Control Object

```swift
import LocalAuthentication
import Security

enum BiometricKeychainError: Error {
    case accessControlCreationFailed
    case keychainOperationFailed(status: OSStatus)
    case dataConversionFailed
    case biometryNotAvailable(reason: String)
}

func createBiometricAccessControl() throws -> SecAccessControl {
    var error: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,  // Strongest: requires passcode, device-only
        .biometryCurrentSet,                               // Invalidates on enrollment change
        &error
    ) else {
        throw BiometricKeychainError.accessControlCreationFailed
    }
    return accessControl
}
```

### Step 2 — Store a Secret Bound to Biometric Auth

```swift
// ✅ SECURE: Secret is encrypted by Secure Enclave, released only on biometric match
func storeSecretWithBiometric(secret: Data, account: String, service: String) throws {
    let accessControl = try createBiometricAccessControl()

    // Delete any existing item first (add-or-update pattern)
    let deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service
    ]
    SecItemDelete(deleteQuery as CFDictionary)

    let addQuery: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service,
        kSecValueData as String: secret,
        kSecAttrAccessControl as String: accessControl,
        kSecAttrSynchronizable as String: kCFBooleanFalse  // Never sync biometric-gated secrets
        // NOTE: Do NOT set kSecAttrAccessible — it conflicts with kSecAttrAccessControl
    ]

    let status = SecItemAdd(addQuery as CFDictionary, nil)
    guard status == errSecSuccess else {
        throw BiometricKeychainError.keychainOperationFailed(status: status)
    }
}
```

**Critical detail:** Do NOT set both `kSecAttrAccessible` and `kSecAttrAccessControl` in the same query. They conflict — `SecAccessControl` already encodes the accessibility level. Setting both causes `errSecParam`.

**Critical detail:** Always use `ThisDeviceOnly` accessibility for biometric-gated secrets. The `ThisDeviceOnly` suffix ensures the secret is hardware-bound and excluded from iCloud backups. Syncing biometric-gated secrets across devices expands the attack surface.

### Step 3 — Retrieve the Secret (Biometric Prompt Appears Automatically)

```swift
// ✅ SECURE: System presents biometric prompt; Secure Enclave gates decryption
func retrieveSecretWithBiometric(account: String, service: String) throws -> Data {
    let context = LAContext()
    context.localizedReason = "Authenticate to access your credentials"

    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: account,
        kSecAttrService as String: service,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecUseAuthenticationContext as String: context
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    switch status {
    case errSecSuccess:
        guard let data = result as? Data else {
            throw BiometricKeychainError.dataConversionFailed
        }
        return data  // Secret returned ONLY after Secure Enclave validates biometric
    case errSecItemNotFound:
        throw BiometricKeychainError.keychainOperationFailed(status: status)
    case errSecUserCanceled:
        throw BiometricKeychainError.keychainOperationFailed(status: status)
    case errSecAuthFailed:
        throw BiometricKeychainError.keychainOperationFailed(status: status)
    default:
        throw BiometricKeychainError.keychainOperationFailed(status: status)
    }
}
```

**Key insight:** Authentication and data protection are the same operation, not sequential ones. When `SecItemCopyMatching` encounters an item with biometric access control, the system presents the biometric prompt automatically. The Secure Enclave verifies the match internally and only then unwraps the AES-256-GCM decryption key. There is no callback to intercept.

---

## `evaluatePolicy` vs `evaluateAccessControl`

These two `LAContext` methods represent the two trust models from WWDC 2014 Session 711:

**`evaluatePolicy(_:localizedReason:reply:)`** triggers biometric authentication and returns a boolean. The Secure Enclave validates the biometric correctly, but the result is communicated to user-space as `true`/`false`. No key is released. The app branches on a boolean in hookable memory. This is "trust the OS."

**`evaluateAccessControl(_:operation:localizedReason:reply:)`** evaluates a `SecAccessControl` object for a specific cryptographic operation (`.useItem`, `.useKeySign`, `.useKeyDecrypt`). When used with keychain items, the authenticated `LAContext` is passed to `SecItemCopyMatching` via `kSecUseAuthenticationContext`, and the Secure Enclave recognizes the prior authentication. This is "trust the Secure Enclave."

**In practice, you rarely call `evaluateAccessControl` directly.** The recommended flow: store data with `SecAccessControl` via `SecItemAdd`, then retrieve with `SecItemCopyMatching`. The system handles the biometric prompt automatically when the query encounters an ACL-protected item.

The only legitimate use of `evaluatePolicy` is **non-security-critical UI gating** — deciding whether to show a "Sign in with Face ID" button. It must never protect sensitive data or gate access to secrets.

---

## Biometric Flag Selection

`SecAccessControlCreateFlags` provides three biometric-related flags. Choosing the wrong one is a common mistake even in otherwise-correct implementations.

### `.biometryCurrentSet` — Banking, Payments, Credential Storage

Ties the keychain item to the **exact biometric enrollment** at time of storage. If the user adds a fingerprint, re-enrolls Face ID, or removes a biometric entry, the item becomes **permanently inaccessible**.

```swift
// ✅ Strongest biometric binding — invalidates on enrollment change
let access = SecAccessControlCreateWithFlags(
    nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    .biometryCurrentSet, nil
)
```

**Tradeoff:** Users who change biometrics must re-authenticate via your app's password flow. Detect enrollment changes via `LAContext.evaluationPolicyDomainState` (see Enrollment Change Detection below) and present graceful re-enrollment.

### `.biometryAny` — Convenience Features, Moderate Sensitivity

Survives biometric enrollment changes. An attacker who enrolls their own biometrics on a compromised device can access the data.

```swift
// Survives re-enrollment — better UX, weaker security
let access = SecAccessControlCreateWithFlags(
    nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    .biometryAny, nil
)
```

**Use case:** "Remember me" features, non-critical app locks, preferences that benefit from biometric convenience without protecting financial data.

### `.userPresence` — Maximum Device Compatibility

Allows passcode fallback when biometrics are unavailable. Weaker because passcodes are susceptible to shoulder-surfing.

```swift
// Broadest compatibility — biometric or passcode
let access = SecAccessControlCreateWithFlags(
    nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    .userPresence, nil
)
```

**Use case:** Accessibility-first apps, devices without biometric hardware, or as a `.biometryCurrentSet` degradation path.

### Combining Flags

Flags can be combined with `.or` and `.and` conjunctions:

```swift
// ✅ Strong biometric binding WITH passcode escape hatch
let access = SecAccessControlCreateWithFlags(
    nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    [.biometryCurrentSet, .or, .devicePasscode], nil
)
```

This combination is practical for most production apps — strong biometric security with a recovery path when biometrics become unavailable.

---

## Biometric Availability Checks and Graceful Degradation

### Incomplete Availability Check

```swift
// ❌ WRONG: Ignores WHY biometrics failed — user gets no guidance
func checkBiometrics() -> Bool {
    let context = LAContext()
    var error: NSError?
    return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
}
```

### Complete Availability Evaluation

```swift
// ✅ CORRECT: Evaluates every failure reason with actionable guidance
enum BiometricAvailability {
    case available(type: LABiometryType)
    case notEnrolled          // Hardware exists, no biometrics registered
    case lockedOut            // Too many failed attempts — passcode required
    case notAvailable         // No hardware or restricted by MDM
    case passcodeNotSet       // No device passcode — biometrics require one
}

func evaluateBiometricAvailability() -> BiometricAvailability {
    let context = LAContext()
    var error: NSError?

    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
        return .available(type: context.biometryType)
    }

    guard let laError = error as? LAError else { return .notAvailable }

    switch laError.code {
    case .biometryNotEnrolled:
        return .notEnrolled     // → "Enable Face ID in Settings"
    case .biometryLockout:
        return .lockedOut       // → Prompt passcode to reset sensor
    case .biometryNotAvailable:
        return .notAvailable    // → Hide biometric UI entirely
    case .passcodeNotSet:
        return .passcodeNotSet  // → "Set a passcode to use Face ID"
    default:
        return .notAvailable
    }
}
```

### Graceful Degradation Flow

```swift
// ✅ Degrades from biometric → passcode → password login
func authenticateWithGracefulDegradation() async throws -> Data {
    let availability = evaluateBiometricAvailability()

    switch availability {
    case .available:
        return try retrieveSecretWithBiometric(account: "user", service: "com.app.auth")

    case .lockedOut:
        // Biometrics locked — use .userPresence item for passcode fallback
        return try retrieveSecretWithPasscodeFallback(account: "user", service: "com.app.auth")

    case .notEnrolled:
        throw BiometricKeychainError.biometryNotAvailable(
            reason: "Please enable Face ID in Settings > Face ID & Passcode"
        )

    case .notAvailable, .passcodeNotSet:
        throw BiometricKeychainError.biometryNotAvailable(
            reason: "Biometric authentication is not available on this device"
        )
    }
}
```

**Critical:** Failing to handle `.biometryLockout` strands users. The app cannot bypass this lockout — the user must successfully enter their device passcode to re-enable the biometric sensor. If your app has no fallback, users are permanently locked out until they leave your app and unlock with passcode.

**Important:** `canEvaluatePolicy()` is strictly for pre-flight UI decisions (showing or hiding a "Sign in with Face ID" button). It must never be used as a security control.

---

## Enrollment Change Detection

When using `.biometryCurrentSet`, detect enrollment changes proactively so your app can guide the user through re-enrollment rather than presenting a cryptic keychain error.

```swift
// ✅ Detect biometric enrollment changes via domainState
class BiometricEnrollmentMonitor {
    private let domainStateKey = "com.app.biometric.domainState"

    /// Call after successful biometric setup to snapshot current enrollment
    func saveCurrentEnrollment() {
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else { return }

        // domainState changes whenever biometric enrollment changes
        if let domainState = context.evaluatedPolicyDomainState {
            UserDefaults.standard.set(domainState, forKey: domainStateKey)
        }
    }

    /// Call on app launch or before biometric retrieval
    func hasEnrollmentChanged() -> Bool {
        let context = LAContext()
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else {
            return true  // Can't evaluate — treat as changed
        }

        guard let currentState = context.evaluatedPolicyDomainState,
              let savedState = UserDefaults.standard.data(forKey: domainStateKey) else {
            return true  // No saved state — first run or data cleared
        }

        return currentState != savedState
    }
}
```

**Note:** `evaluatedPolicyDomainState` is an opaque `Data` blob. It changes whenever biometric enrollment changes but reveals no information about the biometrics themselves. Store it in `UserDefaults` (not keychain) since it is not sensitive — it's only used for change detection.

---

## Thread Safety and async/await

`SecItemCopyMatching` with biometric access control **blocks the calling thread** until the user completes authentication. Never run it on `@MainActor` or the main thread.

`LAContext.evaluatePolicy`'s legacy completion handler executes on a private queue in an unspecified threading context. Direct UI updates from this callback cause crashes, especially on iOS 18 where threading strictness increased.

### Actor-Isolated Biometric Keychain (iOS 15+)

```swift
@available(iOS 15.0, *)
actor BiometricKeychain {

    func retrieveSecret(account: String, service: String) async throws -> Data {
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let context = LAContext()
                context.localizedReason = "Authenticate to access your account"

                let query: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: account,
                    kSecAttrService as String: service,
                    kSecReturnData as String: true,
                    kSecMatchLimit as String: kSecMatchLimitOne,
                    kSecUseAuthenticationContext as String: context
                ]

                var result: AnyObject?
                let status = SecItemCopyMatching(query as CFDictionary, &result)

                switch status {
                case errSecSuccess:
                    if let data = result as? Data {
                        continuation.resume(returning: data)
                    } else {
                        continuation.resume(throwing: BiometricKeychainError.dataConversionFailed)
                    }
                case errSecUserCanceled, errSecAuthFailed:
                    continuation.resume(throwing: BiometricKeychainError.keychainOperationFailed(status: status))
                default:
                    continuation.resume(throwing: BiometricKeychainError.keychainOperationFailed(status: status))
                }
            }
        }
    }
}
```

### SwiftUI ViewModel Integration

```swift
@MainActor
class AuthViewModel: ObservableObject {
    @Published var isAuthenticated = false
    @Published var errorMessage: String?

    private let keychain = BiometricKeychain()

    func authenticate() {
        Task {
            do {
                let secret = try await keychain.retrieveSecret(
                    account: "user_token",
                    service: "com.myapp.auth"
                )
                self.isAuthenticated = true
                self.processToken(secret)
            } catch {
                self.errorMessage = error.localizedDescription
            }
        }
    }
}
```

**Note on native async:** `LAContext` gained `evaluatePolicy(_:localizedReason:) async throws -> Bool` in iOS 15. However, this is only relevant for the non-security-critical UI gating use case. For the secure keychain pattern, you wrap `SecItemCopyMatching` as shown above — there is no native async overload for SecItem\* APIs.

---

## Secure Enclave-Backed Keys with Biometric Protection

For asymmetric key operations (signing, key agreement), combine Secure Enclave key generation with biometric access control via CryptoKit. The private key **never leaves the Secure Enclave** — all operations happen in hardware.

```swift
// ✅ Secure Enclave P-256 key with biometric protection (WWDC 2019-709)
let accessControl = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryCurrentSet],
    nil
)!

let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
    accessControl: accessControl
)

// Signing triggers biometric prompt automatically
let signature = try privateKey.signature(for: dataToSign)
```

Frida operates in user-space on the application processor and has zero access to the Secure Enclave's internal state. The Secure Enclave's memory is encrypted with its own AES engine. Even a kernel-level compromise cannot extract the keys.

---

## SDLC Controls — Catching the Anti-Pattern in CI

Because AI coding assistants frequently generate the vulnerable `evaluatePolicy` pattern, teams should implement automated detection:

**Conceptual SAST rule (`INSECURE_BIOMETRIC_GATE`):** Identify all calls to `LAContext.evaluatePolicy`. If the `success` boolean directly gates access to a resource AND there is no corresponding `SecItemCopyMatching` using a `SecAccessControl` object in the same flow, flag the code.

**Security review sign-off criteria:**

1. Zero instances of standalone `LAContext.evaluatePolicy` gating sensitive operations
2. Evidence of `SecItemAdd` with `kSecAttrAccessControl` using `ThisDeviceOnly` accessibility
3. Documented proof that objection bypass (`ios ui biometrics_bypass`) fails to unlock protected data
4. All `LAError` cases handled with graceful degradation
5. If `.biometryCurrentSet` is used, a tested re-enrollment recovery flow exists

---

## Dynamic Verification — Proving Bypass Resistance

Static code review alone is insufficient. Verification requires dynamic testing:

**Test procedure:** On a jailbroken or instrumented device, inject a Frida script to hook `-[LAContext evaluatePolicy:localizedReason:reply:]` and force `success = true`.

**Pass criteria:** The app prevents access to protected data despite the manipulated callback. The secret remains locked because `SecAccessControl` + Secure Enclave enforcement is independent of the boolean.

**Fail criteria:** The app grants access after the hook forces success. This proves reliance on the vulnerable boolean gate.

---

## Key References

- **WWDC 2014 Session 711** — "Keychain and Authentication with Touch ID": Introduced the two trust models (evaluatePolicy vs keychain+ACL)
- **WWDC 2019 Session 709** — "Cryptography and Your Apps": CryptoKit + Secure Enclave key generation with access control
- **Apple Platform Security Guide** — Secure Enclave architecture, keychain encryption chain (metadata key + secret key), ACL evaluation in hardware
- **OWASP MASTG MSTG-AUTH-8** — Biometric authentication must not be event-bound
- **OWASP MASTG MSTG-AUTH-12** — Integrity of biometric mechanism must be verified
- **OWASP MASTG MASTG-TEST-0266** — Test for local authentication bypass
- **objection wiki** — "Understanding the iOS Biometrics Bypass": Confirms attack boundary at SecAccessControl
- **TN3137** — "On Mac Keychain APIs and implementations" (macOS keychain unification)

---

## Cross-References

- `keychain-fundamentals.md` — SecItem CRUD patterns used by the keychain-bound biometric flow
- `keychain-access-control.md` — `SecAccessControlCreateWithFlags`, accessibility constants, and flag composition rules
- `secure-enclave.md` — Hardware-backed keys with biometric gating via `SecAccessControl`
- `common-anti-patterns.md` — Anti-pattern #3 (LAContext-only biometric gate)
- `credential-storage-patterns.md` — Biometric protection for high-value credentials (OAuth tokens, API keys)
- `testing-security-code.md` — Protocol-based mocking for biometric flows, LAContext test strategies
- `compliance-owasp-mapping.md` — M3 (Insecure Authentication/Authorization) biometric requirements

---

## Summary Checklist

1. **No standalone boolean gates** — `LAContext.evaluatePolicy()` is NEVER the sole authentication mechanism for sensitive data; secrets are always bound to keychain + `SecAccessControl`
2. **Hardware-gated secrets** — All sensitive data protected by biometrics uses `SecAccessControlCreateWithFlags` with the Secure Enclave enforcing the ACL
3. **Correct flag selection** — `.biometryCurrentSet` for high-security (banking, payments); `.biometryAny` for convenience; `.userPresence` for broad compatibility or fallback
4. **No kSecAttrAccessible conflict** — `kSecAttrAccessible` and `kSecAttrAccessControl` are never set on the same keychain item
5. **ThisDeviceOnly accessibility** — Biometric-gated secrets use `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` or `WhenUnlockedThisDeviceOnly`; never syncable
6. **Complete error handling** — All `LAError` codes handled: `.biometryNotEnrolled`, `.biometryLockout`, `.biometryNotAvailable`, `.passcodeNotSet`, `.userCancel`, `.userFallback`
7. **Graceful degradation** — App provides fallback path (passcode or password) when biometrics are unavailable or locked out
8. **Enrollment change detection** — `evaluatedPolicyDomainState` monitored when using `.biometryCurrentSet`; re-enrollment flow implemented
9. **Thread safety** — `SecItemCopyMatching` with biometric ACL never runs on `@MainActor`; actor-isolated or dispatched to background queue
10. **Dynamic verification** — objection/Frida bypass test confirms protected data remains inaccessible when `evaluatePolicy` callback is hooked
11. **SAST/linting** — CI pipeline includes rule to flag standalone `evaluatePolicy` without corresponding `SecAccessControl` keychain operations
