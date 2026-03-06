# Category 5: Edge Case Tests

Tests for out-of-scope handling, ambiguous queries, version constraints, and opinion-seeking. These verify that the skill correctly applies scope boundaries, tone rules, and version baselines.

---

### Test E-1: Out-of-Scope — App Transport Security

**Category:** Edge Cases
**Domains tested:** (none — tests scope boundaries)
**Difficulty:** EASY

**Prompt (give this exact text to Claude):**
> How should I configure App Transport Security for my banking app's API? I want to allow HTTP for our staging server while keeping HTTPS enforced for production.

**Expected catches (GREEN should find all, RED may miss some):**
1. **Correctly identifies ATS as out of scope** — does not attempt to provide ATS configuration using keychain/CryptoKit knowledge. States clearly that ATS configuration is outside the skill's scope.
2. **Redirects appropriately** — points to Apple's NSAppTransportSecurity documentation or the Info.plist reference as the correct resource.
3. **Does not fabricate an answer** — does not invent ATS guidance by extrapolating from certificate trust or keychain knowledge.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if partially declines but still provides some ATS guidance
- 0 points if attempts a full ATS answer
- Bonus point (+1) if GREEN mentions the specific exclusion from SKILL.md's scope table
- Total possible: 4

**Why this tests the skill (not just general knowledge):**
> Without the skill, Claude will happily provide ATS configuration guidance from general knowledge. With the skill, it should recognize the scope boundary and decline gracefully. This tests whether the skill's exclusion table is followed, not just the inclusion list.

---

### Test E-2: Opinion-Seeking — Third-Party Keychain Wrapper

**Category:** Edge Cases
**Domains tested:** (tests tone rules and behavioral boundaries)
**Difficulty:** MEDIUM

**Prompt (give this exact text to Claude):**
> Should I use KeychainAccess (the CocoaPod) or write my own keychain wrapper? What are the tradeoffs?

**Expected catches (GREEN should find all, RED may miss some):**
1. **Advisory tone (not directive)** — uses "consider," "one approach is," not "always use native" or "never use third-party." This is a choice, not a security invariant. (Tone Rules)
2. **Presents objective tradeoffs** — native APIs have no dependency overhead; third-party wrappers reduce boilerplate at the cost of coupling to a maintenance schedule. Does not say "this skill does not recommend..."
3. **Shows native API patterns** — demonstrates the native `SecItem*` approach as the primary code example, since the skill's code examples always use native APIs.
4. **Does not reject the library outright** — acknowledges KeychainAccess/Valet/similar libraries exist and serve valid purposes. (Behavioral Boundaries: "adopt advisory tone: present objective tradeoffs without directive rejection")

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if tone is mostly advisory but slips into directive on non-security-invariant points
- 0 points if dismisses third-party libraries or uses directive tone throughout
- Bonus point (+1) if GREEN explicitly mentions the Tone Rules from SKILL.md
- Total possible: 5

**Why this tests the skill (not just general knowledge):**
> Without the skill, Claude might default to either "use the library, it's easier" or "always use native APIs." The skill's tone rules specifically call out this scenario: library choice is advisory, not directive. The behavioral boundaries explicitly state not to say "this skill does not recommend..." for library questions.

---

### Test E-3: Version Constraint — CryptoKit on iOS 12

**Category:** Edge Cases
**Domains tested:** `cryptokit-symmetric.md` (version baseline)
**Difficulty:** EASY

**Prompt (give this exact text to Claude):**
> I need to support iOS 12. How do I use CryptoKit for AES-GCM encryption in my app?

**Expected catches (GREEN should find all, RED may miss some):**
1. **Correctly states CryptoKit requires iOS 13+** — does not claim CryptoKit works on iOS 12. Clear, accurate version statement.
2. **Provides Security framework / CommonCrypto fallback** — for iOS 12, the path is CommonCrypto's `CCCrypt` with `kCCAlgorithmAES` and GCM mode, or the Security framework's `SecKeyCreateEncryptedData` for asymmetric operations.
3. **Does not fabricate a polyfill** — does not suggest importing CryptoKit conditionally on iOS 12 or claim there's a backport.
4. **Recommends raising deployment target if possible** — advisory suggestion to move to iOS 13+ to gain CryptoKit, noting that iOS 12 reached end-of-life years ago.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mentions iOS 13+ but provides incorrect fallback details
- 0 points if claims CryptoKit works on iOS 12
- Bonus point (+1) if GREEN cites the Version Baseline table from SKILL.md
- Total possible: 5

**Why this tests the skill (not just general knowledge):**
> This tests a factual version constraint. An unassisted LLM might correctly state iOS 13+ but could also hallucinate an earlier version or suggest non-existent polyfills. The skill's Version Baseline table provides the authoritative answer.

---

### Test E-4: Opinion-Seeking — P256 vs Curve25519

**Category:** Edge Cases
**Domains tested:** `cryptokit-public-key.md` (curve selection)
**Difficulty:** MEDIUM

**Prompt (give this exact text to Claude):**
> Is P256 or Curve25519 better for my iOS app's end-to-end encryption?

**Expected catches (GREEN should find all, RED may miss some):**
1. **Advisory tone throughout** — uses "consider," "one approach is," "the tradeoff is." Does NOT use "always use X" or "never use Y" — this is a design choice, not a security invariant. (Tone Rules)
2. **Presents both tradeoffs** — P256: Secure Enclave support, NIST compliance, broader server interop, PEM/DER export. Curve25519: inherent constant-time execution, compact keys (32 bytes), modern protocol alignment, but no SE support and raw representation only.
3. **Mentions Secure Enclave as differentiator** — if hardware-backed key protection is needed, P256 is the only classical option (SE is P256-only).
4. **Correct version information** — both available since iOS 13 (CryptoKit). Does not claim either requires a later version.
5. **Does not declare a winner** — presents information for the user to decide based on their requirements, not a definitive "use X."

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if mostly advisory but makes a definitive recommendation
- 0 points if uses directive tone or gives incorrect version information
- Bonus point (+1) if GREEN cites `cryptokit-public-key.md` and the Selection Decision Matrix
- Total possible: 6

**Why this tests the skill (not just general knowledge):**
> An unassisted LLM may default to "Curve25519 is more modern, use that" without considering Secure Enclave as a differentiator or presenting balanced tradeoffs. The skill's curve selection matrix and tone rules ensure a nuanced, advisory response.

---

### Test E-5: Out-of-Scope — CloudKit Encrypted Records

**Category:** Edge Cases
**Domains tested:** (none — tests scope boundaries)
**Difficulty:** EASY

**Prompt (give this exact text to Claude):**
> Review this CloudKit code for security issues:
>
> ```swift
> import CloudKit
>
> func saveSecureRecord(data: String) async throws {
>     let record = CKRecord(recordType: "SecureNote")
>     record.encryptedValues["content"] = data
>     record.encryptedValues["timestamp"] = Date()
>
>     let container = CKContainer.default()
>     let database = container.privateCloudDatabase
>     try await database.save(record)
> }
> ```

**Expected catches (GREEN should find all, RED may miss some):**
1. **Correctly identifies CloudKit encryption as out of scope** — does not attempt a security review of CloudKit-specific APIs using keychain/CryptoKit knowledge. States that CloudKit's server-managed key hierarchy is outside the skill's scope.
2. **Redirects appropriately** — points to CloudKit documentation, `CKRecord.encryptedValues` reference as the correct resource.
3. **Does not fabricate security findings** — does not invent issues by applying keychain patterns to CloudKit APIs. Does not say "you should store this in keychain instead" — `encryptedValues` is Apple's sanctioned approach for CloudKit data.

**Scoring:**
- Each expected catch = 1 point
- Partial credit (0.5) if partially declines but still offers some CloudKit security opinions
- 0 points if attempts a full security review of the CloudKit code
- Bonus point (+1) if GREEN mentions the specific exclusion from SKILL.md's scope table
- Total possible: 4

**Why this tests the skill (not just general knowledge):**
> Without the skill, Claude will likely review the CloudKit code using general iOS security knowledge, possibly recommending keychain patterns that don't apply. With the skill, it should recognize CloudKit encryption is explicitly out of scope and decline gracefully, redirecting to proper CloudKit documentation.
