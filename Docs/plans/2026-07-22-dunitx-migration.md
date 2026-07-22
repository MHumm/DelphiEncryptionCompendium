# DUnit → DUnitX Migration Plan

> **For agentic workers:** Implement task-by-task on branch `Cleanup_OM-DUnitX-migration`. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make DUnitX the complete, authoritative unit-test runner for DEC while temporarily keeping the classic DUnit suite for parity comparison.

**Architecture:** Keep the dual-project layout during migration. Bring the DUnitX project to full parity with DUnit (all units, all fixtures, same assertions via `DUnitX.DUnitCompatibility` first). Prove green/green equivalence. Only after that, optionally modernize asserts / drop compatibility — **without** deleting DUnit yet.

**Tech Stack:** Delphi DUnitX (`DUnitX.TestFramework`, console + NUnit XML logger), existing DUnit (`TestFramework`, GUI/Text runners), shared test units under `Unit Tests/Tests/`.

**Branch:** `Cleanup_OM-DUnitX-migration` (from `Cleanup_OM`)  
**PR target (later):** `Cleanup_OM` → eventually `development`

## Global Constraints

- **Keep DUnit for now.** `DECDUnitTestSuite` stays buildable and runnable as a comparison baseline until we explicitly decide to remove it (separate decision, not part of the first migration PR).
- **Do not change production crypto code** in this migration unless a test reveals a real bug; then fix in a separate commit with a clear message.
- **Do not mix** AEAD architecture or ChaCha (PR #90) into this work.
- Prefer **behaviour-preserving** migration: same tests, same vectors, same pass/fail meaning.
- Project language for commits/docs in this package: **English** (matches DEC upstream).
- Encoding for any touched `.pas`: preserve existing style; do not mass-reformat.

---

## 0. Audit summary (pre-migration)

### 0.1 Projects

| Project | Role today | Keep? |
|---|---|---|
| `Unit Tests/DECDUnitTestSuite.dpr` | Classic DUnit (GUI/console, TestInsight optional) | **Yes, temporarily** — comparison baseline |
| `Unit Tests/DECDUnitXTestSuite.dpr` | DUnitX console runner | **Yes** — target authoritative suite |
| `Unit Tests/Tests/TestDefines.inc` | `{.$DEFINE DUnitX}` off by default | Will enable for DUnitX path; DUnit path remains without define |

### 0.2 Coverage gap (critical)

DUnitX project is **behind** DUnit. Missing from `DECDUnitXTestSuite.dpr`:

| Unit | In DUnit? | In DUnitX? | Notes |
|---|---|---|---|
| `TestDECCipherModesCCM.pas` | Yes | **No** | CCM mode + NIST-style vectors |
| `TestDECZIPHelper.pas` | Yes | **No** | ZIP crypto algorithm helper |
| `AuthenticatedCiphersCommonTestData.pas` | Yes | **No** | Shared data (not a fixture; needed by CCM/GCM) |

All other test units appear in both projects.

### 0.3 Dual-stack pattern (current)

Almost every fixture unit does:

```pascal
{$INCLUDE TestDefines.inc}
uses
  {$IFDEF DUnitX}
  DUnitX.TestFramework, DUnitX.DUnitCompatibility,
  {$ELSE}
  TestFramework,
  {$ENDIF}
  ...
type
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TMyTests = class(TTestCase)
  published
    procedure TestSomething;
  end;

initialization
  {$IFDEF DUnitX}
  TDUnitX.RegisterTestFixture(...);
  {$ELSE}
  RegisterTests(...);
  {$ENDIF}
```

Assertions are overwhelmingly **DUnit-style** (`CheckEquals` ~1393, `CheckException` ~87, `CheckNotEquals` ~39). Native `Assert.*` is rare (~2× `Assert.Fail`).  
→ Migration phase 1 keeps `DUnitX.DUnitCompatibility` so bodies stay unchanged.

`DECDUnitXTestSuite.dpr` sets `runner.FailsOnNoAsserts := False` — empty tests would not fail. Leave as-is until parity is proven; consider enabling later as a quality gate.

### 0.4 Sense check: do the DUnit tests make sense?

#### Keep / meaningful (vast majority)

| Area | Unit(s) | Verdict |
|---|---|---|
| Base registry | `TestDECBaseClass` | Real class list / identity / short name tests |
| Formats | `TestDECFormat`, `TestDECFormatBase` | Encode/decode + registry; exception helpers for invalid names/ids |
| Hashes | `TestDECHash`, `TestDECHashSHA3`, `TestDECHashKDF`, `TestDECHashMAC` | Large vector suites; SHA3 uses NIST files under `Unit Tests/Data/`; HMAC/PBKDF2 incl. bug #46 regression |
| Ciphers | `TestDECCipher` | Per-algorithm fixtures + key/IV edge cases |
| Modes (classic) | `TestDECCipherModes` | ECBx, OFB8/x, CFB8/x, CFS8/x, CBCx, CTSx; also touches GCM/CCM for auth-API failure paths |
| GCM | `TestDECCipherModesGCM` | NIST-style vectors, auth failure, stream/chunk notes |
| CCM | `TestDECCipherModesCCM` | Dedicated CCM suite (must be on DUnitX) |
| Paddings | `TestDECCipherPaddings` | Positive/negative padding remove; dual Fail/Assert.Fail already |
| Formats API | `TestDECCipherFormats` | Bytes/stream/string encode-decode matrix |
| Util | `TestDECUtil` | Bit ops, protect buffer/stream/string, `IsEqual`, Shannon entropy |
| Random | `TestDECRandom` | **Deterministic** sequences with fixed seed — sensible regression, not “true RNG quality” (documented in unit header) |
| ZIP | `TestDECZIPHelper` | Class resolution + unknown algorithm exceptions |
| Infrastructure | `TestDECTestDataContainer`, `AuthenticatedCiphersCommonTestData` | Support, not empty “fake” suites |

#### Intentional “empty” code (not abandoned tests)

- `TestDECHash.pas`: stub overrides (`DoInit`/`DoDone`/`DoTransform` “Empty on purpose”) on **test doubles** (`TDECHashIncrement8`, abstract-error probes) — **OK**.
- Empty `SetUp`/`TearDown` where only class methods are tested — **OK**.

#### Weak or incomplete (document; fix only if cheap / separate commit)

| Issue | Where | Assessment |
|---|---|---|
| `Check(true)` after successful CCM IV init loop | `TestDECCipherModesCCM` | Only proves “no exception”; weak. Prefer no assert needed if exception is the failure mode, or assert mode/state. **Do not block migration.** |
| CCM large-stream tests commented out | `TestDECCipherModesCCM` | Incomplete vs GCM; track for AEAD work later, not DUnitX migration |
| GCM stream chunking TODOs / dead commented code | `TestDECCipherModesGCM` | Cleanup optional; behaviour tests still present |
| `TestDECCipherModes` uses mostly `TCipher_Null` + short strings | Mode wiring regression, not full AES-CBC NIST vectors | **Still useful** for mode dispatch; real crypto vectors live in cipher/GCM/CCM units |
| File encode/decode tests commented | `TestDECCipherFormats` | Optional future; not required for migration |
| SHA3 TODOs (naming / comments) | `TestDECHashSHA3` | Cosmetic / follow-up |
| Cipher TODOs (“Should be specified via FTestData?”) | `TestDECCipher` | Design debt; tests still assert |

**Overall:** The suite is **substantively meaningful** as a regression pack. No large blocks of skeleton tests that should be deleted before migration. Weak spots are known and secondary.

### 0.5 Comparison protocol (DUnit kept on purpose)

While both runners exist:

1. Build and run **DUnit** suite (`DECDUnitTestSuite`, console if possible) → save log / failure list.  
2. Build and run **DUnitX** suite (`DECDUnitXTestSuite`) → NUnit XML + console.  
3. **Parity rule:** same fixtures must pass on both; any DUnitX-only failure is a migration bug until proven otherwise.  
4. New tests added during/after migration go into shared units and must be registered for **both** runners until DUnit is retired.

---

## File map (what will change)

| Path | Action |
|---|---|
| `Unit Tests/Tests/TestDefines.inc` | Document dual use; keep `DUnitX` define for DUnitX builds |
| `Unit Tests/DECDUnitXTestSuite.dpr` | Add missing units; ensure include/define story is reliable |
| `Unit Tests/DECDUnitXTestSuite.dproj` | Mirror unit list / search paths / `DUnitX` define |
| `Unit Tests/DECDUnitTestSuite.dpr` / `.dproj` | **Keep**; only touch if registration/shared unit needs both |
| `Unit Tests/Tests/*.pas` | Ensure every fixture registers under both `IFDEF` branches; remove dead dual bugs only |
| `Docs/Cleanup-Roadmap.md` | Link to this plan; note “DUnit retained for comparison” |
| `readme.md` (optional later) | Mention both runners until DUnit removal |

---

## Task 1: Baseline both runners

**Files:** none (measurement only), or add `Docs/plans/dunitx-parity-log.md` if useful

- [ ] **Step 1: Confirm branch**

```bash
git branch --show-current
# expect: Cleanup_OM-DUnitX-migration
```

- [ ] **Step 2: Build DUnit suite (Win32 Debug preferred)**

Use project `Unit Tests/DECDUnitTestSuite.dproj` with Delphi MSBuild / IDE / `DelphiBuildDPROJ.ps1` if available in environment.

Expected: successful compile.

- [ ] **Step 3: Run DUnit suite**

Prefer console: define `CONSOLE_TESTRUNNER` if needed, or run GUI and export results.

Record: total tests, failures, errors, ignored.

- [ ] **Step 4: Build DUnitX suite as-is (before fixes)**

`Unit Tests/DECDUnitXTestSuite.dproj` — ensure `DUnitX` is defined in the project (dproj already has `DUnitX;DEBUG` etc.).  
Also ensure `TestDefines.inc` define is **on** for DUnitX builds (today default is **off** — see Task 2).

- [ ] **Step 5: Run DUnitX suite as-is**

Record baseline. Expect possible missing CCM/ZIP coverage even if green.

- [ ] **Step 6: Commit only if you added a parity log file; otherwise no commit**

---

## Task 2: Make `DUnitX` define reliable for the DUnitX project

**Problem:** `TestDefines.inc` has `{.$DEFINE DUnitX}` commented out. DUnitX dpr includes it, but dproj also defines `DUnitX`. Relying on both is confusing; DUnit must **not** define `DUnitX`.

**Files:**
- Modify: `Unit Tests/Tests/TestDefines.inc`
- Modify: `Unit Tests/DECDUnitXTestSuite.dpr` (comments)
- Verify: `Unit Tests/DECDUnitTestSuite.dproj` has **no** `DUnitX` in `DCC_Define`

- [ ] **Step 1: Document the switch in `TestDefines.inc`**

Keep default **off** so opening test units under the DUnit project still compiles as DUnit. Rely on **project-level** `DCC_Define=DUnitX` for the DUnitX project (already present in dproj). Update the comment to say:

```pascal
/// <summary>
///   When DUnitX is defined (typically via DECDUnitXTestSuite project options),
///   unit tests compile against DUnitX + DUnitCompatibility.
///   When undefined (DECDUnitTestSuite), classic DUnit TestFramework is used.
///   Do not enable the define here permanently — that would break the DUnit project.
/// </summary>
{.$DEFINE DUnitX}
```

- [ ] **Step 2: Verify DUnitX dproj defines `DUnitX` for all configs used**

Debug/Release (and GUI if present) must include `DUnitX` in `DCC_Define`.

- [ ] **Step 3: Verify DUnit dproj does not define `DUnitX`**

- [ ] **Step 4: Rebuild both projects**

Expected: both compile.

- [ ] **Step 5: Commit**

```bash
git add "Unit Tests/Tests/TestDefines.inc" "Unit Tests/DECDUnitXTestSuite.dpr"
git commit -m "Clarify DUnit vs DUnitX define ownership for dual-suite builds."
```

---

## Task 3: Close the DUnitX project gap (CCM, ZIP, shared data)

**Files:**
- Modify: `Unit Tests/DECDUnitXTestSuite.dpr`
- Modify: `Unit Tests/DECDUnitXTestSuite.dproj` (add units the IDE/MSBuild need)
- Verify: `TestDECCipherModesCCM.pas`, `TestDECZIPHelper.pas`, `AuthenticatedCiphersCommonTestData.pas` already have dual-stack `IFDEF` registration

- [ ] **Step 1: Add to `DECDUnitXTestSuite.dpr` uses clause** (order flexible; keep near related units):

```pascal
  TestDECCipherModesGCM in 'Tests\TestDECCipherModesGCM.pas',
  TestDECCipherModesCCM in 'Tests\TestDECCipherModesCCM.pas',
  TestDECCipherPaddings in 'Tests\TestDECCipherPaddings.pas',
  TestDECZIPHelper in 'Tests\TestDECZIPHelper.pas',
  AuthenticatedCiphersCommonTestData in 'Tests\AuthenticatedCiphersCommonTestData.pas';
```

(Adjust if some lines already exist — avoid duplicates.)

- [ ] **Step 2: Add the same units to `DECDUnitXTestSuite.dproj`**

Prefer IDE “add unit” or careful `DCCReference` entries matching existing style.

- [ ] **Step 3: Confirm CCM/ZIP units register fixtures under `{$IFDEF DUnitX}`**

Each should call `TDUnitX.RegisterTestFixture(...)` in `initialization`.

- [ ] **Step 4: Build + run DUnitX**

Expected: CCM and ZIP tests appear and run.

- [ ] **Step 5: Run DUnit again (sanity — should be unchanged)**

- [ ] **Step 6: Commit**

```bash
git add "Unit Tests/DECDUnitXTestSuite.dpr" "Unit Tests/DECDUnitXTestSuite.dproj"
git commit -m "Include CCM, ZIP helper, and AEAD test data in DUnitX suite."
```

---

## Task 4: Fixture registration audit (every unit dual-clean)

**Files:** all `Unit Tests/Tests/Test*.pas` with fixtures

- [ ] **Step 1: Inventory registration**

For each fixture unit, ensure:

| Branch | Required |
|---|---|
| `{$IFDEF DUnitX}` | `[TestFixture]` on classes + `TDUnitX.RegisterTestFixture` (or documented RTTI-only discovery — currently suite uses both `UseRTTI := True` **and** explicit register; keep explicit register for consistency) |
| `{$ELSE}` | `RegisterTest` / `RegisterTests` as today |

- [ ] **Step 2: Fix any unit that only registers one side**

Known OK from audit: most units already dual-register. Re-check after CCM/ZIP inclusion.

- [ ] **Step 3: `TestDECUtil` fixtures**

Methods are not all named `Test*` (e.g. `ReverseBits32`) but are `published` — DUnit picks them up; DUnitX via `TTestCase` compatibility should too. Run suite and confirm counts roughly match.

- [ ] **Step 4: Commit only if fixes were needed**

```bash
git commit -m "Fix dual-stack test registration gaps for DUnitX parity."
```

---

## Task 5: Parity run (pass/fail comparison)

**Files:** optional log under `Docs/plans/`

- [ ] **Step 1: Run full DUnit suite, capture output**

- [ ] **Step 2: Run full DUnitX suite, capture console + NUnit XML**

- [ ] **Step 3: Compare**

| Check | Criterion |
|---|---|
| Failures on DUnitX not on DUnit | **Blocker** — fix migration |
| Failures on both | Product/test bug — fix or document, not “DUnitX issue” |
| Tests only on one runner | **Blocker** — registration/project gap |
| Count mismatch | Investigate (`TestUtil` naming, ignored tests, RTTI double-registration) |

Watch for **double execution** if both RTTI and `RegisterTestFixture` register the same class twice under DUnitX. If duplicates appear, set `runner.UseRTTI := False` **or** remove redundant registration — pick one strategy suite-wide (prefer **explicit RegisterTestFixture + UseRTTI False** for predictability).

- [ ] **Step 4: Fix DUnitX runner if double-registration**

In `DECDUnitXTestSuite.dpr`:

```pascal
runner.UseRTTI := False; // fixtures registered explicitly in unit initialization
```

Re-run parity.

- [ ] **Step 5: Commit runner tweak + any registration fixes**

```bash
git commit -m "Stabilize DUnitX discovery to match DUnit fixture set."
```

---

## Task 6: Small sense-check cleanups (only if zero behaviour risk)

Do **not** expand scope. Optional in same branch if parity is green:

- [ ] Replace `Check(true)` in CCM IV success path with a real assertion or remove and rely on exception — **only** if still equivalent.
- [ ] Delete clearly dead commented stream tests **or** leave with a single `// Deferred: multi-call CCM streams (AEAD roadmap)` note — do not implement streams here.
- [ ] Ensure `TestDECCipherPaddings` does not need both `Fail` and `Assert.Fail` under the same `IFDEF` in a broken way (read both branches).

- [ ] **Commit only if something landed**

```bash
git commit -m "Minor test clarity fixes found during DUnitX parity review."
```

---

## Task 7: Documentation

**Files:**
- Modify: `Docs/Cleanup-Roadmap.md` (link + “DUnit retained for comparison”)
- This plan: mark tasks done as work proceeds
- Optional: short note in `readme.md` under “Has it been tested?”

- [ ] **Step 1: Update Cleanup-Roadmap section 2**

State explicitly:

- DUnitX is the target authoritative runner.
- DUnit suite remains until parity is trusted and a later PR removes it.
- Link to `Docs/plans/2026-07-22-dunitx-migration.md`.

- [ ] **Step 2: Commit**

```bash
git add Docs/Cleanup-Roadmap.md Docs/plans/2026-07-22-dunitx-migration.md
git commit -m "Document DUnitX migration plan and dual-suite comparison policy."
```

---

## Task 8: Done criteria for this branch (mergeable to `Cleanup_OM`)

Migration branch is **complete enough to merge** when:

1. DUnitX project includes **all** test units DUnit has (incl. CCM, ZIP, shared AEAD data).
2. Both suites **compile** on the supported Delphi version used in this environment.
3. Parity run: **no DUnitX-only failures**; fixture sets aligned (no missing suites).
4. DUnit project **still present and green** (comparison baseline).
5. Docs updated; no ChaCha/AEAD drive-by changes.
6. `DUnitX.DUnitCompatibility` may still be used — **OK** for this phase.

**Explicitly deferred (later PRs):**

- Remove `DECDUnitTestSuite` and all `{$ELSE}` DUnit branches.
- Replace `Check*` with native `Assert.*` and drop `DUnitCompatibility`.
- Enable `FailsOnNoAsserts := True`.
- Rework weak tests / implement CCM stream tests.
- Folder rename `Unit Tests` → `tests`.

---

## Suggested commit series (summary)

1. Clarify define ownership  
2. Add missing units to DUnitX project  
3. Registration / UseRTTI stabilization  
4. Optional minor test clarity  
5. Docs  

---

## References

| Item | Path / link |
|---|---|
| Roadmap | `Docs/Cleanup-Roadmap.md` |
| DUnit project | `Unit Tests/DECDUnitTestSuite.*` |
| DUnitX project | `Unit Tests/DECDUnitXTestSuite.*` |
| Define switch | `Unit Tests/Tests/TestDefines.inc` |
| NIST/GCM/SHA3 data | `Unit Tests/Data/` |
| Collector branch | `Cleanup_OM` |
| This feature branch | `Cleanup_OM-DUnitX-migration` |

---

*Plan written after full dual-suite inventory and sense-check of existing DUnit tests. DUnit retention for comparison is a binding constraint until a later removal PR.*
