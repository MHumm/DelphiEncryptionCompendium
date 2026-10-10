# DUnit / DUnitX Parity Log

Baseline measurement for DUnit → DUnitX migration (Task 1).  
Branch: `Cleanup_OM-DUnitX-migration`  
Date: 2026-07-22  
Host: Delphi 13 Florence (BDS 37.0), Win32

## How to reproduce

1. Build library: `Source\DEC60.dproj` Config=Debug Platform=Win32, `/p:ProductVersion=37.0`
2. Build DUnit console: `Unit Tests\DECDUnitTestSuite.dproj` Config=**Console** Platform=Win32
3. Build DUnitX: `Unit Tests\DECDUnitXTestSuite.dproj` Config=**Debug** Platform=Win32  
   - On this machine DUnitX Win32 DCUs live under  
     `C:\Users\Public\Documents\Embarcadero\Studio\37.0\Bpl\Win32\Debug`  
     (not under `$(BDS)\lib\win32\…`). Pass them on the unit search path together with  
     `Compiled\DCU_IDE37.0_Win32_Debug` when building from MSBuild.
4. **CWD must be the EXE output directory** so relative data paths  
   `..\..\Unit Tests\Data\…` resolve to the repo’s `Unit Tests\Data\`.  
   Running from `Unit Tests\` resolves to `X:\Unit Tests\Data\` and fails massively.
5. DUnitX CLI: `DECDUnitXTestSuite.exe -exit:Continue -xml:<path>\dunitx-results.xml`

Logs (local, not committed): `.superpowers/sdd/baseline-logs/`

---

## Project inventory

| Project | Role | Config used | Output |
|---|---|---|---|
| `DECDUnitTestSuite` | Classic DUnit (keep for comparison) | Console (defines `CONSOLE_TESTRUNNER`) | `Compiled\BIN_IDE37.0_Win32_Console\` |
| `DECDUnitXTestSuite` | DUnitX console | Debug (defines `DUnitX;DEBUG`) | `Compiled\BIN_IDE37.0_Win32_Debug\` |
| `Tests\TestDefines.inc` | `{.$DEFINE DUnitX}` **off** by default | DUnitX project supplies define via dproj | — |

### Units coverage (updated Task 3+)

All test units are referenced by both projects, including:

| Unit | Role |
|---|---|
| `TestDECCipherModesCCM.pas` | CCM fixture (`TestTDECCCM`) — both runners |
| `TestDECZIPHelper.pas` | ZIP helpers (`TestZIPHelpers`) — both runners |
| `AuthenticatedCiphersCommonTestData.pas` | support only (no fixture) |

Task 1 gap (CCM + ZIP missing from DUnitX) is **closed**.

---

## Baseline results (2026-07-22)

### DUnit — Console / Win32

| Metric | Value |
|---|---|
| Run | **1425** |
| Failures | **12** |
| Errors | **0** |
| Ignored | (not reported separately) |
| Duration | ~1:15 |
| Exit code | 0 (DUnit TextTestRunner does not fail the process on test failures) |

### DUnitX — Debug / Win32 (as-is, before migration fixes)

| Metric | Value |
|---|---|
| Found | **1457** |
| Passed | **1442** |
| Failed | **15** |
| Errors | **0** |
| Ignored | **0** |
| Exit code | 1 (`EXIT_ERRORS` when not all passed) |

> Count gap (1457 vs 1425): DUnitX reports **more** cases despite missing CCM+ZIP (~19 tests). Likely RTTI discovery / registration differences under `runner.UseRTTI := True` plus dual-stack registration. Not investigated further in Task 1.

---

## Failure lists

### Shared failures (same assertion intent on both runners) — 12

| # | Fixture / test | Notes |
|---|---|---|
| 1–7 | `TestTHash_Keccak_224` — `TestCalcStream`, `TestCalcStreamRawByteString`, `TestCalcStreamNoDone`, `TestCalcStreamNoDoneMulti`, `TestCalcBuffer`, `TestCalcBytes`, `TestCalcRawByteString` | Index 1 digest mismatch |
| 8 | `TestTHash_Keccak_224.TestCalcUnicodeString` | Index 1 empty expected vs non-empty |
| 9 | `TestTHash_Keccak_256.TestCalcUnicodeString` | Index 4 mismatch (input `<02>`) |
| 10 | `TestTHash_Keccak_384.TestCalcUnicodeString` | Index 4 mismatch |
| 11 | `TestTHash_Keccak_512.TestCalcUnicodeString` | Index 4 mismatch |
| 12 | `TestTDECGCM.TestEncodeStreamChunked` | Auth tag mismatch (Set 105) |

These are **pre-existing product/test issues**, not migration bugs. Track separately from DUnitX parity work.

### DUnitX-only failures — 3

| # | Fixture / test | DUnit result | Notes |
|---|---|---|---|
| 13 | `TestTISO10126Padding.TestAddPadding_RawByteString` | **Pass** (22 patterns) | ISO 10126 uses random pad bytes; possible non-determinism or DUnitX compatibility assert difference |
| 14 | `TestTISO10126Padding.TestAddPadding_Bytes` | **Pass** (22 patterns) | Same as above |
| 15 | `TestTHash_BCrypt.TestIsPasswordHash` | **Pass** | Expected `False`, got `True` under DUnitX only — investigate in migration |

### DUnit-only coverage (not run on DUnitX yet)

All **16** CCM + **3** ZIP tests **passed** on DUnit in this baseline. They are absent from `DECDUnitXTestSuite.dpr` (Task 3+).

---

## Build notes / environment quirks

1. **No** `build-scripts/DelphiBuildDPROJ.ps1` in this repo; used `rsvars.bat` + `msbuild` (Studio 37.0).
2. Library must be built first so `Compiled\DCU_IDE37.0_Win32_Debug` exists (test dproj search path points there, not at `Source\`).
3. DUnitX first compile without extra path: `F2613 Unit 'DUnitX.Loggers.Console' not found`. Fixed by adding Bpl Win32 Debug DCU dir.
4. Overriding only `DCC_UnitSearchPath` on the MSBuild command line **replaces** the dproj’s DEC DCU path — include **both** DEC DCU and DUnitX DCU paths.
5. `TestDefines.inc` still has `{.$DEFINE DUnitX}` commented; project define `DUnitX` in dproj is what enables the dual-stack branch for DUnitX builds today (Task 2 will harden this).
6. **Shared DCU dir:** both test projects write fixture DCUs to `Compiled\DCU_IDE37.0_Win32__Demos`. When switching DUnitX → DUnit, delete `Test*.dcu` (and `AuthenticatedCiphers*.dcu`) from that folder first, or the DUnit build fails looking for `DUnitX.Attributes`.
7. **Run CWD:** always the EXE output directory so `..\..\Unit Tests\Data\…` resolves correctly.

---

## Task 5 parity run (2026-07-22) — pass/fail comparison

Rebuilt and re-ran both suites on `Cleanup_OM-DUnitX-migration` after Task 4 dual-registration fixes.  
`runner.UseRTTI := False`; fixtures registered only via `TDUnitX.RegisterTestFixture` in unit `initialization`.

Local logs: `.superpowers/sdd/baseline-logs/task5-dunit-run.txt`, `task5-dunitx-run.txt`, `task5-dunitx-nunit.xml`.

### Counts

| Suite | Config | Found/Run | Passed | Failed | Errors | Exit |
|---|---|---:|---:|---:|---:|---:|
| **DUnit** Task 5 | Console Win32 | **1436** | 1424 | **12** | 0 | 0 |
| **DUnitX** Task 5 | Debug Win32 | **1476** | **1461** | **15** | 0 | 1 |
| DUnit Task 1 baseline | Console Win32 | 1425 | — | 12 | 0 | — |
| DUnitX Task 1 baseline | Debug Win32 | 1457 | 1442 | 15 | 0 | 1 |

NUnit XML: `total=1476 failures=15 errors=0` (matches console summary).

Coverage: CCM + ZIP present on **both** runners (gap from Task 1 closed in Task 3). No unit-level “tests only on one runner” blocker.

### Count gap (1476 − 1436 = **40**) — explained

Not fixture double-registration (UseRTTI is False; NUnit shows **122** unique fixtures).

DUnitX discovers **redeclared published methods** twice when a descendant re-publishes a base `published` method (base RTTI entry + override entry). Classic DUnit `.Suite` registers each method name once.

| Pattern | Extra cases | Example |
|---|---:|---|
| Hash leaf redeclares `TestIsPasswordHash` (base `THash_TestBase` already has it) | 38 | `TestTHash_MD2` … `TestTHash_Shake256` |
| `TestTISO10126Padding` overrides `TestAddPadding_*` | 2 | `TestAddPadding_RawByteString`, `TestAddPadding_Bytes` |
| **Total extras** | **40** | 1476 = 1436 + 40 |

Confirmed in NUnit XML: same fixture path lists the same `test-case` name twice (often one Success + one Failure when base vs override assertions differ).

### Failure classification

#### Shared failures (both runners) — **12** — product/test baseline, not migration

| # | Fixture / test | Notes |
|---|---|---|
| 1–7 | `TestTHash_Keccak_224` — `TestCalcStream`, `TestCalcStreamRawByteString`, `TestCalcStreamNoDone`, `TestCalcStreamNoDoneMulti`, `TestCalcBuffer`, `TestCalcBytes`, `TestCalcRawByteString` | Index 1 digest mismatch |
| 8 | `TestTHash_Keccak_224.TestCalcUnicodeString` | Index 1 empty expected vs non-empty |
| 9 | `TestTHash_Keccak_256.TestCalcUnicodeString` | Index 4 (`Input: <02>`) |
| 10 | `TestTHash_Keccak_384.TestCalcUnicodeString` | Index 4 |
| 11 | `TestTHash_Keccak_512.TestCalcUnicodeString` | Index 4 |
| 12 | `TestTDECGCM.TestEncodeStreamChunked` | Auth tag mismatch Set 105 |

#### DUnitX-only failures — **3** — method double-discovery (not product crypto)

| # | Fixture / test | DUnit | Cause |
|---|---|---|---|
| 13 | `TestTISO10126Padding.TestAddPadding_RawByteString` | Pass | DUnitX also invokes **base** `TestTPaddingBase` implementation (exact byte compare); random pad bytes fail. Override with `RemoveRandomPadding` still **passes**. |
| 14 | `TestTISO10126Padding.TestAddPadding_Bytes` | Pass | Same as above |
| 15 | `TestTHash_BCrypt.TestIsPasswordHash` | Pass | DUnitX also invokes **base** `THash_TestBase.TestIsPasswordHash` (`CheckEquals(false, …)`). Override expecting `True` still **passes**. |

These three are **migration / DUnitX discovery issues**, not random flakiness and not missing registration. They are **blockers for strict pass-set parity** until the published override pattern is adjusted (e.g. stop re-publishing inherited tests; use a single published method per name; or attribute-only `[Test]` on leaves).

#### DUnit-only failures — **0**

No failures that appear only on DUnit.

### Runner / registration status

| Check | Result |
|---|---|
| `runner.UseRTTI` | **False** (explicit fixtures only) — no change needed in Task 5 |
| RTTI + RegisterTestFixture double fixture set | **Not observed** |
| Redeclared published method double execution | **Yes — 40 cases** (see above) |
| Units missing from one project | **None** (CCM/ZIP dual-listed) |

No runner source tweak was required in Task 5.

---

## Parity rule (updated Task 5)

- Same fixtures must be registered on both runners (done Tasks 3–4).
- **Shared** failures = product/test debt; do not treat as DUnitX migration defects.
- **DUnitX-only** failures today are the ISO10126×2 + BCrypt `TestIsPasswordHash` trio, explained by redeclared published methods. Fix that discovery pattern before calling pass/fail parity complete.
- Count: expect DUnitX ≥ DUnit; residual +40 is the redeclared-method effect, not missing tests.
- Keep cleaning shared `__Demos` test DCUs when alternating runners.

---

## Task 6 run (2026-07-22) — DUnitX-only failures fixed

After non-published virtual hooks for ISO10126 padding compare and BCrypt `ExpectedIsPasswordHash` (see Task 6 report):

| Suite | Found/Run | Failed | DUnitX-only fails |
|---|---:|---:|---:|
| DUnit Console | 1436 | **12** | — |
| DUnitX Debug | **1473** | **12** | **0** |

Fail-sets match (12 shared Keccak/GCM). Count gap 37 = remaining redundant hash-leaf `TestIsPasswordHash` redeclares (no longer fail).

### Decision: leave remaining hash-leaf redeclares as-is

**Accepted (2026-07-22):** Do **not** remove the ~37 non-password hash leaf
`TestIsPasswordHash` redeclares. They only inflate the DUnitX case count
(base RTTI + leaf re-publish); both invocations pass with the same meaning as
the base (`IsPasswordHash = False`). Fail-set parity is already achieved; no
product or migration defect remains. Optional hygiene only — explicitly out of
scope unless someone wants exact count parity later.
