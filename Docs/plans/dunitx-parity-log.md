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

### Units in DUnit only (coverage gap)

| Unit | Approx. tests (from DUnit log) |
|---|---|
| `TestDECCipherModesCCM.pas` | 16 (`TestTDECCCM`) |
| `TestDECZIPHelper.pas` | 3 (`TestZIPHelpers`) |
| `AuthenticatedCiphersCommonTestData.pas` | support only (no fixture) |

All other test units are referenced by both projects.

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

---

## Parity rule (for later tasks)

- Same fixtures must pass on both runners.
- DUnitX-only failures (ISO10126×2, BCrypt IsPasswordHash) are **migration-priority** until proven environmental.
- Shared 12 failures are baseline noise; do not block adding CCM/ZIP to DUnitX, but re-check they remain the same set after registration fixes.
- After Task 3 (add missing units), expect DUnitX total ≥ DUnit total and CCM/ZIP green.
