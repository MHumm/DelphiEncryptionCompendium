# DEC Cleanup Roadmap

Working branch: **`Cleanup_OM`** (PRs against **`development`**).

This document records agreed technical decisions and the planned order of work.
It is intentionally a planning artefact, not a design for individual pull requests.

---

## 1. Context: PR #90 (ChaCha20-Poly1305)

Open contribution: [PR #90](https://github.com/MHumm/DelphiEncryptionCompendium/pull/90)
(`mikerabat` → base branch `development_chacha20poly1305`).

The PR currently mixes **two independent concerns**:

| Concern | What it contains | Risk if merged as-is |
|---|---|---|
| **A. Architecture / AEAD base rewrite** | Slimmer `TAuthenticatedCipherModesBase` lifecycle (`InitAuth`, `UpdateWithEncDecBuf`, `FinalizeMAC` / `FinalizeAEAD`, multi-call encode/decode); large GCM rewrite for stream/chunk support (#87); shared wiring for authenticated modes | Touches core cipher-mode contracts; can break GCM/CCM and existing tests; needs careful review |
| **B. ChaCha features** | `TCipher_ChaCha20`, `TCipher_XChaCha20`, Poly1305 mode (`cmPoly1305`, `DECCipherModesPoly1305`), CPU feature detection, SSE/AVX paths, AES-NI, Wycheproof/RFC tests | Large feature surface, but can be evaluated as an algorithm addition **once** the base API is stable |

Related extras in the same PR (also not “pure ChaCha”): AES-NI assembler, `DECCPUSupport`, `DECOptions.inc` ASM define changes, 64-bit util/ASM fixes.

### Decision (binding)

**The architecture rework must be completely separated from the ChaCha feature work.**

Consequences:

1. **Do not** merge PR #90 as a single unit.
2. Split (or re-land) into at least:
   - **PR / package 1 — AEAD architecture:** base class + GCM multi-call/stream behaviour (+ only the minimum CCM adaptations required for the new interface). No ChaCha/XChaCha/Poly1305 algorithm code.
   - **PR / package 2 — ChaCha20 / XChaCha20 / Poly1305 AEAD:** algorithms, mode wiring, SIMD options, dedicated tests — built **on top of** the settled architecture from package 1.
3. Optional further splits (if review load requires it): AES-NI, CPU support, options/ASM fixes as separate changes.
4. Until that split exists, treat PR #90 as a **reference implementation / donor branch**, not as the integration path.

Rationale: architecture changes redefine how authenticated modes work for the whole library. Reviewing them together with a new cipher family makes regressions harder to attribute and forces an all-or-nothing review of ~8k LOC.

---

## 2. Prerequisite: DUnit → DUnitX migration (DUnit kept for comparison)

**Before** tackling the AEAD architecture split (and before large cipher-mode refactors), DUnitX must become a **complete, parity-proven** runner for the whole suite.

### 2.1 Binding constraint: keep DUnit temporarily

The classic **DUnit suite stays** for the time being so we can **compare results** (same tests, both runners) and prove the migration did not drop or alter behaviour.

| Phase | DUnit (`DECDUnitTestSuite`) | DUnitX (`DECDUnitXTestSuite`) |
|---|---|---|
| **Now / migration branch** | Keep; baseline for comparison | Bring to full parity; make authoritative for new work |
| **Later (separate PR)** | Remove after explicit decision | Only runner; drop dual-stack / compatibility |

Detailed plan: **[`Docs/plans/2026-07-22-dunitx-migration.md`](plans/2026-07-22-dunitx-migration.md)**  
Branch: `Cleanup_OM-DUnitX-migration`

### 2.2 Current state (as of `development` / start of cleanup)

| Item | Status |
|---|---|
| Classic DUnit project | `Unit Tests/DECDUnitTestSuite.dpr` (+ `.dproj`) — uses `TestFramework` |
| DUnitX project | `Unit Tests/DECDUnitXTestSuite.dpr` (+ `.dproj`) — **incomplete** vs DUnit (missing CCM, ZIP helper, AEAD common test data) |
| Shared switch | `Unit Tests/Tests/TestDefines.inc` — `{.$DEFINE DUnitX}` (**off by default**); DUnitX dproj supplies define |
| Dual-stack tests | Most units use `{$IFDEF DUnitX}` + `DUnitX.DUnitCompatibility` vs classic `TestFramework` |
| Sense check | Existing tests are largely **meaningful** (vectors, regressions); weak spots documented in the plan, not migration blockers |

### 2.3 Target state after migration branch (DUnit still present)

| Item | Target |
|---|---|
| DUnitX project | **Full** unit list matching DUnit |
| Parity | No DUnitX-only failures; fixture sets aligned |
| DUnit project | Still builds and runs (comparison) |
| Assert style | May still use `Check*` via `DUnitCompatibility` |
| Dual `IFDEF` | Still allowed |

### 2.4 Later target (after comparison period — not this branch)

| Item | Target |
|---|---|
| Framework | **DUnitX only** |
| DUnit project | Removed |
| Native asserts | `Assert.*`; drop `DUnitCompatibility` |
| Docs / CI | DUnitX only |

Do **not** mix this migration with AEAD architecture or ChaCha feature work in the same PR.

---

## 3. Agreed overall work order

```
Cleanup_OM (and follow-up PRs → development)
│
├─ 0. Repo hygiene (started)
│     e.g. DelphiStandards .gitignore
│
├─ 1. DUnit → DUnitX migration (complete)     ← next major technical step
│     Single test runner, no dual-stack
│
├─ 2. AEAD architecture split (from PR #90 concern A)
│     Base + GCM stream/multi-call only; review as core API change
│
├─ 3. ChaCha / XChaCha / Poly1305 (from PR #90 concern B)
│     On top of settled AEAD base; algorithms + tests
│
└─ 4. Optional: AES-NI / CPU support / options fixes
      As separate reviewable packages if not absorbed earlier
```

### Why this order

1. **Tests first:** architecture and cipher merges need a single, trustworthy automated suite. Dual DUnit/DUnitX weakens that signal.
2. **Architecture before features:** ChaCha-as-AEAD depends on (or must not re-introduce) the multi-call authenticated-mode model; shipping ChaCha on the old GCM-only shape and then rewriting the base again is wasted motion.
3. **Separation of review:** maintainers can accept/reject AEAD API changes without blocking or rubber-stamping a large SIMD cipher contribution.

---

## 4. Out of scope for this document

- Detailed AEAD class design (belongs in a design note when step 2 starts).
- Accept/reject decision on individual PR #90 commits.
- Delphi style / layout alignment with external house standards beyond what is already done (e.g. `.gitignore`).
- FPC/Lazarus policy (may interact with ASM defines from the donor PR; track separately).

---

## 5. References

| Item | Location |
|---|---|
| Working branch | `Cleanup_OM` |
| Integration target | `development` |
| Donor PR | https://github.com/MHumm/DelphiEncryptionCompendium/pull/90 |
| Donor branch (origin target) | `development_chacha20poly1305` |
| Donor head (implementation) | `mikerabat/DelphiEncryptionCompendium` branch `development` |
| DUnit project | `Unit Tests/DECDUnitTestSuite.*` |
| DUnitX project | `Unit Tests/DECDUnitXTestSuite.*` |
| Dual-stack switch | `Unit Tests/Tests/TestDefines.inc` |

---

*Document created as part of cleanup planning on `Cleanup_OM`. Update this file when a step completes or a decision changes.*
