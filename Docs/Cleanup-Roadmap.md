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

**Status (branch `Cleanup_OM-DUnitX-migration`, 2026-07-22):** migration work is **done for this phase**. DUnitX is the **target authoritative runner**. The classic **DUnit suite remains** until parity is trusted longer-term and a **later PR** removes it (not part of this migration).

| Phase | DUnit (`DECDUnitTestSuite`) | DUnitX (`DECDUnitXTestSuite`) |
|---|---|---|
| **Now (migration branch complete)** | Kept; comparison baseline | Complete unit list; parity-proven fail-set; preferred for new work |
| **Later (separate PR)** | Remove after explicit decision | Only runner; drop dual-stack / compatibility |

Detailed plan: **[`Docs/plans/2026-07-22-dunitx-migration.md`](plans/2026-07-22-dunitx-migration.md)**  
Parity log: **[`Docs/plans/dunitx-parity-log.md`](plans/dunitx-parity-log.md)**

### 2.1 Binding constraint: keep DUnit temporarily

The classic **DUnit suite stays** for the time being so we can **compare results** (same tests, both runners) and prove the migration did not drop or alter behaviour.

### 2.2 Achieved state after migration branch

| Item | Status |
|---|---|
| Classic DUnit project | `Unit Tests/DECDUnitTestSuite.*` — still builds/runs (comparison) |
| DUnitX project | **Full** unit list matching DUnit, including **CCM**, **ZIP**, AEAD common test data; DPR hardened (explicit registration, `UseRTTI := False`, exit codes, console mode) |
| Shared switch | `Unit Tests/Tests/TestDefines.inc` — `{.$DEFINE DUnitX}` **off by default**; DUnitX dproj supplies the define |
| Dual-stack tests | Fixtures register under both `{$IFDEF DUnitX}` and classic DUnit |
| Assert style | Still `Check*` via `DUnitX.DUnitCompatibility` (native `Assert.*` deferred) |
| **Fail-set parity** | Both suites: **12 shared failures** (Keccak digest vectors + GCM chunked stream tag — product/test debt, not migration). **0 DUnitX-only failures** |

### 2.3 Later target (after comparison period — not this branch)

| Item | Target |
|---|---|
| Framework | **DUnitX only** |
| DUnit project | Removed |
| Native asserts | `Assert.*`; drop `DUnitCompatibility` |
| Docs / CI | DUnitX only |
| Shared 12 failures | Fix as product/test work (Keccak / GCM), independent of runner choice |

Do **not** mix this migration with AEAD architecture or ChaCha feature work in the same PR.

---

## 3. Agreed overall work order

```
Cleanup_OM (and follow-up PRs → development)
│
├─ 0. Repo hygiene (started)
│     e.g. DelphiStandards .gitignore
│
├─ 1. DUnit → DUnitX migration                ← done on Cleanup_OM-DUnitX-migration
│     DUnitX complete + fail-set parity; DUnit retained for comparison
│     (single runner / remove DUnit = later PR)
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
| DUnitX migration plan | `Docs/plans/2026-07-22-dunitx-migration.md` |
| DUnit / DUnitX parity log | `Docs/plans/dunitx-parity-log.md` |
| Migration branch | `Cleanup_OM-DUnitX-migration` |

---

*Document created as part of cleanup planning on `Cleanup_OM`. Updated 2026-07-22 for completed DUnitX migration phase (DUnit still retained for comparison).*
