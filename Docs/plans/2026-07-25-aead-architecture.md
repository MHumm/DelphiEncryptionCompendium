# AEAD Architecture Package (from PR #90 Concern A)

**Branch:** `package/aead-architecture`  
**Base:** `development`  
**Donor:** [PR #90](https://github.com/MHumm/DelphiEncryptionCompendium/pull/90) (architecture only)  
**GCM streaming reference:** PR #99 multi-call GCM semantics (absorbed)

## Goal

Separate AEAD architecture from ChaCha/Poly1305 (Cleanup-Roadmap Concern A vs B).

## What landed

| Area | Decision |
|------|----------|
| Mode object | Single `FAuthObj: TAuthenticatedCipherModesBase` instead of dual `FGCM`/`FCCM` |
| Public API | `IDECAuthenticatedCipher` unchanged |
| Protected API | `EncodeGCM`/`DecodeGCM`/`EncodeCCM`/`DecodeCCM` kept as dispatch wrappers (no rename break) |
| GCM streaming | PR #99 engine: GHASH partial + CTR keystream remainder + `FFinalized` |
| Tag timing | Tag is valid only after `Done` (multi-call GHASH). Callers must `Done` before reading the tag |
| CCM | Still one-shot; base `Done` is a no-op for the CCM object; ExpectedTag still verified in `TDECCipherModes.Done` |
| Poly1305 / ChaCha | **Out of scope** (package B) |
| `cmPoly1305` enum | **Not** added in this package |

## What was rejected from PR #90 (as-is)

1. **`fIsLastBlock` CTR model** — treats any non-16-aligned *call* as end of message; breaks multi-chunk streams (e.g. 7+25).
2. **Missing keystream remainder** — wrong ciphertext after partial blocks.
3. **Abstract hooks with empty `inherited`** — EAbstractError risk on CCM stubs.
4. **Burn-on-finalize of only H** without post-Done lock — unsafe continued Encode after Done.
5. **Shipping Poly1305/ChaCha/CPU units** with the architecture package.

## Lifecycle (binding)

```
Init(Key, IV)
  → set DataToAuthenticate / AuthenticationResultBitLength / ExpectedAuthenticationResult
  → Encode* or Decode*  (multi-call OK for GCM; one-shot for CCM)
  → Done                 (finalizes GCM tag; verifies ExpectedTag if set)
  → read CalculatedAuthenticationResult
```

After `Done`, further GCM `Encode`/`Decode` raise until `Init` again. `Done` is idempotent for the tag.

## Files

| File | Role |
|------|------|
| `Source/DECAuthenticatedCipherModesBase.pas` | Shared AEAD base + virtual `Done` |
| `Source/DECCipherModes.pas` | `FAuthObj` wiring, leak-safe `InitMode`, unified `Done` |
| `Source/DECCipherModesGCM.pas` | Multi-call GCM (PR #99 semantics) |
| `Unit Tests/Tests/TestDECCipherModesGCM.pas` | Multi-chunk + Done lifecycle tests |
| `Unit Tests/Data/gcmEncryptExtIV256_large.rsp` | Corrected large-vector tag |

## Test results (Delphi 13, Win32 Console DUnit)

- GCM suite: **19/19** green (including multi-chunk 16+16, 7+25, Done lifecycle)
- CCM suite: **16/16** green
- Non-AEAD cipher modes: green
- Residual reds: pre-existing Keccak vector issues only (separate PRs #98/#100)

## Package B next

ChaCha20 / XChaCha20 / Poly1305 AEAD on top of this base (`FAuthObj` + `Done` contract).
