# DEC Style Guide

**Single source of truth (SSOT)** for coding style, structure, and contribution shape in the Delphi Encryption Compendium (DEC).

| | |
|---|---|
| **Applies to** | All **new** units, and all **new or rewritten** code in pull requests |
| **Does not require** | Mass reformatting of existing sources to match this guide |
| **Language** | English for identifiers, comments, docs, and commit messages in this repository |
| **Companion docs** | [`CONTRIBUTING.md`](../CONTRIBUTING.md) (process) · [`SECURITY.md`](../SECURITY.md) · `Docs/DEC65.pdf` (API & how-to extend algorithms) |

If this file and any older note disagree (e.g. historical wording in `DEC65.pdf` §3.7.1), **this file wins**.

---

## 1. Scope and enforcement

1. **Existing code** may keep historical style. Do not drive-by reformat unrelated lines in a feature PR.
2. **New code** must follow this guide. This includes new units, new types, new methods, substantial rewrites, and code that comes in through pull requests (“donor” code). Reviewers should request fixes before merge.

   Example: when we later take ChaCha20/Poly1305 from PR #90, clean it up to match this guide (naming, structure, docs). Do not copy the donor style as-is.
3. Prefer matching a neighbouring routine in the same unit when the local historic style is still consistent *and* this guide is silent — but **naming, docs, headers, FPC/Delphi uses, and tests** always follow this guide for new work.
4. Submodules / third-party trees are out of scope.

---

## 2. Pull requests and extension rules

Moved here from the former short `CONTRIBUTING.md` / `DEC65.pdf` §3.7.1 list so process and style live in one place.

### 2.1 Pull requests

- Base the PR on **`development`** (newest integration branch).
- Prefer **one focused topic** per PR; split large topics. Discuss architecture-sized changes with maintainers **before** large implementation.
- Prefer **one commit** per PR when practical (or a clean, reviewable history).
- Describe **what** changed and **why**.
- Code must **compile** for the supported Delphi range (see readme / `DEC65.pdf` chapter 1).
- Be open to review feedback.

### 2.2 Extending DEC

- Any functional addition needs **unit tests** (authoritative runner: **DUnitX**; classic DUnit may still exist for comparison — see readme).
- New cipher / hash / format classes must call **`RegisterClass`** as existing units do, or demos and class lists will not pick them up.
- Do not use language features or units unavailable on the **minimum Delphi version** DEC claims to support.
- Algorithm-specific how-to (where to put a cipher, mode, padding, hash, …) remains in **`Docs/DEC65.pdf` §3.7.2 ff.** — that is API/structure guidance, not a second style guide.

---

## 3. Files, encoding, units

### 3.1 Unit header (required on new units)

Copy the Apache 2.0 block used in existing `Source/*.pas` files (reference `NOTICE.txt` / `LICENSE.txt`), then:

```pascal
unit DECSomething;
{$INCLUDE DECOptions.inc}

interface
```

### 3.2 Unit naming (library)

- Library units use the established **`DEC…` prefix** and flat names matching the file (`DECCipherModesGCM.pas` → `unit DECCipherModesGCM`).
- Do **not** introduce app-style hierarchical unit names (`Customer.Details.Form`) inside the DEC library tree.
- Demo/test projects may use clearer local names; still keep file name = unit name.

### 3.3 Uses clauses (Delphi + FPC)

```pascal
uses
  {$IFDEF FPC}
  SysUtils, Classes,
  {$ELSE}
  System.SysUtils, System.Classes,
  {$ENDIF}
  DECTypes, DECUtil;
```

| Rule | Detail |
|---|---|
| Delphi `interface` uses | Prefer **namespaced** RTL units (`System.SysUtils`, …) |
| FPC | Non-namespaced counterparts via `{$IFDEF FPC}` as above |
| `implementation` uses | **No** unit namespace prefixes (FPC) — same IFDEF pattern as existing units |
| Non-portable code | Wrap in `{$IFDEF}` so FPC (or unsupported platforms) do not see it. Turn project-specific defines (class registration, ASM, and similar) on or off in **`DECOptions.inc`**. That is the central place for such switches. |

### 3.4 Encoding and line endings

| Item | Guidance for **new** files |
|---|---|
| Character set | **UTF-8** |
| BOM | Match the dominant pattern of sibling units in the same folder; prefer **UTF-8 with BOM** when adding units that may contain non-ASCII in comments/strings |
| Line endings | **CRLF** for `.pas` / `.dpr` / `.inc` (Delphi-friendly). Repo `.gitattributes` may normalize on checkout — do not introduce mixed endings inside one file |
| DFM/FMX non-ASCII | Prefer `#<codepoint>` form when editing form text |

Do not re-encode entire historical units “for style” in unrelated PRs.

---

## 4. Formatting

Aligned with modern Delphi practice (and the [Delphi Style Guide EN](https://github.com/omonien/DelphiStandards/blob/master/Delphi%20Style%20Guide%20EN.md) where it does not conflict with DEC).

| Rule | Detail |
|---|---|
| Indentation | **2 spaces** per level; no tabs |
| Line length | Soft max **~120** characters; break long parameter lists and expressions readably |
| `begin` / `end` | On their **own** lines |
| Statements | One statement per line |
| Simple branches | Prefer `begin`/`end` even for a **single** statement. Bare `Exit` / `raise` / `Continue` / `Break` may stay without `begin`/`end`. |
| `with` | **Do not use** `with` |
| Comments | `//` line · `{ … }` block · `///` XML docs · `(* … *)` for temporarily disabled code |
| Compiler directives | `{$IFDEF …}` style, uppercase directives; nest carefully |

```pascal
procedure TExample.DoWork(const AValue: string);
begin
  if AValue = '' then
    raise EDECException.Create('Value required');

  if IsReady then
  begin
    Process(AValue);
  end;
end;
```

Always write `begin`/`end` around the `if` body, even when there is only one statement (`Process(AValue)` above). Several people maintain DEC, so clarity matters more than a short listing. A common late bug is to add a second line and forget `begin`/`end`; then only the first line is inside the `if`.

Bare `Exit`, `raise`, `Continue`, and `Break` may stay without `begin`/`end` (see the `raise` line above).

**Do not use `with`.** Prefer `FreeAndNil` over `.Free` when releasing owned objects. No empty `except` blocks unless a short comment explains a deliberate swallow (e.g. finalization / logging must not raise).

---

## 5. Naming

**PascalCase** for types, methods, and multi-word identifiers.

### 5.1 Types

| Kind | Prefix | Example |
|---|---|---|
| Class | `T` | `TCipher_AES`, `TDECHash` |
| Interface | `I` | `IDECHash` |
| Record | `T` | `TBlock16Byte` |
| Type alias | `T` (recommended) | `TIndex = Integer` |
| Exception | `E` | `EDECException`, `EDECCipherException` |
| Enum type | `T` | `TCipherMode` |
| Pointer to type | `P` | `PBlock16Byte` (when used) |

Cipher / hash algorithm classes keep DEC’s established patterns: `TCipher_…`, `THash_…`, `TFormat_…`.

Type aliases: prefer a `T` prefix (`TIndex = Integer`). This is a **recommendation**, not a must. Leave `T` off only when the alias is meant to look like a Delphi language or RTL name (for example string-style names where `T` would look odd).

### 5.2 Variables and parameters

| Scope | Prefix | Example |
|---|---|---|
| Local | `L` | `LKey`, `LBuffer` |
| Field | `F` | `FMode`, `FInitializationVector` |
| Parameter | `A` | `const AData: TBytes` |
| Global (avoid) | `G` | only unit-internal in `implementation` if unavoidable |
| Loop index | none | `i`, `j`, `k` allowed |

**Do not** use lowercase `f` / `l` field prefixes on new code (`fInp…` style is rejected in review).

**Public fields**

For **new** code, avoid public fields on **classes**. Use properties instead.

This is not a hard ban: older DEC classes may keep public fields until that type is rewritten.

If a type needs many public fields, prefer a **record**, or rethink the design. On records, public fields are the normal value layout (no `F` prefix).

### 5.3 Constants

| Kind | Prefix | Example |
|---|---|---|
| General | `c` | `cBlockSize` |
| String constant | `s` | `sInvalidNonce` |
| Resource string | `rs` | `rsErrorMessage` |
| System / build | `ALL_CAPS` | rare; prefer DEC existing patterns |

String constants use `s` plus the rest of the name, as existing DEC code already does (`sInvalidNonce`, `sHashNotInitialized`). Names like `sCipher…` are `s` + the word Cipher, not a special `sc` prefix.

### 5.4 Methods

- Procedures: verb phrases (`DoEncode`, `Init`, `RegisterClass`).
- Functions: `Get…` / `Is…` / `Can…` / domain verbs (`Calculate`, `EncodeBytes`) as in existing DEC APIs.
- Event properties: `On…`; protected raisers often `Do…`.

### 5.5 Enumerations (new types)

Prefer **scoped enums** for **new** enumerations:

```pascal
{$SCOPEDENUMS ON}
type
  TPoly1305CpuMode = (Pas, Avx);
{$SCOPEDENUMS OFF}

// use: TPoly1305CpuMode.Pas
```

Do not invent a second parallel prefix style (`pmPas`) on new scoped enums. Existing unscoped enums (`TCipherMode`, …) stay as they are until a dedicated, tested migration — **not** drive-by renames.

---

## 6. Documentation comments

Use XML doc comments (`///`) on **new public** API:

- Minimum: `<summary>` on public types, methods, and properties.
- Document **all** parameters with `<param>` (one for each parameter, even if the name seems obvious).
- Also add `<returns>`, `<exception>`, `<remarks>` where they help.

```pascal
/// <summary>
///   Initializes the cipher with a key and nonce/IV.
/// </summary>
/// <param name="AKey">
///   Symmetric key bytes; length must match Context.KeySize.
/// </param>
/// <param name="AInitVector">
///   Nonce or initialization vector (IV). Size depends on the cipher and mode.
/// </param>
procedure Init(const AKey: TBytes; const AInitVector: TBytes); overload;
```

Explain **what** and **why**, not trivial restatements of the identifier. Security-relevant limits (nonce size, counter wrap, max message length) belong in `<remarks>` or class summary.

---

## 7. Implementation practices (short)

| Topic | Guidance |
|---|---|
| Ownership | `try` / `finally` + `FreeAndNil` for owned instances |
| Collections | Prefer generics (`TArray<T>`, `TList<T>`, `TBytes`) over legacy untyped patterns for new code |
| Inline variables | Allowed where the minimum supported Delphi version permits; otherwise classic `var` section |
| Process-global state | Avoid `class var` for mode switches; prefer instance fields or explicit library init |
| Secrets | Clear sensitive buffers when the surrounding DEC type already does (`ProtectBuffer` / established patterns); do not log keys or tags |
| ASM / SIMD | Optional fast paths only after a pure Pascal path exists; must match Pascal results in tests; gate with existing `DECOptions.inc` / platform defines |
| Errors | Prefer existing `EDEC*` exception types; messages clear and stable enough for tests |

---

## 8. Tests

| Rule | Detail |
|---|---|
| Required | New algorithms and behavioural fixes need tests |
| Runner | Prefer **DUnitX** project (`Unit Tests/DECDUnitXTestSuite`) |
| Vectors | Prefer **specification / RFC / NIST / Wycheproof** sources; document origin in the test unit or data file header |
| Dual stack | If a shared test unit still supports classic DUnit via `TestDefines.inc`, keep the `{$IFDEF DUnitX}` registration pattern consistent with existing fixtures |
| Format of cipher vectors | Existing suite often uses `TFormat_ESCAPE` — follow neighbouring tests |

---

## 9. What not to do in “style” PRs

- Reformat whole units unrelated to the change.
- Rename public API only for naming purity (needs its own, deliberate PR and compatibility story).
- Mix large architecture rewrites with pure style fixes.
- Drop FPC guards or raise the minimum Delphi version without maintainer agreement.

---

## 10. Checklist for authors and reviewers (new code)

- [ ] Apache header + `{$INCLUDE DECOptions.inc}` on new units  
- [ ] Delphi/FPC `uses` IFDEFs correct; no namespaced units in `implementation`  
- [ ] Naming: `T`/`E`/`I` (type aliases: `T` recommended), `F`/`L`/`A`, string constants `s…`, no `f` fields  
- [ ] `///` docs on new public API, with `<param>` for **every** parameter  
- [ ] No `with`; `begin`/`end` even for a single statement (except bare `Exit`/`raise`/`Continue`/`Break`)  
- [ ] 2-space indent, readable line breaks  
- [ ] Unit tests with cited vectors  
- [ ] `RegisterClass` where required  
- [ ] Compiles on supported Delphi; FPC-impact considered  
- [ ] No unrelated reformatting  

---

## 11. Document history and sources

This guide consolidates and supersedes scattered notes:

| Former location | Disposition |
|---|---|
| `CONTRIBUTING.md` PR bullets | Process kept there as a short pointer; detail here (§2) |
| `Docs/DEC65.pdf` §3.7.1 “Structure and style” | Superseded by this file; §3.7.2+ remains the how-to for algorithms |
| De-facto style in `Source/*.pas` | Naming of ciphers/hashes/formats and header shape preserved |
| [Delphi Style Guide EN](https://github.com/omonien/DelphiStandards/blob/master/Delphi%20Style%20Guide%20EN.md) (Olaf Monien) | Formatting, prefixes, docs, and modern practices adapted for DEC |

When `DEC65.pdf` is next regenerated, §3.7.1 should be reduced to a short paragraph pointing at **`Docs/StyleGuide.md`**.

---

*Initial version for DEC · 2026-07-23 · docs-only; no source reformatting required by adopting this guide.*  
*Revised 2026-09-08 · PR #101 review: donor/PR wording, `begin`/`end`, `DECOptions.inc`, no `with`, type aliases, public fields, string constants `s…`, XML `<param>` for all parameters.*
