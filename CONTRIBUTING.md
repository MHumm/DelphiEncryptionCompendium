# Contributing to DEC

We welcome contributions from the Delphi and FPC communities.

You can open a pull request with a clear description of the change, or contact the
main contact listed in `NOTICE.txt`.

## Coding style (required for new code)

**Single source of truth:** [`Docs/StyleGuide.md`](Docs/StyleGuide.md)

Please read it before writing or reviewing code. In short:

- **New and rewritten code** must follow the style guide (naming, headers, FPC/Delphi `uses`, docs, tests), including code that comes in through pull requests (“donor” code).
- **Existing sources** are not required to be mass-reformatted; do not mix drive-by style rewrites into feature PRs.
- Algorithm extension how-to (where to plug in a cipher, mode, hash, …) remains in **`Docs/DEC65.pdf` §3.7.2 and following**.

## Pull request basics

Details and the full checklist live in the style guide (§2 and §10). Essentials:

* Base your work on the **`development`** branch.
* Prefer **one focused topic** per PR (and one commit when practical).
* Describe **what** and **why**; code must **compile**.
* Add or update **unit tests** for functional changes (DUnitX is the preferred runner).
* New cipher / hash / format classes must **register** via `RegisterClass` like existing algorithms.

## Security issues

Do not open a public PR for unfixed vulnerabilities. Follow [`SECURITY.md`](SECURITY.md).
