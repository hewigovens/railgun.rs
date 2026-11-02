# railgun.rs

A Rust core for a private Railgun wallet. `README.md` has the commands, `docs/architecture.md` the design, `scope.md` the plan and `HANDOFF.md` the current state and open items.

## Task Authority

- Investigation and code review are read-only unless fixes are requested.
- Implementation does not authorize push. Spending real funds, or sending anything to the aggregator or another service, needs a request that covers it.
- Keep mnemonics, keys and `.test-wallet/` contents out of source, logs, fixtures and reports.
- Report evidence as separate claims: build, focused tests, live integration, and measurements. Name the command behind each and list what was skipped.

## Principles

1. **Compatibility is the spec.** Bytes must match the TS engine and the live contract. Prefer a vector from the engine or a check against the chain over reasoning about it.
2. **Business logic stays in Rust crates.** Bindings convert types and expose core APIs; they add no logic.
3. **Behavior belongs to types.** Prefer inherent methods when the type is in the crate, and a focused trait otherwise.
4. **Comments explain the why.** Default to no comment. Comment only a non-obvious why, on a single line, which may run past 80 columns.
5. **Test behavior, essentials only.** Choose the smallest layer that proves a behavior. A bug fix adds the regression test that would have caught it. Do not keep tests that only mirror constants, static config or field-by-field wiring.

## Code Organization

- One primary type per file, named after the type. Private helpers stay with it, and a type plus its request and result vocabulary may share a file.
- Split by single responsibility, not line count.
- Keep `lib.rs` and `mod.rs` thin: module declarations and `pub use` re-exports only.
- Put `use` declarations at the top of the module, never inside a function.
- Use `pub(crate)` or `pub(super)`, never path-scoped `pub(in ...)`.
- A function over 120 lines fails `clippy::too_many_lines`; split it by responsibility unless it is a vector table.

Dependency direction, never inverted: `rg-primitives` → `rg-keys`, `rg-notes`, `rg-tree` → `rg-sync` → `rg-wallet` → `rg-tx` → `rg-core` → `rg-uniffi`. `rg-prover` knows nothing about Railgun, and `rg-poi` depends only on `rg-primitives` and `rg-tree`; `rg-core` joins them.

## UniFFI

`rg-uniffi` follows JayJay's layout: `uniffi::setup_scaffolding!()` in `lib.rs`, `src/types/` for records, `#[uniffi::remote(...)]` for records owned by core crates, `#[derive(uniffi::Object)]` wrappers around `rg-core` types, and a `uniffi-bindgen.rs` binary behind the `cli` feature. It adds no logic. `u128` does not cross the boundary, so amounts are decimal strings. Calls block, so shells run them off the UI thread. Run `just test-swift` and `just test-kotlin` when the surface changes. Error fields are `reason`, since `message` collides with Kotlin's `Throwable.message`.

## Version Control

This repo uses Jujutsu in a colocated checkout. Use `jj` for history, not `git commit` or `git push`.

- Do not add AI attribution to commits or PRs.
- `jj st`, `jj log` and `jj diff` snapshot the working copy, so serialize them. Use `jj --ignore-working-copy` for reads that must not snapshot.
- At the end of a task, `jj describe` the change.

## Before Finishing

Re-read the whole diff and run two cleanup rounds: delete what the change left dead, dedupe, and simplify. Stop when a round changes nothing, then re-run affected checks. Before publishing run `just lint` and `just test`.

```bash
just test-rust <crate> [filter]
just test
just test-proof <artifacts>
just test-swift
just test-kotlin
just lint
just format
```
