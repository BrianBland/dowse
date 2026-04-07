# dowse-core

Runtime components: prefetch inspector, recording inspector, proxy detection,
hint table trimming, and scoring.

## `PrefetchInspector`

Integrates with [revm](https://github.com/bluealloy/revm) via the `Inspector` trait.
On each `call`:

1. Looks up `(bytecode_address, selector)` in the hint table (wildcard fallback).
2. Resolves each `SlotExpression` against the actual calldata and `msg.sender`.
3. Calls `db.storage()` / `db.basic()` to warm the database cache in the background.
4. For `Account { selector }` and `ComputedAccount { selector }` items, chains into
   that address's hint entry and prefetches its `Storage` items (e.g. `balanceOf`
   mapping slots on the token contract). Only `Storage` items are chained to prevent
   infinite recursion.

Prefetching is gas-neutral — it warms the underlying DB cache but does not create
journal entries or mark slots as warm in the EVM.

## `RecordingInspector`

Records actual state accesses during EVM execution for validation and trace inference.
Hooks `SLOAD`, `BALANCE`, `EXTCODESIZE`, `EXTCODECOPY`, `EXTCODEHASH` opcodes via
`Inspector::step`. Returns a list of `(CallKey, Vec<RecordedAccess>)` per call frame.

## `detect_proxy`

Sync, provider-agnostic proxy detection. Accepts a `read_storage` closure and checks:
- EIP-1967 implementation slot
- OpenZeppelin legacy slot
- EIP-1967 beacon → beacon's implementation slot

The async wrapper in `dowse-cli` calls this using an `alloy-provider`.

## `trim_hint_table`

Removes low-value entries before shipping hints to production. An entry is kept if it
has at least `min_dynamic_items` items that depend on runtime inputs (calldata, caller,
SLOAD). `Account` items are always kept regardless of the threshold.

## `score_hints`

Compares hint table predictions against `RecordedAccess` data. Returns a `HintScore`
with hits, misses, and uncovered counts, from which precision and recall are derived.

## `resolve_slot`

Evaluates a `SlotExpression` tree against a `ResolutionContext` (calldata + caller).
Returns `None` for expressions that contain unresolvable `SLoad` nodes at prefetch
time.
