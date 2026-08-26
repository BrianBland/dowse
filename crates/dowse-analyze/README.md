# dowse-analyze

Produces `HintTable` entries from bytecode or recorded traces.

## Bytecode analysis (`bytecode` module)

`analyze_bytecode(bytecode: &[u8]) -> Vec<AnalyzedSelector>` runs a symbolic EVM
interpreter over raw bytecode and returns per-selector hint items.

**Approach:**

1. Scan for `JUMPDEST` positions and the selector dispatch table (the `CALLDATALOAD` /
   `SHR 0xe0` / `EQ` / `JUMPI` chain at the function dispatcher).
2. For each discovered selector, run symbolic execution from its entry point.
3. Also run from PC 0 to capture wildcard/fallback behavior.
4. Collect `SLOAD` slot expressions → `PrefetchItem::Storage`.
5. Collect `CALL`/`STATICCALL`/`DELEGATECALL` targets:
   - Concrete addresses → `PrefetchItem::Account { address, selector }`.
   - Symbolic addresses (e.g. loaded via SLOAD) → `PrefetchItem::ComputedAccount { address: SlotExpression, selector }`.

**Branch budget:** Each `JUMPI` explores both paths. Forward branches (guards, if-else)
get the full remaining budget. Backward branches (loops) get `budget / 4`. Maximum
branch depth is 32; a visited `(pc, stack_fingerprint)` set prevents revisiting the
same state.

**Opcode constants** come from `revm::bytecode::opcode`.

`analyzed_to_entries` converts the result into `(Selector, Vec<PrefetchItem>)` pairs
ready for insertion into a `HintTable`.

## Trace inference (`trace` module)

`infer_from_traces(traces: &[TraceRecord]) -> HintTable` builds hints from recorded
execution data. `infer_from_traces_with_threshold` allows trading additional concrete-slot
coverage for speculative reads. This is useful when bytecode analysis alone doesn't capture
all accessed slots (e.g. behind complex dispatch logic).

Algorithm per `(address, selector)` group:
1. **Fixed slots** — slots appearing in ≥80% of traces → `Concrete` items.
2. **Mapping slots** — tries `keccak256(calldata[offset..offset+32], base_slot)` for
   offsets 4/36/68 and base slots 0–9. If ≥50% of traces match, emits a `Keccak256`
   expression.
3. **Caller mappings** — when traces include the transaction sender, tries
   `keccak256(caller, base_slot)` for base slots 0–9.
