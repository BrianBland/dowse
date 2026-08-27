# dowse-types

Shared data model for dowse. No logic — pure types with serde support.

## Key types

**`HintTable`** — the top-level structure. Keyed by `B256` code hash so all contracts
sharing the same bytecode share one set of hints. Lookup resolves
`address → code_hash → selector → [PrefetchItem]`, falling back to the wildcard
selector (`None`) when no exact match exists.

**`PrefetchItem`** — one thing to prefetch:
- `Scored { confidence, item }` — access probability for an item; unscored legacy items imply `1.0`
- `Storage { slot: SlotExpression }` — a storage slot on the current contract
- `Account { address, selector? }` — load account info; when selector is set, chain into that address's hint entry
- `ExternalStorage { address, slot }` — a storage slot on a known external contract
- `ComputedAccount { address: SlotExpression, selector? }` — account at a runtime-computed address (e.g. loaded via SLOAD)

**`SlotExpression`** — an expression tree describing how to derive a concrete `B256`
slot key from runtime context:
```
Concrete | CalldataWord | Caller | Keccak256 | Add | SLoad
```

**`HintScore`** — precision/recall metrics from hint table validation.

## Serde

JSON uses `"*"` for wildcard selectors and `"0xaabbccdd"` for specific ones.
The `selector` field on `Account` and `ComputedAccount` is omitted from JSON when
`None` (`skip_serializing_if`), so existing tables without it deserialize cleanly.
