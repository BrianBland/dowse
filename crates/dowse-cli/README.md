# dowse-cli

The `dowse` binary. See the top-level [README](../../README.md) for full CLI reference.

## Subcommands

| Command | Description |
|---|---|
| `generate` | Analyze bytecode and emit a hint table |
| `infer` | Infer a hint table from recorded execution traces |
| `inspect` | Pretty-print a hint table with summary stats |
| `validate` | Score hints against recorded traces |
| `merge` | Merge multiple JSON hint tables |
| `convert` | Convert between JSON and binary formats |

## Output formats

- **human** — ANSI-colored text, items sorted by type (Storage → Account → ComputedAccount)
- **json** — Pretty-printed JSON; wildcard selectors serialize as `"*"`
- **binary** — Compact binary; see format.rs for tag layout

## Binary format tags

**Items:** `0x01` Account, `0x02` Storage, `0x03` ComputedAccount, `0x04` Account+selector, `0x05` ComputedAccount+selector, `0x06` ExternalStorage, `0x07` Scored

**SlotExpression:** `0x01` Concrete, `0x02` CalldataWord, `0x03` Caller, `0x04` Keccak256, `0x05` Add, `0x06` SLoad
