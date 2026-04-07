# dowse

EVM state prefetching hint tables — predict which storage slots a contract will touch
before execution starts, so they can be warmed in parallel.

## How it works

When an EVM node receives a transaction, the state reads it needs are unknown until
execution begins. Each cold SLOAD costs 2,100 gas and may stall a sequential pipeline.

Dowse analyzes contract bytecode (via symbolic execution) or recorded traces to produce
a **hint table**: a mapping of `(code_hash, selector) → [PrefetchItem]`. At block
execution time, a prefetch inspector fires on each call, resolves the hint items using
actual calldata and caller, and warms the database cache in parallel.

```
analyze bytecode ──→ HintTable ──→ PrefetchInspector ──→ warm DB cache
                        (JSON / binary)                    before EVM accesses
```

## Crates

| Crate | Purpose |
|---|---|
| `dowse-types` | `HintTable`, `PrefetchItem`, `SlotExpression` — the shared data model |
| `dowse-analyze` | Symbolic EVM + trace inference → produces `HintTable` entries |
| `dowse-core` | Runtime components: `PrefetchInspector`, `RecordingInspector`, proxy detection, trimming, scoring |
| `dowse-cli` | `dowse` binary — generate, inspect, validate, merge, convert |

## Quick start

```bash
cargo build --release

# Generate hints for a contract on Base
dowse generate \
  --address 0x2fE5ea20d6a4D9488368012611F04C2c1E928629 \
  --rpc-url https://mainnet.base.org

# Recursively follow Account targets (e.g. routers → tokens)
dowse generate \
  --address 0xabc... \
  --rpc-url https://mainnet.base.org \
  --recursive --depth 2 \
  --format json --output hints.json

# Inspect a saved hint table
dowse inspect --hints hints.json

# Validate hints against recorded traces
dowse validate --hints hints.json --traces traces.json

# Merge multiple hint tables
dowse merge hints-a.json hints-b.json --output merged.json

# Convert formats
dowse convert --input hints.json --from json --to binary --output hints.bin
```

## CLI reference

### `generate`

Fetches bytecode (or accepts hex directly) and runs symbolic analysis.

```
dowse generate [OPTIONS]

Options:
  --address <ADDR>     Contract address to fetch (requires --rpc-url)
  --bytecode <HEX>     Hex-encoded bytecode, or path to a file containing hex
  --rpc-url <URL>      RPC endpoint (or set RPC_URL / BASE_RPC_URL env)
  --no-proxy           Skip proxy detection
  --recursive          Follow Account targets and analyze their bytecode too
  --depth <N>          Max recursion depth for --recursive [default: 2]
  --format <FMT>       Output format: human | json | binary [default: human]
  --output <FILE>      Write to file instead of stdout
```

Proxy detection runs automatically unless `--no-proxy` is passed. EIP-1967,
OpenZeppelin legacy, and beacon proxy patterns are recognized. Proxy bytecode is
analyzed alongside the implementation so that proxy-level SLOADs (e.g. loading the
implementation address) are captured.

### `inspect`

Pretty-print a hint table with summary statistics.

```
dowse inspect --hints <FILE> [--format human|json|binary]
```

### `validate`

Score a hint table against recorded execution traces. Traces must be a JSON array of
`TraceRecord` objects (see `dowse-analyze/src/trace.rs`).

```
dowse validate --hints <FILE> --traces <FILE>
```

Prints precision (fraction of predicted accesses that were used) and recall (fraction
of actual accesses that were predicted).

### `merge`

Merge two or more JSON hint tables. Later entries override earlier ones on conflict.

```
dowse merge a.json b.json ... [--output FILE]
```

### `convert`

Convert between JSON and binary formats.

```
dowse convert --input FILE --from json --to binary [--output FILE]
```

## Hint table format

### JSON

```jsonc
{
  "version": 1,
  "metadata": { "source": "bytecode-analysis", "description": "..." },
  "entries": {
    "0x<code_hash>": {
      "*": [ ... ],                  // wildcard: any call
      "0x70a08231": [ ... ]          // selector-specific
    }
  },
  "code_hashes": {
    "0x<address>": "0x<code_hash>"  // address → code hash registry
  }
}
```

### PrefetchItem types

```jsonc
// Load a storage slot (resolved from calldata/caller at runtime)
{ "kind": "Storage", "slot": <SlotExpression> }

// Load account info for a known address; optionally chain into its hints
{ "kind": "Account", "address": "0x...", "selector": "0x70a08231" }

// Load account info for an address computed from storage at runtime
{ "kind": "ComputedAccount", "address": <SlotExpression>, "selector": "0x70a08231" }
```

### SlotExpression types

| Type | Meaning |
|---|---|
| `Concrete { value }` | A fixed slot number |
| `CalldataWord { offset }` | 32 bytes of calldata at `offset` (offset 4 = first ABI arg) |
| `Caller` | `msg.sender` |
| `Keccak256 { inputs }` | `keccak256(concat(inputs))` — standard mapping slot |
| `Add { left, right }` | Arithmetic addition (packed structs, ERC-1155 offsets) |
| `SLoad { key }` | Value of a storage slot — for token addresses loaded from storage |

### Binary format

Compact encoding for hot paths. Each entry: `[32B code_hash][4B selector][1B count][items...]`.

Item tags: `0x01` Account, `0x02` Storage, `0x03` ComputedAccount, `0x04` Account+selector, `0x05` ComputedAccount+selector.

SlotExpression tags: `0x01` Concrete, `0x02` CalldataWord, `0x03` Caller, `0x04` Keccak256, `0x05` Add, `0x06` SLoad.

## Prefetch inspector

`PrefetchInspector` integrates with [revm](https://github.com/bluealloy/revm) via the
`Inspector` trait. On each `call`, it:

1. Looks up `(address, selector)` in the hint table (falls back to wildcard).
2. Resolves each item's `SlotExpression` against the actual calldata and caller.
3. Calls `db.storage()` / `db.basic()` to warm the database cache.
4. For `Account` and `ComputedAccount` items with a selector, chains into that
   address's hint entry to also prefetch its storage slots (e.g. `balanceOf` mapping
   slots on the token contract).

Prefetching is gas-neutral — it warms the underlying DB cache but does not create
journal entries or mark slots as warm in the EVM.

## Symbolic analysis

`analyze_bytecode` runs a multi-path symbolic interpreter over raw EVM bytecode:

- Tracks a symbolic stack and memory through all opcodes.
- At each `JUMPI`, explores both the fall-through and the taken branch (with `/4`
  budget decay for backward/loop branches; forward branches get full budget).
- Collects `SLOAD` slot expressions and `CALL`/`STATICCALL` targets.
- Converts symbolic expressions to `SlotExpression` trees.
- Detects the selector dispatch table to emit per-selector entries.

Maximum branch depth: 32. Visited `(pc, stack_fingerprint)` states prevent loops.

## Trace inference

`infer_from_traces` builds a hint table from recorded execution data instead of
bytecode. It groups traces by `(address, selector)`, emits `Concrete` slots that
appear in ≥80% of traces, and attempts to reverse-engineer `keccak256` mapping slots
by trying common calldata offsets and base slot indices.

## Proxy detection

`detect_proxy` (sync, provider-agnostic) and the async wrapper in the CLI both check:

1. EIP-1967 implementation slot (`keccak256("eip1967.proxy.implementation") - 1`)
2. OpenZeppelin legacy slot (`keccak256("org.zeppelinos.proxy.implementation")`)
3. EIP-1967 beacon slot → read beacon's EIP-1967 slot for final implementation

When a proxy is detected, both the implementation bytecode and the proxy's own
bytecode are analyzed and merged — capturing proxy-level SLOADs invisible to the
implementation alone.
