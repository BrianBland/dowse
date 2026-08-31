# dowse-decode

Protocol-aware state-prefetch decoders for transaction calldata.

The Base mainnet decoder recognizes deterministic ERC-20 and B20 state and nested calls through
major Uniswap, Aerodrome, account-abstraction, and settlement protocols. It emits concrete account
and storage targets without executing EVM bytecode or reading state. State-dependent swap tails,
including concentrated-liquidity tick traversal and arbitrary hooks, are intentionally left to
bounded pre-simulation.
