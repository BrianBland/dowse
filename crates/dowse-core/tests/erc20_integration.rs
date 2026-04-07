use alloy_primitives::{address, keccak256, Address, Bytes, FixedBytes, B256, U256};

const CONTRACT_CODE_HASH: B256 = B256::repeat_byte(0xCC);
use dowse_core::{PrefetchInspector, RecordingInspector};
use dowse_types::{HintTable, PrefetchItem, SlotExpression};
use revm::context::{Context, TxEnv};
use revm::database::InMemoryDB;
use revm::handler::{MainBuilder, MainContext};
use revm::state::{AccountInfo, Bytecode};
use revm::{ExecuteEvm, InspectEvm};

// A minimal ERC-20 contract (compiled from Solidity) that supports:
// - balanceOf(address) -> uint256     selector: 0x70a08231
// - transfer(address,uint256)         selector: 0xa9059cbb
// - allowance(address,address)        selector: 0xdd62ed3e
//
// Storage layout:
//   slot 0: mapping(address => uint256) balances
//   slot 1: mapping(address => mapping(address => uint256)) allowances
//   slot 2: uint256 totalSupply
//
// We use hand-crafted EVM bytecode for a minimal test contract.

const BALANCES_SLOT: u8 = 0;
const _ALLOWANCES_SLOT: u8 = 1;
const TOTAL_SUPPLY_SLOT: u8 = 2;

const CONTRACT: Address = address!("0xcafe000000000000000000000000000000000001");
const ALICE: Address = address!("0xa11ce00000000000000000000000000000000001");
const BOB: Address = address!("0xb0b0000000000000000000000000000000000001");

/// Compute Solidity mapping slot: keccak256(pad32(key) ++ pad32(base_slot))
fn mapping_slot(key: Address, base_slot: u8) -> U256 {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(key.as_slice()); // address left-padded to 32 bytes
    buf[63] = base_slot;
    keccak256(&buf).into()
}

/// Set up an InMemoryDB with a simple contract and some initial balances.
fn setup_db() -> InMemoryDB {
    let mut db = InMemoryDB::default();

    let alice_balance_slot = mapping_slot(ALICE, BALANCES_SLOT);
    let bob_balance_slot = mapping_slot(BOB, BALANCES_SLOT);

    let bytecode: Vec<u8> = {
        let mut code = Vec::new();

        // -- Function dispatch --
        // PUSH1 0x00 CALLDATALOAD   => loads first 32 bytes (includes selector)
        code.extend_from_slice(&[0x60, 0x00, 0x35]);
        // PUSH1 0xe0 SHR            => shift right to get selector
        code.extend_from_slice(&[0x60, 0xe0, 0x1c]);
        // DUP1
        code.push(0x80);
        // PUSH4 0x70a08231 (balanceOf) EQ PUSH1 <dest1> JUMPI
        code.extend_from_slice(&[0x63, 0x70, 0xa0, 0x82, 0x31, 0x14, 0x60]);
        let balance_of_dest = code.len() as u8 + 4; // will be patched
        code.push(0x00); // placeholder
        code.push(0x57); // JUMPI

        // DUP1
        code.push(0x80);
        // PUSH4 0xa9059cbb (transfer) EQ PUSH1 <dest2> JUMPI
        code.extend_from_slice(&[0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x14, 0x60]);
        let transfer_dest_idx = code.len();
        code.push(0x00); // placeholder
        code.push(0x57); // JUMPI

        // Default: STOP
        code.push(0x00); // STOP

        // -- balanceOf handler --
        let balance_of_pc = code.len() as u8;
        code[balance_of_dest as usize - 1] = balance_of_pc; // patch jump dest
        code.push(0x5b); // JUMPDEST

        // Load address arg: PUSH1 0x04 CALLDATALOAD
        code.extend_from_slice(&[0x60, 0x04, 0x35]);
        // Store at memory[0]: PUSH1 0x00 MSTORE
        code.extend_from_slice(&[0x60, 0x00, 0x52]);
        // Store base_slot at memory[32]: PUSH1 0x00 PUSH1 0x20 MSTORE
        code.extend_from_slice(&[0x60, 0x00, 0x60, 0x20, 0x52]);
        // keccak256(mem[0..64]): PUSH1 0x40 PUSH1 0x00 SHA3
        code.extend_from_slice(&[0x60, 0x40, 0x60, 0x00, 0x20]);
        // SLOAD
        code.push(0x54);
        // Store result at memory[0] and return it: PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
        code.extend_from_slice(&[0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]);

        // -- transfer handler --
        let transfer_pc = code.len() as u8;
        code[transfer_dest_idx] = transfer_pc; // patch jump dest
        code.push(0x5b); // JUMPDEST

        // Load "to" address: PUSH1 0x04 CALLDATALOAD
        code.extend_from_slice(&[0x60, 0x04, 0x35]);
        // Compute balances[to] slot:
        // Store "to" at mem[0]
        code.extend_from_slice(&[0x60, 0x00, 0x52]);
        // Store base_slot=0 at mem[32]
        code.extend_from_slice(&[0x60, 0x00, 0x60, 0x20, 0x52]);
        // keccak256(mem[0..64])
        code.extend_from_slice(&[0x60, 0x40, 0x60, 0x00, 0x20]);
        // SLOAD balances[to]
        code.push(0x54);
        // POP (discard result for simplicity)
        code.push(0x50);

        // Also SLOAD totalSupply (slot 2) as an example of a fixed slot access
        code.extend_from_slice(&[0x60, TOTAL_SUPPLY_SLOT, 0x54, 0x50]); // PUSH1 2 SLOAD POP

        // STOP
        code.push(0x00);

        code
    };

    // Set up contract account with the bytecode
    let contract_info = AccountInfo {
        balance: U256::ZERO,
        nonce: 1,
        code_hash: keccak256(&bytecode),
        account_id: None,
        code: Some(Bytecode::new_legacy(Bytes::from(bytecode))),
    };
    db.insert_account_info(CONTRACT, contract_info);

    // Set initial balances
    db.insert_account_storage(CONTRACT, alice_balance_slot, U256::from(1000))
        .unwrap();
    db.insert_account_storage(CONTRACT, bob_balance_slot, U256::from(500))
        .unwrap();
    // Total supply
    db.insert_account_storage(
        CONTRACT,
        U256::from(TOTAL_SUPPLY_SLOT),
        U256::from(1500),
    )
    .unwrap();

    // Give Alice some ETH for gas
    db.insert_account_info(
        ALICE,
        AccountInfo {
            balance: U256::from(10u64.pow(18)), // 1 ETH
            nonce: 0,
            ..Default::default()
        },
    );

    db
}

fn build_balance_of_calldata(addr: Address) -> Bytes {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&[0x70, 0xa0, 0x82, 0x31]); // balanceOf selector
    let mut padded = [0u8; 32];
    padded[12..32].copy_from_slice(addr.as_slice());
    data.extend_from_slice(&padded);
    Bytes::from(data)
}

fn build_transfer_calldata(to: Address) -> Bytes {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]); // transfer selector
    let mut padded = [0u8; 32];
    padded[12..32].copy_from_slice(to.as_slice());
    data.extend_from_slice(&padded);
    // amount (not used by our simplified contract, but include for completeness)
    data.extend_from_slice(&[0u8; 32]);
    Bytes::from(data)
}

fn build_hint_table() -> HintTable {
    let mut table = HintTable::new();
    table.metadata.source = "test".into();

    // balanceOf(address): prefetch balances[arg0]
    // keccak256(calldataWord(4) ++ concrete(0))
    table.insert(
        CONTRACT,
        CONTRACT_CODE_HASH,
        Some(FixedBytes::from([0x70, 0xa0, 0x82, 0x31])),
        vec![PrefetchItem::Storage {
            slot: SlotExpression::Keccak256 {
                inputs: vec![
                    SlotExpression::CalldataWord { offset: 4 },
                    SlotExpression::Concrete {
                        value: B256::with_last_byte(BALANCES_SLOT),
                    },
                ],
            },
        }],
    );

    // transfer(address,uint256): prefetch balances[to] and totalSupply
    table.insert(
        CONTRACT,
        CONTRACT_CODE_HASH,
        Some(FixedBytes::from([0xa9, 0x05, 0x9c, 0xbb])),
        vec![
            PrefetchItem::Storage {
                slot: SlotExpression::Keccak256 {
                    inputs: vec![
                        SlotExpression::CalldataWord { offset: 4 },
                        SlotExpression::Concrete {
                            value: B256::with_last_byte(BALANCES_SLOT),
                        },
                    ],
                },
            },
            PrefetchItem::Storage {
                slot: SlotExpression::Concrete {
                    value: B256::with_last_byte(TOTAL_SUPPLY_SLOT),
                },
            },
        ],
    );

    table
}

#[test]
fn execution_results_identical_with_and_without_prefetcher() {
    // Execute balanceOf(ALICE) without prefetcher
    let db_no_prefetch = setup_db();
    let calldata = build_balance_of_calldata(ALICE);

    let tx = TxEnv::builder()
        .caller(ALICE)
        .kind(revm::primitives::TxKind::Call(CONTRACT))
        .data(calldata.clone())
        .gas_limit(100_000)
        .build()
        .unwrap();

    let ctx_no = Context::mainnet().with_db(db_no_prefetch);
    let mut evm_no = ctx_no.build_mainnet();
    let result_no = evm_no.transact(tx.clone()).unwrap();

    // Execute balanceOf(ALICE) with prefetcher
    let db_with_prefetch = setup_db();
    let hints = build_hint_table();
    let inspector = PrefetchInspector::new(&hints);

    let ctx_with = Context::mainnet().with_db(db_with_prefetch);
    let mut evm_with = ctx_with.build_mainnet_with_inspector(inspector);
    let result_with = evm_with.inspect_tx(tx).unwrap();

    // Results should be identical
    assert_eq!(
        format!("{:?}", result_no.result),
        format!("{:?}", result_with.result),
        "Execution results should be identical with and without prefetcher"
    );

    // Prefetcher stats should show activity
    let stats = evm_with.inspector.stats();
    assert!(
        stats.calls_with_hints > 0,
        "Prefetcher should have found hints for the call"
    );
    assert!(
        stats.items_prefetched > 0,
        "Prefetcher should have prefetched items"
    );
    assert_eq!(stats.items_failed, 0, "No prefetch failures expected");
}

#[test]
fn gas_accounting_preserved_with_prefetcher() {
    let calldata = build_balance_of_calldata(ALICE);
    let tx = TxEnv::builder()
        .caller(ALICE)
        .kind(revm::primitives::TxKind::Call(CONTRACT))
        .data(calldata.clone())
        .gas_limit(100_000)
        .build()
        .unwrap();

    // Without prefetcher
    let db1 = setup_db();
    let ctx1 = Context::mainnet().with_db(db1);
    let mut evm1 = ctx1.build_mainnet();
    let result1 = evm1.transact(tx.clone()).unwrap();

    // With prefetcher
    let db2 = setup_db();
    let hints = build_hint_table();
    let inspector = PrefetchInspector::new(&hints);
    let ctx2 = Context::mainnet().with_db(db2);
    let mut evm2 = ctx2.build_mainnet_with_inspector(inspector);
    let result2 = evm2.inspect_tx(tx).unwrap();

    // Gas usage should be identical -- prefetching is gas-neutral
    let gas1 = &result1.result;
    let gas2 = &result2.result;
    assert_eq!(
        format!("{gas1:?}"),
        format!("{gas2:?}"),
        "Gas accounting must be identical with and without prefetcher"
    );
}

#[test]
fn transfer_with_prefetcher() {
    let calldata = build_transfer_calldata(BOB);
    let tx = TxEnv::builder()
        .caller(ALICE)
        .kind(revm::primitives::TxKind::Call(CONTRACT))
        .data(calldata)
        .gas_limit(100_000)
        .build()
        .unwrap();

    let db = setup_db();
    let hints = build_hint_table();
    let inspector = PrefetchInspector::new(&hints);
    let ctx = Context::mainnet().with_db(db);
    let mut evm = ctx.build_mainnet_with_inspector(inspector);
    let result = evm.inspect_tx(tx).unwrap();

    // Should succeed
    assert!(
        !format!("{:?}", result.result).contains("Revert"),
        "Transfer should not revert"
    );

    let stats = evm.inspector.stats();
    assert!(stats.calls_with_hints > 0);
    // We hint for 2 items: balances[to] mapping + totalSupply fixed slot
    assert!(
        stats.items_prefetched >= 2,
        "Expected at least 2 items prefetched, got {}",
        stats.items_prefetched
    );
}

#[test]
fn hint_table_serde_roundtrip() {
    let table = build_hint_table();
    let json = serde_json::to_string_pretty(&table).unwrap();
    let restored: HintTable = serde_json::from_str(&json).unwrap();

    assert_eq!(table.version, restored.version);
    assert_eq!(table.selector_count(), restored.selector_count());

    // Verify items exist for CONTRACT's code hash
    assert!(restored.entries.contains_key(&CONTRACT_CODE_HASH));
}

#[test]
fn scoring_against_recorded_accesses() {
    let calldata = build_balance_of_calldata(ALICE);

    // Manually compute what the recording inspector would see
    let alice_slot = mapping_slot(ALICE, BALANCES_SLOT);
    let expected_access = dowse_types::RecordedAccess::Storage {
        address: CONTRACT,
        slot: B256::from(alice_slot),
    };

    let hints = build_hint_table();
    let score = dowse_core::score::score_hints(
        &hints,
        &[expected_access],
        &calldata,
        ALICE,
        CONTRACT,
        Some(FixedBytes::from([0x70, 0xa0, 0x82, 0x31])),
    );

    assert_eq!(score.hits, 1, "Should match the balances[alice] access");
    assert_eq!(score.misses, 0, "No misses expected");
    assert_eq!(score.uncovered, 0, "No uncovered accesses expected");
    assert!((score.precision() - 1.0).abs() < f64::EPSILON);
    assert!((score.recall() - 1.0).abs() < f64::EPSILON);
}
