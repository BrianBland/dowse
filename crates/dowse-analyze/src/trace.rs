use std::collections::{HashMap, HashSet};

use alloy_primitives::{Address, B256, Bytes, FixedBytes, keccak256};
use dowse_types::{HintTable, PrefetchItem, Selector, SlotExpression};

/// A single recorded trace of a contract call.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TraceRecord {
    /// Contract address called.
    pub address: Address,
    /// Transaction sender, when captured by the trace source.
    #[serde(default)]
    pub caller: Option<Address>,
    /// Full calldata including 4-byte selector.
    pub calldata: Bytes,
    /// Storage slots accessed: (address, slot).
    pub storage_accesses: Vec<(Address, B256)>,
}

/// Infer a `HintTable` from recorded execution traces.
///
/// Groups traces by (contract, selector), then:
/// 1. Identifies slots that appear in all/most traces for a selector -> `Concrete` slots
/// 2. For variable slots, attempts to reverse-engineer keccak256 mapping derivation
pub fn infer_from_traces(traces: &[TraceRecord]) -> HintTable {
    infer_from_traces_with_threshold(traces, 0.8)
}

/// Infers a [`HintTable`] with a configurable minimum frequency for concrete slots.
pub fn infer_from_traces_with_threshold(
    traces: &[TraceRecord],
    fixed_slot_min_frequency: f64,
) -> HintTable {
    assert!(
        fixed_slot_min_frequency > 0.0 && fixed_slot_min_frequency <= 1.0,
        "fixed slot minimum frequency must be in (0, 1]"
    );
    let mut table = HintTable::new();
    table.metadata.source = "trace-inference".into();

    // Group by (address, selector)
    let mut grouped: HashMap<(Address, Selector), Vec<&TraceRecord>> = HashMap::new();
    for trace in traces {
        let selector: Selector = if trace.calldata.len() >= 4 {
            Some(FixedBytes::<4>::from_slice(&trace.calldata[..4]))
        } else {
            None
        };
        grouped
            .entry((trace.address, selector))
            .or_default()
            .push(trace);
    }

    for ((address, selector), traces) in &grouped {
        let items = infer_items_for_group(*address, traces, fixed_slot_min_frequency);
        if !items.is_empty() {
            // Use keccak256(address) as synthetic code hash for trace-inferred hints
            let code_hash = keccak256(address.as_slice());
            table.insert(*address, code_hash, *selector, items);
        }
    }

    table
}

fn infer_items_for_group(
    contract: Address,
    traces: &[&TraceRecord],
    fixed_slot_min_frequency: f64,
) -> Vec<PrefetchItem> {
    if traces.is_empty() {
        return Vec::new();
    }

    let total = traces.len();
    let mut items = Vec::new();

    // Collect all (address, slot) pairs and count how often each appears
    let mut slot_counts: HashMap<(Address, B256), usize> = HashMap::new();
    for trace in traces {
        // Deduplicate within a single trace
        let unique: HashSet<_> = trace.storage_accesses.iter().cloned().collect();
        for access in unique {
            *slot_counts.entry(access).or_default() += 1;
        }
    }

    let threshold = (total as f64 * fixed_slot_min_frequency).ceil() as usize;

    let mut fixed_slots = HashSet::new();
    for ((address, slot), count) in &slot_counts {
        if *count >= threshold {
            if *address == contract {
                items.push(PrefetchItem::Storage {
                    slot: SlotExpression::Concrete { value: *slot },
                });
            } else {
                items.push(PrefetchItem::ExternalStorage {
                    address: *address,
                    slot: SlotExpression::Concrete { value: *slot },
                });
            }
            fixed_slots.insert((*address, *slot));
        }
    }

    // For variable slots (not fixed), try to derive mapping patterns
    let variable_slots: Vec<_> = slot_counts
        .keys()
        .filter(|k| !fixed_slots.contains(k))
        .cloned()
        .collect();

    if !variable_slots.is_empty() {
        let mapping_items = try_infer_mappings(contract, traces, &variable_slots);
        items.extend(mapping_items);
    }

    items
}

/// Attempt to infer mapping base slots from variable storage accesses.
fn try_infer_mappings(
    contract: Address,
    traces: &[&TraceRecord],
    variable_slots: &[(Address, B256)],
) -> Vec<PrefetchItem> {
    let mut results = Vec::new();
    let mut found_targets: HashSet<(Address, usize, B256)> = HashSet::new();
    let mut found_caller_targets: HashSet<(Address, B256)> = HashSet::new();
    let addresses: HashSet<Address> = variable_slots.iter().map(|(address, _)| *address).collect();

    // Try common calldata offsets (4, 36, 68 = first 3 args including selector prefix)
    for arg_idx in 0..3 {
        let calldata_offset = 4 + arg_idx * 32;

        // Try common base slots (0..10)
        for address in &addresses {
            for base_idx in 0u8..10 {
                let base_slot = B256::with_last_byte(base_idx);

                let mut matches = 0usize;
                let mut checked = 0usize;

                for trace in traces {
                    let cd = &trace.calldata;
                    let start = calldata_offset;
                    let end = start + 32;
                    if cd.len() < end {
                        continue;
                    }
                    checked += 1;

                    let key_bytes = &cd[start..end];
                    let expected_slot = keccak256_mapping(key_bytes, &base_slot);

                    if trace
                        .storage_accesses
                        .iter()
                        .any(|access| access == &(*address, expected_slot))
                    {
                        matches += 1;
                    }
                }

                // If >= 50% of traces match this pattern, emit it.
                if checked > 0
                    && matches * 2 >= checked
                    && found_targets.insert((*address, calldata_offset, base_slot))
                {
                    let slot = SlotExpression::Keccak256 {
                        inputs: vec![
                            SlotExpression::CalldataWord {
                                offset: calldata_offset,
                            },
                            SlotExpression::Concrete { value: base_slot },
                        ],
                    };
                    if *address == contract {
                        results.push(PrefetchItem::Storage { slot });
                    } else {
                        results.push(PrefetchItem::ExternalStorage {
                            address: *address,
                            slot,
                        });
                    }
                }
            }
        }
    }

    for address in &addresses {
        for base_idx in 0u8..10 {
            let base_slot = B256::with_last_byte(base_idx);
            let mut matches = 0usize;
            let mut checked = 0usize;

            for trace in traces {
                let Some(caller) = trace.caller else {
                    continue;
                };
                checked += 1;
                let expected_slot = keccak256_mapping(caller.as_slice(), &base_slot);
                if trace
                    .storage_accesses
                    .iter()
                    .any(|access| access == &(*address, expected_slot))
                {
                    matches += 1;
                }
            }

            if checked > 0
                && matches * 2 >= checked
                && found_caller_targets.insert((*address, base_slot))
            {
                let slot = SlotExpression::Keccak256 {
                    inputs: vec![
                        SlotExpression::Caller,
                        SlotExpression::Concrete { value: base_slot },
                    ],
                };
                if *address == contract {
                    results.push(PrefetchItem::Storage { slot });
                } else {
                    results.push(PrefetchItem::ExternalStorage {
                        address: *address,
                        slot,
                    });
                }
            }
        }
    }

    results
}

/// Compute keccak256(left_pad_32(key) ++ base_slot) for mapping slot derivation.
fn keccak256_mapping(key: &[u8], base_slot: &B256) -> B256 {
    let mut buf = Vec::with_capacity(64);
    if key.len() < 32 {
        buf.resize(32 - key.len(), 0);
    }
    buf.extend_from_slice(key);
    buf.extend_from_slice(base_slot.as_slice());
    keccak256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn infer_fixed_slots() {
        let addr = address!("0xdead000000000000000000000000000000000001");
        let slot = B256::with_last_byte(5);
        let sel = vec![0xa9, 0x05, 0x9c, 0xbb];

        // Create 5 traces all accessing the same slot
        let traces: Vec<TraceRecord> = (0..5)
            .map(|_| TraceRecord {
                address: addr,
                caller: None,
                calldata: Bytes::from(sel.clone()),
                storage_accesses: vec![(addr, slot)],
            })
            .collect();

        let table = infer_from_traces(&traces);
        let items = table.lookup(addr, Some(FixedBytes::from([0xa9, 0x05, 0x9c, 0xbb]))).unwrap();
        assert_eq!(items.len(), 1);
        assert!(matches!(
            &items[0],
            PrefetchItem::Storage { slot: SlotExpression::Concrete { value: s } } if *s == slot
        ));
    }

    #[test]
    fn infer_mapping_pattern() {
        let addr = address!("0xdead000000000000000000000000000000000001");
        let base_slot = B256::with_last_byte(0);
        let sel = [0x70, 0xa0, 0x82, 0x31]; // balanceOf

        // Create traces with different addresses, each accessing their mapping slot
        let traces: Vec<TraceRecord> = (1u8..=5)
            .map(|i| {
                let mut calldata = Vec::from(sel);
                let mut key = vec![0u8; 32];
                key[31] = i;
                calldata.extend_from_slice(&key);

                // Compute expected mapping slot
                let expected = keccak256_mapping(&key, &base_slot);

                TraceRecord {
                    address: addr,
                    caller: None,
                    calldata: Bytes::from(calldata),
                    storage_accesses: vec![(addr, expected)],
                }
            })
            .collect();

        let table = infer_from_traces(&traces);
        let items = table.lookup(addr, Some(FixedBytes::from(sel))).unwrap();

        // Should find a mapping pattern with CalldataWord at offset 4
        assert!(items.iter().any(|item| matches!(
            item,
            PrefetchItem::Storage {
                slot: SlotExpression::Keccak256 { inputs },
            } if inputs.len() == 2
                && matches!(&inputs[0], SlotExpression::CalldataWord { offset: 4 })
                && matches!(&inputs[1], SlotExpression::Concrete { value: bs } if *bs == base_slot)
        )));
    }

    #[test]
    fn infer_fixed_external_slot() {
        let contract = address!("0xdead000000000000000000000000000000000001");
        let external = address!("0xdead000000000000000000000000000000000002");
        let slot = B256::with_last_byte(5);
        let traces: Vec<TraceRecord> = (0..5)
            .map(|_| TraceRecord {
                address: contract,
                caller: None,
                calldata: Bytes::from(vec![1, 2, 3, 4]),
                storage_accesses: vec![(external, slot)],
            })
            .collect();

        let table = infer_from_traces(&traces);
        let items = table.lookup(contract, Some(FixedBytes::from([1, 2, 3, 4]))).unwrap();
        assert!(matches!(
            &items[0],
            PrefetchItem::ExternalStorage {
                address,
                slot: SlotExpression::Concrete { value }
            } if *address == external && *value == slot
        ));
    }

    #[test]
    fn infer_external_mapping_pattern() {
        let contract = address!("0xdead000000000000000000000000000000000001");
        let external = address!("0xdead000000000000000000000000000000000002");
        let base_slot = B256::with_last_byte(3);
        let selector = [0x70, 0xa0, 0x82, 0x31];
        let traces: Vec<TraceRecord> = (1u8..=5)
            .map(|value| {
                let mut calldata = Vec::from(selector);
                let mut key = vec![0u8; 32];
                key[31] = value;
                calldata.extend_from_slice(&key);
                TraceRecord {
                    address: contract,
                    caller: None,
                    calldata: Bytes::from(calldata),
                    storage_accesses: vec![(external, keccak256_mapping(&key, &base_slot))],
                }
            })
            .collect();

        let table = infer_from_traces(&traces);
        let items = table.lookup(contract, Some(FixedBytes::from(selector))).unwrap();
        assert!(items.iter().any(|item| matches!(
            item,
            PrefetchItem::ExternalStorage {
                address,
                slot: SlotExpression::Keccak256 { inputs }
            } if *address == external
                && matches!(&inputs[0], SlotExpression::CalldataWord { offset: 4 })
                && matches!(&inputs[1], SlotExpression::Concrete { value } if *value == base_slot)
        )));
    }

    #[test]
    fn infer_caller_mapping_pattern() {
        let contract = address!("0xdead000000000000000000000000000000000001");
        let external = address!("0xdead000000000000000000000000000000000002");
        let base_slot = B256::with_last_byte(4);
        let selector = [0x12, 0x34, 0x56, 0x78];
        let traces: Vec<TraceRecord> = (1u8..=5)
            .map(|value| {
                let caller = Address::with_last_byte(value);
                TraceRecord {
                    address: contract,
                    caller: Some(caller),
                    calldata: Bytes::from(selector.to_vec()),
                    storage_accesses: vec![(
                        external,
                        keccak256_mapping(caller.as_slice(), &base_slot),
                    )],
                }
            })
            .collect();

        let table = infer_from_traces(&traces);
        let items = table.lookup(contract, Some(FixedBytes::from(selector))).unwrap();

        assert!(items.iter().any(|item| matches!(
            item,
            PrefetchItem::ExternalStorage {
                address,
                slot: SlotExpression::Keccak256 { inputs }
            } if *address == external
                && matches!(&inputs[0], SlotExpression::Caller)
                && matches!(&inputs[1], SlotExpression::Concrete { value } if *value == base_slot)
        )));
    }

    #[test]
    fn configurable_threshold_includes_conditional_fixed_slot() {
        let contract = address!("0xdead000000000000000000000000000000000001");
        let always = B256::with_last_byte(1);
        let conditional = B256::with_last_byte(2);
        let traces: Vec<TraceRecord> = (0..5)
            .map(|index| TraceRecord {
                address: contract,
                caller: None,
                calldata: Bytes::from(vec![1, 2, 3, 4]),
                storage_accesses: if index < 2 {
                    vec![(contract, always), (contract, conditional)]
                } else {
                    vec![(contract, always)]
                },
            })
            .collect();

        let table = infer_from_traces_with_threshold(&traces, 0.4);
        let items = table.lookup(contract, Some(FixedBytes::from([1, 2, 3, 4]))).unwrap();

        assert!(items.iter().any(|item| matches!(
            item,
            PrefetchItem::Storage { slot: SlotExpression::Concrete { value } }
                if *value == conditional
        )));
    }
}
