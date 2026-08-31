use std::collections::{HashMap, HashSet};

use alloy_primitives::{keccak256, Address, Bytes, FixedBytes, B256};
use dowse_types::{HintTable, PrefetchItem, Selector, SlotExpression};

const CONFIDENCE_Z_SCORE: f64 = 1.96;
const MAPPING_ARGUMENT_COUNT: usize = 3;
const MAPPING_BASE_SLOT_COUNT: usize = 10;

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

/// Incremental trace learner that can publish a hint-table snapshot without retaining calldata.
///
/// This learner is cumulative. A long-running or adversarially exposed consumer must impose
/// retention and cardinality bounds before using it in a production process.
#[derive(Debug)]
pub struct OnlineHintLearner {
    fixed_slot_min_frequency: f64,
    groups: HashMap<(Address, Selector), InferenceGroup>,
}

#[derive(Debug, Default)]
struct InferenceGroup {
    observations: usize,
    slot_counts: HashMap<(Address, B256), usize>,
    calldata_checked: [usize; MAPPING_ARGUMENT_COUNT],
    calldata_matches: [HashMap<(Address, u8), usize>; MAPPING_ARGUMENT_COUNT],
    caller_checked: usize,
    caller_matches: HashMap<(Address, u8), usize>,
}

impl OnlineHintLearner {
    /// Creates a cumulative learner with the minimum frequency for concrete storage slots.
    pub fn new(fixed_slot_min_frequency: f64) -> Self {
        assert!(
            fixed_slot_min_frequency > 0.0 && fixed_slot_min_frequency <= 1.0,
            "fixed slot minimum frequency must be in (0, 1]"
        );
        Self {
            fixed_slot_min_frequency,
            groups: HashMap::new(),
        }
    }

    /// Adds one completed call trace to the learner.
    pub fn observe(&mut self, trace: &TraceRecord) {
        let selector = if trace.calldata.len() >= 4 {
            Some(FixedBytes::<4>::from_slice(&trace.calldata[..4]))
        } else {
            None
        };
        let group = self.groups.entry((trace.address, selector)).or_default();
        group.observations += 1;

        let storage_accesses = trace
            .storage_accesses
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        for access in &storage_accesses {
            *group.slot_counts.entry(*access).or_default() += 1;
        }

        for argument_index in 0..MAPPING_ARGUMENT_COUNT {
            let offset = 4 + argument_index * 32;
            let Some(key) = trace.calldata.get(offset..offset + 32) else {
                continue;
            };
            group.calldata_checked[argument_index] += 1;
            record_mapping_matches(
                &storage_accesses,
                key,
                &mut group.calldata_matches[argument_index],
            );
        }

        if let Some(caller) = trace.caller {
            group.caller_checked += 1;
            record_mapping_matches(
                &storage_accesses,
                caller.as_slice(),
                &mut group.caller_matches,
            );
        }
    }

    /// Builds a hint table from every observation ingested so far.
    pub fn hint_table(&self) -> HintTable {
        let mut table = HintTable::new();
        table.metadata.source = "online-trace-inference".into();

        for ((address, selector), group) in &self.groups {
            let items = group.infer_items(*address, self.fixed_slot_min_frequency);
            if !items.is_empty() {
                let code_hash = keccak256(address.as_slice());
                table.insert(*address, code_hash, *selector, items);
            }
        }
        table
    }

    /// Returns the number of observed address-selector groups.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Returns the number of distinct concrete storage targets retained by the learner.
    pub fn storage_target_count(&self) -> usize {
        self.groups
            .values()
            .map(|group| group.slot_counts.len())
            .sum()
    }
}

impl InferenceGroup {
    fn infer_items(&self, contract: Address, fixed_slot_min_frequency: f64) -> Vec<PrefetchItem> {
        let threshold = (self.observations as f64 * fixed_slot_min_frequency).ceil() as usize;
        let mut items = Vec::new();
        let mut fixed_slots = HashSet::new();

        for ((address, slot), count) in &self.slot_counts {
            if *count >= threshold {
                items.push(storage_item(
                    contract,
                    *address,
                    SlotExpression::Concrete { value: *slot },
                    conservative_confidence(*count, self.observations),
                ));
                fixed_slots.insert((*address, *slot));
            }
        }

        let variable_addresses = self
            .slot_counts
            .keys()
            .filter(|target| !fixed_slots.contains(target))
            .map(|(address, _)| *address)
            .collect::<HashSet<_>>();
        if variable_addresses.is_empty() {
            return items;
        }

        for argument_index in 0..MAPPING_ARGUMENT_COUNT {
            let checked = self.calldata_checked[argument_index];
            if checked == 0 {
                continue;
            }
            let offset = 4 + argument_index * 32;
            for address in &variable_addresses {
                for base_index in 0..MAPPING_BASE_SLOT_COUNT as u8 {
                    let matches = self.calldata_matches[argument_index]
                        .get(&(*address, base_index))
                        .copied()
                        .unwrap_or_default();
                    if matches * 2 >= checked {
                        items.push(storage_item(
                            contract,
                            *address,
                            mapping_expression(SlotExpression::CalldataWord { offset }, base_index),
                            conservative_confidence(matches, checked),
                        ));
                    }
                }
            }
        }

        if self.caller_checked > 0 {
            for address in &variable_addresses {
                for base_index in 0..MAPPING_BASE_SLOT_COUNT as u8 {
                    let matches = self
                        .caller_matches
                        .get(&(*address, base_index))
                        .copied()
                        .unwrap_or_default();
                    if matches * 2 >= self.caller_checked {
                        items.push(storage_item(
                            contract,
                            *address,
                            mapping_expression(SlotExpression::Caller, base_index),
                            conservative_confidence(matches, self.caller_checked),
                        ));
                    }
                }
            }
        }

        items
    }
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
    let mut learner = OnlineHintLearner::new(fixed_slot_min_frequency);
    for trace in traces {
        learner.observe(trace);
    }
    let mut table = learner.hint_table();
    table.metadata.source = "trace-inference".into();
    table
}

fn storage_item(
    contract: Address,
    address: Address,
    slot: SlotExpression,
    confidence: f64,
) -> PrefetchItem {
    if address == contract {
        PrefetchItem::Storage { slot }.with_confidence(confidence)
    } else {
        PrefetchItem::ExternalStorage { address, slot }.with_confidence(confidence)
    }
}

fn mapping_expression(key: SlotExpression, base_index: u8) -> SlotExpression {
    SlotExpression::Keccak256 {
        inputs: vec![
            key,
            SlotExpression::Concrete {
                value: B256::with_last_byte(base_index),
            },
        ],
    }
}

fn record_mapping_matches(
    storage_accesses: &HashSet<(Address, B256)>,
    key: &[u8],
    matches: &mut HashMap<(Address, u8), usize>,
) {
    let expected_slots = std::array::from_fn::<_, MAPPING_BASE_SLOT_COUNT, _>(|base_index| {
        keccak256_mapping(key, &B256::with_last_byte(base_index as u8))
    });
    for (address, slot) in storage_accesses {
        for (base_index, expected_slot) in expected_slots.iter().enumerate() {
            if slot == expected_slot {
                *matches.entry((*address, base_index as u8)).or_default() += 1;
            }
        }
    }
}

fn conservative_confidence(successes: usize, trials: usize) -> f64 {
    if trials == 0 {
        return 0.0;
    }
    let trials = trials as f64;
    let observed = successes as f64 / trials;
    let z_squared = CONFIDENCE_Z_SCORE * CONFIDENCE_Z_SCORE;
    let center = observed + z_squared / (2.0 * trials);
    let margin = CONFIDENCE_Z_SCORE
        * ((observed * (1.0 - observed) + z_squared / (4.0 * trials)) / trials).sqrt();
    (center - margin) / (1.0 + z_squared / trials)
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
        let items = table
            .lookup(addr, Some(FixedBytes::from([0xa9, 0x05, 0x9c, 0xbb])))
            .unwrap();
        assert_eq!(items.len(), 1);
        assert!(matches!(
            items[0].scored().0,
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
            item.scored().0,
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
        let items = table
            .lookup(contract, Some(FixedBytes::from([1, 2, 3, 4])))
            .unwrap();
        assert!(matches!(
            items[0].scored().0,
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
        let items = table
            .lookup(contract, Some(FixedBytes::from(selector)))
            .unwrap();
        assert!(items.iter().any(|item| matches!(
            item.scored().0,
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
        let items = table
            .lookup(contract, Some(FixedBytes::from(selector)))
            .unwrap();

        assert!(items.iter().any(|item| matches!(
            item.scored().0,
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
        let items = table
            .lookup(contract, Some(FixedBytes::from([1, 2, 3, 4])))
            .unwrap();

        let conditional = items
            .iter()
            .find(|item| {
                matches!(
                    item.scored().0,
                    PrefetchItem::Storage { slot: SlotExpression::Concrete { value } }
                        if *value == conditional
                )
            })
            .expect("conditional slot should meet the configured threshold");
        assert!(conditional.scored().1 < 0.4);
        assert!(conditional.scored().1 > 0.05);
    }

    #[test]
    fn confidence_penalizes_small_samples() {
        assert!(conservative_confidence(1, 1) < conservative_confidence(5, 5));
        assert!(conservative_confidence(5, 5) < conservative_confidence(50, 50));
        assert!(conservative_confidence(0, 0) == 0.0);
    }
}
