use std::collections::HashSet;

use alloy_primitives::{Address, B256};
use dowse_types::{HintScore, HintTable, PrefetchItem, RecordedAccess};

use crate::resolve::{resolve_slot, ResolutionContext};

/// Score a hint table against recorded accesses from a single call.
///
/// `calldata` is needed to resolve dynamic storage slots in the hint table.
/// `caller` is needed to resolve `Caller` expressions.
pub fn score_hints(
    hints: &HintTable,
    recorded: &[RecordedAccess],
    calldata: &[u8],
    caller: Address,
    target: Address,
    selector: Option<alloy_primitives::FixedBytes<4>>,
) -> HintScore {
    let predicted: HashSet<RecordedAccess> =
        resolve_predicted(hints, calldata, caller, target, selector)
            .into_iter()
            .collect();
    let actual: HashSet<RecordedAccess> = recorded.iter().cloned().collect();

    let mut hits = 0u64;
    let mut misses = 0u64;

    for p in &predicted {
        if actual.contains(p) {
            hits += 1;
        } else {
            misses += 1;
        }
    }

    let uncovered = actual
        .iter()
        .filter(|access| !predicted.contains(access))
        .count() as u64;

    HintScore {
        hits,
        misses,
        uncovered,
    }
}

/// Resolve all hint table predictions into concrete `RecordedAccess` values.
fn resolve_predicted(
    hints: &HintTable,
    calldata: &[u8],
    caller: Address,
    target: Address,
    selector: Option<alloy_primitives::FixedBytes<4>>,
) -> Vec<RecordedAccess> {
    let items = match hints.lookup(target, selector) {
        Some(items) => items,
        None => return Vec::new(),
    };

    let ctx = ResolutionContext { calldata, caller };

    let mut result = Vec::new();
    for item in items {
        match item {
            PrefetchItem::Account { address, .. } => {
                result.push(RecordedAccess::Account(*address));
            }
            PrefetchItem::Storage { slot } => {
                if let Some(key) = resolve_slot(slot, &ctx) {
                    result.push(RecordedAccess::Storage {
                        address: target,
                        slot: B256::from(key),
                    });
                }
            }
            PrefetchItem::ExternalStorage { address, slot } => {
                if let Some(key) = resolve_slot(slot, &ctx) {
                    result.push(RecordedAccess::Storage {
                        address: *address,
                        slot: B256::from(key),
                    });
                }
            }
            PrefetchItem::ComputedAccount { address: expr, .. } => {
                if let Some(key) = resolve_slot(expr, &ctx) {
                    let addr = Address::from_word(key.into());
                    result.push(RecordedAccess::Account(addr));
                }
            }
        }
    }
    result
}

/// Score a hint table against multiple recorded call traces.
///
/// Each trace is `(target_address, caller, calldata, recorded_accesses)`.
pub fn score_hints_batch(
    hints: &HintTable,
    traces: &[(Address, Address, Vec<u8>, Vec<RecordedAccess>)],
) -> HintScore {
    let mut total = HintScore::default();
    for (target, caller, calldata, accesses) in traces {
        let selector = if calldata.len() >= 4 {
            Some(alloy_primitives::FixedBytes::<4>::from_slice(
                &calldata[..4],
            ))
        } else {
            None
        };
        let score = score_hints(hints, accesses, calldata, *caller, *target, selector);
        total.hits += score.hits;
        total.misses += score.misses;
        total.uncovered += score.uncovered;
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, Address, FixedBytes, B256};
    use dowse_types::{HintTable, PrefetchItem, SlotExpression};

    const DUMMY_HASH: B256 = B256::repeat_byte(0xAB);

    #[test]
    fn perfect_score() {
        let addr = address!("0xdead000000000000000000000000000000000001");
        let slot = B256::with_last_byte(5);

        let mut hints = HintTable::new();
        let sel = FixedBytes::from([0x01, 0x02, 0x03, 0x04]);
        hints.insert(
            addr,
            DUMMY_HASH,
            Some(sel),
            vec![PrefetchItem::Storage {
                slot: SlotExpression::Concrete { value: slot },
            }],
        );

        let recorded = vec![RecordedAccess::Storage {
            address: addr,
            slot,
        }];

        let calldata = vec![0x01, 0x02, 0x03, 0x04];
        let score = score_hints(&hints, &recorded, &calldata, Address::ZERO, addr, Some(sel));
        assert_eq!(score.hits, 1);
        assert_eq!(score.misses, 0);
        assert_eq!(score.uncovered, 0);
        assert!((score.precision() - 1.0).abs() < f64::EPSILON);
        assert!((score.recall() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn partial_coverage() {
        let addr = address!("0xdead000000000000000000000000000000000001");
        let slot_a = B256::with_last_byte(1);
        let slot_b = B256::with_last_byte(2);
        let slot_c = B256::with_last_byte(3);

        let mut hints = HintTable::new();
        let sel = FixedBytes::from([0x01, 0x02, 0x03, 0x04]);
        hints.insert(
            addr,
            DUMMY_HASH,
            Some(sel),
            vec![
                PrefetchItem::Storage {
                    slot: SlotExpression::Concrete { value: slot_a },
                },
                PrefetchItem::Storage {
                    slot: SlotExpression::Concrete { value: slot_b },
                },
            ],
        );

        // Actual access: slot_a (hit) and slot_c (uncovered). slot_b is a miss.
        let recorded = vec![
            RecordedAccess::Storage {
                address: addr,
                slot: slot_a,
            },
            RecordedAccess::Storage {
                address: addr,
                slot: slot_c,
            },
        ];

        let calldata = vec![0x01, 0x02, 0x03, 0x04];
        let score = score_hints(&hints, &recorded, &calldata, Address::ZERO, addr, Some(sel));
        assert_eq!(score.hits, 1);
        assert_eq!(score.misses, 1);
        assert_eq!(score.uncovered, 1);
    }

    #[test]
    fn duplicate_predictions_are_scored_once() {
        let addr = address!("0xdead000000000000000000000000000000000001");
        let slot = B256::with_last_byte(1);

        let mut hints = HintTable::new();
        let sel = FixedBytes::from([0x01, 0x02, 0x03, 0x04]);
        hints.insert(
            addr,
            DUMMY_HASH,
            Some(sel),
            vec![
                PrefetchItem::Storage {
                    slot: SlotExpression::Concrete { value: slot },
                },
                PrefetchItem::Storage {
                    slot: SlotExpression::Concrete { value: slot },
                },
            ],
        );

        let recorded = vec![RecordedAccess::Storage {
            address: addr,
            slot,
        }];
        let calldata = vec![0x01, 0x02, 0x03, 0x04];

        let score = score_hints(&hints, &recorded, &calldata, Address::ZERO, addr, Some(sel));

        assert_eq!(score.hits, 1);
        assert_eq!(score.misses, 0);
        assert_eq!(score.uncovered, 0);
    }
}
