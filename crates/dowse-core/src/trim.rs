use dowse_types::{HintTable, PrefetchItem, SlotExpression};

/// Trim a hint table down to only high-value entries.
///
/// The prefetcher runs concurrently with EVM execution. To be worthwhile, we
/// need entries that:
///   1. Are NOT concrete storage slots (those are often already warm/cached).
///   2. Reference dynamic expressions (CalldataWord, Caller, Keccak256) that
///      predict state the sequential interpreter hasn't seen yet.
///   3. Have at least `min_dynamic_items` dynamic slots per selector to justify
///      the overhead.
///
/// Concrete Account entries are kept because they prefetch code + balance + nonce
/// for addresses that might be called.
pub fn trim_hint_table(table: &HintTable, min_dynamic_items: usize) -> HintTable {
    let mut trimmed = HintTable::new();
    trimmed.version = table.version;
    trimmed.metadata = table.metadata.clone();
    // Copy all address→code_hash mappings wholesale
    trimmed.code_hashes = table.code_hashes.clone();

    for (code_hash, sel_map) in &table.entries {
        for (selector, items) in sel_map {
            let valuable: Vec<PrefetchItem> = items
                .iter()
                .filter(|item| is_valuable_item(item))
                .cloned()
                .collect();

            let dynamic_count = valuable
                .iter()
                .filter(|item| matches!(
                    item,
                    PrefetchItem::Storage { slot } if is_dynamic_slot(slot)
                ) || matches!(
                    item,
                    PrefetchItem::ComputedAccount { address, .. } if is_dynamic_slot(address)
                ))
                .count();

            if dynamic_count >= min_dynamic_items
                || (!valuable.is_empty() && min_dynamic_items == 0)
            {
                trimmed.insert_by_hash(*code_hash, *selector, valuable);
            }
        }
    }

    trimmed
}

/// Is this prefetch item worth the overhead of concurrent fetching?
pub fn is_valuable_item(item: &PrefetchItem) -> bool {
    match item {
        PrefetchItem::Account { .. } => true,
        PrefetchItem::Storage { slot } => is_dynamic_slot(slot),
        PrefetchItem::ComputedAccount { address, .. } => is_dynamic_slot(address),
    }
}

/// Is this slot expression dynamic (depends on runtime inputs)?
pub fn is_dynamic_slot(expr: &SlotExpression) -> bool {
    match expr {
        SlotExpression::Concrete { .. } => false,
        SlotExpression::CalldataWord { .. } | SlotExpression::Caller => true,
        SlotExpression::Keccak256 { inputs } => inputs.iter().any(is_dynamic_slot),
        SlotExpression::Add { left, right } => is_dynamic_slot(left) || is_dynamic_slot(right),
        SlotExpression::SLoad { key } => is_dynamic_slot(key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, B256, FixedBytes};

    const DUMMY_HASH: B256 = B256::repeat_byte(0xAB);

    #[test]
    fn dynamic_slot_detection() {
        assert!(!is_dynamic_slot(&SlotExpression::Concrete {
            value: B256::ZERO
        }));
        assert!(is_dynamic_slot(&SlotExpression::CalldataWord { offset: 4 }));
        assert!(is_dynamic_slot(&SlotExpression::Caller));
        assert!(is_dynamic_slot(&SlotExpression::Keccak256 {
            inputs: vec![
                SlotExpression::CalldataWord { offset: 4 },
                SlotExpression::Concrete {
                    value: B256::ZERO
                },
            ],
        }));
        assert!(!is_dynamic_slot(&SlotExpression::Keccak256 {
            inputs: vec![SlotExpression::Concrete {
                value: B256::ZERO
            }],
        }));
    }

    #[test]
    fn trim_removes_concrete_only_selectors() {
        let mut table = HintTable::new();
        let addr = address!("0xdead000000000000000000000000000000000001");

        // Selector with only concrete slots
        table.insert(
            addr,
            DUMMY_HASH,
            Some(FixedBytes::from([0xaa, 0xaa, 0xaa, 0xaa])),
            vec![PrefetchItem::Storage {
                slot: SlotExpression::Concrete {
                    value: B256::ZERO,
                },
            }],
        );

        // Selector with a dynamic slot
        table.insert(
            addr,
            DUMMY_HASH,
            Some(FixedBytes::from([0xbb, 0xbb, 0xbb, 0xbb])),
            vec![PrefetchItem::Storage {
                slot: SlotExpression::Keccak256 {
                    inputs: vec![
                        SlotExpression::CalldataWord { offset: 4 },
                        SlotExpression::Concrete {
                            value: B256::ZERO,
                        },
                    ],
                },
            }],
        );

        let trimmed = trim_hint_table(&table, 1);
        assert_eq!(trimmed.selector_count(), 1);
    }

    #[test]
    fn trim_keeps_account_items() {
        let mut table = HintTable::new();
        let addr = address!("0xdead000000000000000000000000000000000001");
        let target = address!("0x0000000000000000000000000000000000C0FFEE");

        table.insert(
            addr,
            DUMMY_HASH,
            Some(FixedBytes::from([0xaa, 0xaa, 0xaa, 0xaa])),
            vec![PrefetchItem::Account { address: target, selector: None }],
        );

        // min_dynamic_items=0 keeps non-empty selectors
        let trimmed = trim_hint_table(&table, 0);
        assert_eq!(trimmed.item_count(), 1);
    }
}
