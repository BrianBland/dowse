#![doc = include_str!("../README.md")]

use std::collections::HashMap;

use alloy_primitives::{keccak256, Address, B256, U256};
use dowse_types::{HintTable, PrefetchItem, SlotExpression};

/// Maximum number of each target type emitted for one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanLimits {
    /// Maximum number of account targets.
    pub accounts: usize,
    /// Maximum number of storage targets.
    pub storage_slots: usize,
}

impl PlanLimits {
    /// Creates target limits for a plan.
    pub const fn new(accounts: usize, storage_slots: usize) -> Self {
        Self {
            accounts,
            storage_slots,
        }
    }
}

/// A concrete storage value to load before transaction execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StorageTarget {
    /// Account whose storage should be read.
    pub address: Address,
    /// Concrete storage key.
    pub slot: B256,
}

/// Diagnostics produced while resolving a plan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlanDiagnostics {
    /// Items that could not be resolved from transaction context alone.
    pub unresolved_items: usize,
    /// Resolved items omitted because their target budget was exhausted.
    pub truncated_items: usize,
    /// Resolved targets omitted because the plan already contained them.
    pub duplicate_items: usize,
}

/// Concrete, bounded state targets for one transaction.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PrefetchPlan {
    /// Accounts to load. Consumers may also load bytecode referenced by each account.
    pub accounts: Vec<Address>,
    /// Storage slots to load.
    pub storage: Vec<StorageTarget>,
    /// Confidence scores parallel to [`Self::accounts`].
    pub account_confidence: Vec<f64>,
    /// Confidence scores parallel to [`Self::storage`].
    pub storage_confidence: Vec<f64>,
    /// Resolution diagnostics.
    pub diagnostics: PlanDiagnostics,
}

impl PrefetchPlan {
    /// Returns the total number of concrete targets in the plan.
    pub fn target_count(&self) -> usize {
        self.accounts.len() + self.storage.len()
    }

    /// Merges plans, retaining the highest confidence for duplicate targets and applying limits
    /// after all sources have contributed.
    pub fn merge(plans: impl IntoIterator<Item = Self>, limits: PlanLimits) -> Self {
        let mut merged = Self::default();
        let mut accounts = HashMap::new();
        let mut storage = HashMap::new();

        for plan in plans {
            merged.diagnostics.unresolved_items += plan.diagnostics.unresolved_items;
            merged.diagnostics.truncated_items += plan.diagnostics.truncated_items;
            merged.diagnostics.duplicate_items += plan.diagnostics.duplicate_items;

            for (address, confidence) in plan.accounts.into_iter().zip(plan.account_confidence) {
                push_account(&mut merged, &mut accounts, address, confidence);
            }
            for (target, confidence) in plan.storage.into_iter().zip(plan.storage_confidence) {
                push_storage(&mut merged, &mut storage, target, confidence);
            }
        }

        prioritize_targets(
            &mut merged.accounts,
            &mut merged.account_confidence,
            limits.accounts,
            &mut merged.diagnostics,
        );
        prioritize_targets(
            &mut merged.storage,
            &mut merged.storage_confidence,
            limits.storage_slots,
            &mut merged.diagnostics,
        );
        merged
    }
}

/// Resolves a hint table against transaction context without reading state.
#[derive(Debug, Clone, Copy)]
pub struct PrefetchPlanner<'a> {
    hints: &'a HintTable,
    limits: PlanLimits,
}

impl<'a> PrefetchPlanner<'a> {
    /// Creates a planner backed by `hints` with per-transaction target limits.
    pub const fn new(hints: &'a HintTable, limits: PlanLimits) -> Self {
        Self { hints, limits }
    }

    /// Resolves top-level hints for a call transaction.
    ///
    /// Returns `None` when the table has no matching address and selector entry. Child selectors
    /// are intentionally ignored: their calldata and caller context are not known before EVM
    /// execution. Dependent storage reads are counted as unresolved rather than read synchronously.
    pub fn plan(&self, target: Address, caller: Address, calldata: &[u8]) -> Option<PrefetchPlan> {
        let selector = (calldata.len() >= 4)
            .then(|| alloy_primitives::FixedBytes::<4>::from_slice(&calldata[..4]));
        let items = self.hints.lookup(target, selector)?;
        let context = ResolutionContext { calldata, caller };
        let mut plan = PrefetchPlan::default();
        let mut accounts = HashMap::new();
        let mut storage = HashMap::new();

        for item in items {
            let (item, confidence) = item.scored();
            match item {
                PrefetchItem::Account { address, .. } => {
                    push_account(&mut plan, &mut accounts, *address, confidence);
                }
                PrefetchItem::Storage { slot } => {
                    let Some(slot) = resolve_expression(slot, &context) else {
                        plan.diagnostics.unresolved_items += 1;
                        continue;
                    };
                    push_storage(
                        &mut plan,
                        &mut storage,
                        StorageTarget {
                            address: target,
                            slot,
                        },
                        confidence,
                    );
                }
                PrefetchItem::ExternalStorage { address, slot } => {
                    push_account(&mut plan, &mut accounts, *address, confidence);
                    let Some(slot) = resolve_expression(slot, &context) else {
                        plan.diagnostics.unresolved_items += 1;
                        continue;
                    };
                    push_storage(
                        &mut plan,
                        &mut storage,
                        StorageTarget {
                            address: *address,
                            slot,
                        },
                        confidence,
                    );
                }
                PrefetchItem::ComputedAccount { address, .. } => {
                    let Some(address) = resolve_expression(address, &context) else {
                        plan.diagnostics.unresolved_items += 1;
                        continue;
                    };
                    push_account(
                        &mut plan,
                        &mut accounts,
                        Address::from_word(address),
                        confidence,
                    );
                }
                PrefetchItem::Scored { .. } => unreachable!("scored() removes wrappers"),
            }
        }

        prioritize_targets(
            &mut plan.accounts,
            &mut plan.account_confidence,
            self.limits.accounts,
            &mut plan.diagnostics,
        );
        prioritize_targets(
            &mut plan.storage,
            &mut plan.storage_confidence,
            self.limits.storage_slots,
            &mut plan.diagnostics,
        );

        Some(plan)
    }
}

fn push_account(
    plan: &mut PrefetchPlan,
    seen: &mut HashMap<Address, usize>,
    address: Address,
    confidence: f64,
) {
    if let Some(index) = seen.get(&address) {
        plan.diagnostics.duplicate_items += 1;
        plan.account_confidence[*index] = plan.account_confidence[*index].max(confidence);
    } else {
        seen.insert(address, plan.accounts.len());
        plan.accounts.push(address);
        plan.account_confidence.push(confidence);
    }
}

fn push_storage(
    plan: &mut PrefetchPlan,
    seen: &mut HashMap<StorageTarget, usize>,
    target: StorageTarget,
    confidence: f64,
) {
    if let Some(index) = seen.get(&target) {
        plan.diagnostics.duplicate_items += 1;
        plan.storage_confidence[*index] = plan.storage_confidence[*index].max(confidence);
    } else {
        seen.insert(target, plan.storage.len());
        plan.storage.push(target);
        plan.storage_confidence.push(confidence);
    }
}

fn prioritize_targets<T>(
    targets: &mut Vec<T>,
    confidence: &mut Vec<f64>,
    limit: usize,
    diagnostics: &mut PlanDiagnostics,
) {
    let mut ranked = std::mem::take(targets)
        .into_iter()
        .zip(std::mem::take(confidence))
        .enumerate()
        .collect::<Vec<_>>();
    ranked.sort_by(|(left_index, (_, left)), (right_index, (_, right))| {
        right
            .total_cmp(left)
            .then_with(|| left_index.cmp(right_index))
    });
    diagnostics.truncated_items += ranked.len().saturating_sub(limit);
    ranked.truncate(limit);
    for (_, (target, target_confidence)) in ranked {
        targets.push(target);
        confidence.push(target_confidence);
    }
}

struct ResolutionContext<'a> {
    calldata: &'a [u8],
    caller: Address,
}

fn resolve_expression(
    expression: &SlotExpression,
    context: &ResolutionContext<'_>,
) -> Option<B256> {
    match expression {
        SlotExpression::Concrete { value } => Some(*value),
        SlotExpression::CalldataWord { offset } => {
            let end = offset.checked_add(32)?;
            context.calldata.get(*offset..end).map(B256::from_slice)
        }
        SlotExpression::Caller => Some(context.caller.into_word()),
        SlotExpression::Keccak256 { inputs } => {
            let mut preimage = Vec::with_capacity(inputs.len().saturating_mul(32));
            for input in inputs {
                preimage.extend_from_slice(resolve_expression(input, context)?.as_slice());
            }
            Some(keccak256(preimage))
        }
        SlotExpression::Add { left, right } => {
            let left = U256::from_be_bytes(resolve_expression(left, context)?.0);
            let right = U256::from_be_bytes(resolve_expression(right, context)?.0);
            Some(B256::from(left.wrapping_add(right)))
        }
        SlotExpression::SLoad { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{address, FixedBytes};

    use super::*;

    const TARGET: Address = address!("0x1111000000000000000000000000000000000001");
    const CALLER: Address = address!("0x2222000000000000000000000000000000000002");
    const ACCOUNT: Address = address!("0x3333000000000000000000000000000000000003");
    const CODE_HASH: B256 = B256::repeat_byte(0x11);
    const SELECTOR: FixedBytes<4> = FixedBytes::new([0xaa, 0xbb, 0xcc, 0xdd]);

    fn calldata(word: B256) -> Vec<u8> {
        let mut calldata = SELECTOR.to_vec();
        calldata.extend_from_slice(word.as_slice());
        calldata
    }

    #[test]
    fn resolves_top_level_accounts_and_dynamic_storage() {
        let mut hints = HintTable::new();
        hints.insert(
            TARGET,
            CODE_HASH,
            Some(SELECTOR),
            vec![
                PrefetchItem::Account {
                    address: ACCOUNT,
                    selector: Some(FixedBytes::new([1, 2, 3, 4])),
                },
                PrefetchItem::Storage {
                    slot: SlotExpression::Keccak256 {
                        inputs: vec![
                            SlotExpression::CalldataWord { offset: 4 },
                            SlotExpression::Concrete { value: B256::ZERO },
                        ],
                    },
                },
            ],
        );

        let word = B256::with_last_byte(7);
        let plan = PrefetchPlanner::new(&hints, PlanLimits::new(4, 4))
            .plan(TARGET, CALLER, &calldata(word))
            .unwrap();

        assert_eq!(plan.accounts, vec![ACCOUNT]);
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(word.as_slice());
        assert_eq!(
            plan.storage,
            vec![StorageTarget {
                address: TARGET,
                slot: keccak256(preimage)
            }]
        );
        assert_eq!(plan.diagnostics, PlanDiagnostics::default());
    }

    #[test]
    fn resolves_external_storage_against_top_level_calldata() {
        let mut hints = HintTable::new();
        hints.insert(
            TARGET,
            CODE_HASH,
            Some(SELECTOR),
            vec![PrefetchItem::ExternalStorage {
                address: ACCOUNT,
                slot: SlotExpression::CalldataWord { offset: 4 },
            }],
        );
        let word = B256::with_last_byte(7);

        let plan = PrefetchPlanner::new(&hints, PlanLimits::new(1, 1))
            .plan(TARGET, CALLER, &calldata(word))
            .unwrap();

        assert_eq!(plan.accounts, vec![ACCOUNT]);
        assert_eq!(
            plan.storage,
            vec![StorageTarget {
                address: ACCOUNT,
                slot: word
            }]
        );
    }

    #[test]
    fn does_not_follow_child_selectors() {
        let child_selector = FixedBytes::new([1, 2, 3, 4]);
        let mut hints = HintTable::new();
        hints.insert(
            TARGET,
            CODE_HASH,
            Some(SELECTOR),
            vec![PrefetchItem::Account {
                address: ACCOUNT,
                selector: Some(child_selector),
            }],
        );
        hints.insert(
            ACCOUNT,
            B256::repeat_byte(0x33),
            Some(child_selector),
            vec![PrefetchItem::Storage {
                slot: SlotExpression::Concrete {
                    value: B256::with_last_byte(9),
                },
            }],
        );

        let plan = PrefetchPlanner::new(&hints, PlanLimits::new(4, 4))
            .plan(TARGET, CALLER, &calldata(B256::ZERO))
            .unwrap();

        assert_eq!(plan.accounts, vec![ACCOUNT]);
        assert!(plan.storage.is_empty());
    }

    #[test]
    fn omits_dependent_and_out_of_bounds_expressions() {
        let mut hints = HintTable::new();
        hints.insert(
            TARGET,
            CODE_HASH,
            Some(SELECTOR),
            vec![
                PrefetchItem::Storage {
                    slot: SlotExpression::SLoad {
                        key: Box::new(SlotExpression::Concrete { value: B256::ZERO }),
                    },
                },
                PrefetchItem::Storage {
                    slot: SlotExpression::CalldataWord { offset: usize::MAX },
                },
            ],
        );

        let plan = PrefetchPlanner::new(&hints, PlanLimits::new(4, 4))
            .plan(TARGET, CALLER, SELECTOR.as_slice())
            .unwrap();

        assert!(plan.storage.is_empty());
        assert_eq!(plan.diagnostics.unresolved_items, 2);
    }

    #[test]
    fn deduplicates_and_bounds_targets() {
        let extra = address!("0x4444000000000000000000000000000000000004");
        let slot = SlotExpression::Concrete {
            value: B256::with_last_byte(1),
        };
        let mut hints = HintTable::new();
        hints.insert(
            TARGET,
            CODE_HASH,
            Some(SELECTOR),
            vec![
                PrefetchItem::Account {
                    address: ACCOUNT,
                    selector: None,
                },
                PrefetchItem::Account {
                    address: ACCOUNT,
                    selector: None,
                },
                PrefetchItem::Account {
                    address: extra,
                    selector: None,
                },
                PrefetchItem::Storage { slot: slot.clone() },
                PrefetchItem::Storage { slot: slot.clone() },
                PrefetchItem::Storage {
                    slot: SlotExpression::Concrete {
                        value: B256::with_last_byte(2),
                    },
                },
            ],
        );

        let plan = PrefetchPlanner::new(&hints, PlanLimits::new(1, 1))
            .plan(TARGET, CALLER, &calldata(B256::ZERO))
            .unwrap();

        assert_eq!(plan.target_count(), 2);
        assert_eq!(plan.diagnostics.duplicate_items, 2);
        assert_eq!(plan.diagnostics.truncated_items, 2);
    }

    #[test]
    fn deduplicated_targets_keep_highest_confidence() {
        let slot = SlotExpression::Concrete {
            value: B256::with_last_byte(1),
        };
        let mut hints = HintTable::new();
        hints.insert(
            TARGET,
            CODE_HASH,
            Some(SELECTOR),
            vec![
                PrefetchItem::Account {
                    address: ACCOUNT,
                    selector: None,
                }
                .with_confidence(0.4),
                PrefetchItem::Account {
                    address: ACCOUNT,
                    selector: None,
                }
                .with_confidence(0.9),
                PrefetchItem::Storage { slot: slot.clone() }.with_confidence(0.8),
                PrefetchItem::Storage { slot }.with_confidence(0.3),
            ],
        );

        let plan = PrefetchPlanner::new(&hints, PlanLimits::new(4, 4))
            .plan(TARGET, CALLER, &calldata(B256::ZERO))
            .unwrap();
        assert_eq!(plan.account_confidence, vec![0.9]);
        assert_eq!(plan.storage_confidence, vec![0.8]);
    }

    #[test]
    fn bounds_targets_after_prioritizing_confidence() {
        let low_account = address!("0x4444000000000000000000000000000000000004");
        let high_account = address!("0x5555000000000000000000000000000000000005");
        let low_slot = B256::with_last_byte(1);
        let high_slot = B256::with_last_byte(2);
        let mut hints = HintTable::new();
        hints.insert(
            TARGET,
            CODE_HASH,
            Some(SELECTOR),
            vec![
                PrefetchItem::Account {
                    address: low_account,
                    selector: None,
                }
                .with_confidence(0.1),
                PrefetchItem::Account {
                    address: high_account,
                    selector: None,
                }
                .with_confidence(0.9),
                PrefetchItem::Storage {
                    slot: SlotExpression::Concrete { value: low_slot },
                }
                .with_confidence(0.2),
                PrefetchItem::Storage {
                    slot: SlotExpression::Concrete { value: high_slot },
                }
                .with_confidence(0.8),
            ],
        );

        let plan = PrefetchPlanner::new(&hints, PlanLimits::new(1, 1))
            .plan(TARGET, CALLER, &calldata(B256::ZERO))
            .unwrap();

        assert_eq!(plan.accounts, vec![high_account]);
        assert_eq!(plan.account_confidence, vec![0.9]);
        assert_eq!(
            plan.storage,
            vec![StorageTarget {
                address: TARGET,
                slot: high_slot,
            }]
        );
        assert_eq!(plan.storage_confidence, vec![0.8]);
        assert_eq!(plan.diagnostics.truncated_items, 2);
    }

    #[test]
    fn returns_none_without_matching_hints() {
        let hints = HintTable::new();
        assert!(PrefetchPlanner::new(&hints, PlanLimits::new(1, 1))
            .plan(TARGET, CALLER, &calldata(B256::ZERO))
            .is_none());
    }

    #[test]
    fn merges_sources_before_deduplicating_and_bounding() {
        let low_slot = StorageTarget {
            address: TARGET,
            slot: B256::with_last_byte(1),
        };
        let high_slot = StorageTarget {
            address: TARGET,
            slot: B256::with_last_byte(2),
        };
        let first = PrefetchPlan {
            accounts: vec![ACCOUNT],
            storage: vec![low_slot, high_slot],
            account_confidence: vec![0.2],
            storage_confidence: vec![0.3, 0.8],
            diagnostics: PlanDiagnostics::default(),
        };
        let second = PrefetchPlan {
            accounts: vec![ACCOUNT],
            storage: vec![low_slot],
            account_confidence: vec![1.0],
            storage_confidence: vec![0.9],
            diagnostics: PlanDiagnostics::default(),
        };

        let merged = PrefetchPlan::merge([first, second], PlanLimits::new(1, 1));

        assert_eq!(merged.accounts, vec![ACCOUNT]);
        assert_eq!(merged.account_confidence, vec![1.0]);
        assert_eq!(merged.storage, vec![low_slot]);
        assert_eq!(merged.storage_confidence, vec![0.9]);
        assert_eq!(merged.diagnostics.duplicate_items, 2);
        assert_eq!(merged.diagnostics.truncated_items, 1);
    }
}
