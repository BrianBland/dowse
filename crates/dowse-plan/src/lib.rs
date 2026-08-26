#![doc = include_str!("../README.md")]

use std::collections::HashSet;

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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrefetchPlan {
    /// Accounts to load. Consumers may also load bytecode referenced by each account.
    pub accounts: Vec<Address>,
    /// Storage slots to load.
    pub storage: Vec<StorageTarget>,
    /// Resolution diagnostics.
    pub diagnostics: PlanDiagnostics,
}

impl PrefetchPlan {
    /// Returns the total number of concrete targets in the plan.
    pub fn target_count(&self) -> usize {
        self.accounts.len() + self.storage.len()
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
        let mut accounts = HashSet::new();
        let mut storage = HashSet::new();

        for item in items {
            match item {
                PrefetchItem::Account { address, .. } => {
                    push_account(&mut plan, &mut accounts, *address, self.limits.accounts);
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
                        self.limits.storage_slots,
                    );
                }
                PrefetchItem::ExternalStorage { address, slot } => {
                    push_account(&mut plan, &mut accounts, *address, self.limits.accounts);
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
                        self.limits.storage_slots,
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
                        self.limits.accounts,
                    );
                }
            }
        }

        Some(plan)
    }
}

fn push_account(
    plan: &mut PrefetchPlan,
    seen: &mut HashSet<Address>,
    address: Address,
    limit: usize,
) {
    if seen.contains(&address) {
        plan.diagnostics.duplicate_items += 1;
    } else if plan.accounts.len() == limit {
        plan.diagnostics.truncated_items += 1;
    } else {
        seen.insert(address);
        plan.accounts.push(address);
    }
}

fn push_storage(
    plan: &mut PrefetchPlan,
    seen: &mut HashSet<StorageTarget>,
    target: StorageTarget,
    limit: usize,
) {
    if seen.contains(&target) {
        plan.diagnostics.duplicate_items += 1;
    } else if plan.storage.len() == limit {
        plan.diagnostics.truncated_items += 1;
    } else {
        seen.insert(target);
        plan.storage.push(target);
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
        assert_eq!(plan.storage, vec![StorageTarget { address: ACCOUNT, slot: word }]);
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
    fn returns_none_without_matching_hints() {
        let hints = HintTable::new();
        assert!(PrefetchPlanner::new(&hints, PlanLimits::new(1, 1))
            .plan(TARGET, CALLER, &calldata(B256::ZERO))
            .is_none());
    }
}
