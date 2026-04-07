use alloy_primitives::{Address, FixedBytes};
use dowse_types::{HintTable, PrefetchItem, PrefetchStats};
use revm::context_interface::ContextTr;
use revm::interpreter::{CallInputs, CallOutcome};
use revm::{Database, Inspector};

use crate::resolve::{resolve_slot, ResolutionContext};

/// Inspector that prefetches predicted storage slots into the database cache
/// before EVM execution accesses them.
///
/// This is gas-neutral: we load data via `context.db_mut().storage()` which warms
/// the underlying database cache but does NOT create journal entries or mark
/// slots as warm. The EVM still charges cold-access gas normally.
pub struct PrefetchInspector<'a> {
    hints: &'a HintTable,
    stats: PrefetchStats,
}

impl<'a> PrefetchInspector<'a> {
    pub fn new(hints: &'a HintTable) -> Self {
        Self {
            hints,
            stats: PrefetchStats::default(),
        }
    }

    pub fn stats(&self) -> &PrefetchStats {
        &self.stats
    }

    pub fn into_stats(self) -> PrefetchStats {
        self.stats
    }
}

impl<CTX> Inspector<CTX> for PrefetchInspector<'_>
where
    CTX: ContextTr,
{
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        let target = inputs.bytecode_address;
        let calldata = inputs.input.bytes(context);
        let selector = if calldata.len() >= 4 {
            Some(FixedBytes::<4>::from_slice(&calldata[..4]))
        } else {
            None
        };

        match self.hints.lookup(target, selector) {
            Some(items) => {
                self.stats.calls_with_hints += 1;
                let ctx = ResolutionContext {
                    calldata: &calldata,
                    caller: inputs.caller,
                };
                let db = context.db_mut();
                for item in items {
                    match item {
                        PrefetchItem::Account { address, selector } => {
                            match db.basic(*address) {
                                Ok(_) => self.stats.items_prefetched += 1,
                                Err(_) => self.stats.items_failed += 1,
                            }
                            // Chain: prefetch the target's storage slots too
                            if let Some(sel) = selector {
                                if let Some(child_items) = self.hints.lookup(*address, Some(*sel)) {
                                    for child in child_items {
                                        // Only chain Storage items to avoid infinite recursion
                                        if let PrefetchItem::Storage { slot } = child {
                                            if let Some(key) = resolve_slot(slot, &ctx) {
                                                match db.storage(*address, key) {
                                                    Ok(_) => self.stats.items_prefetched += 1,
                                                    Err(_) => self.stats.items_failed += 1,
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        PrefetchItem::Storage { slot } => {
                            if let Some(key) = resolve_slot(slot, &ctx) {
                                match db.storage(target, key) {
                                    Ok(_) => self.stats.items_prefetched += 1,
                                    Err(_) => self.stats.items_failed += 1,
                                }
                            } else {
                                self.stats.items_failed += 1;
                            }
                        }
                        PrefetchItem::ComputedAccount { address: expr, selector } => {
                            if let Some(key) = resolve_slot(expr, &ctx) {
                                let addr = Address::from_word(key.into());
                                match db.basic(addr) {
                                    Ok(_) => self.stats.items_prefetched += 1,
                                    Err(_) => self.stats.items_failed += 1,
                                }
                                // Chain: prefetch the target's storage slots too
                                if let Some(sel) = selector {
                                    if let Some(child_items) = self.hints.lookup(addr, Some(*sel)) {
                                        for child in child_items {
                                            // Only chain Storage items to avoid infinite recursion
                                            if let PrefetchItem::Storage { slot } = child {
                                                if let Some(child_key) = resolve_slot(slot, &ctx) {
                                                    match db.storage(addr, child_key) {
                                                        Ok(_) => self.stats.items_prefetched += 1,
                                                        Err(_) => self.stats.items_failed += 1,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else {
                                self.stats.items_failed += 1;
                            }
                        }
                    }
                }
            }
            None => {
                self.stats.calls_without_hints += 1;
            }
        }

        None // never override execution
    }
}
