use std::collections::HashMap;

use alloy_primitives::hex;
use alloy_primitives::{Address, B256, FixedBytes};
use serde::{Deserialize, Serialize};

/// Custom serialization for `SelectorMap` so that `None` (wildcard) keys
/// serialize as `"*"` in JSON, and `Some(sel)` keys serialize as `"0xaabbccdd"`.
mod selector_map_serde {
    use super::*;
    use serde::de::{self, MapAccess, Visitor};
    use serde::ser::SerializeMap;
    use std::fmt;

    pub fn serialize<S>(map: &HashMap<Selector, Vec<PrefetchItem>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut keys: Vec<&Selector> = map.keys().collect();
        keys.sort_by(|a, b| match (a, b) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(a), Some(b)) => a.as_slice().cmp(b.as_slice()),
        });

        let mut m = serializer.serialize_map(Some(map.len()))?;
        for key in keys {
            let key_str = match key {
                Some(sel) => format!("0x{}", hex::encode(sel)),
                None => "*".to_string(),
            };
            m.serialize_entry(&key_str, &map[key])?;
        }
        m.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<Selector, Vec<PrefetchItem>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SelectorMapVisitor;

        impl<'de> Visitor<'de> for SelectorMapVisitor {
            type Value = HashMap<Selector, Vec<PrefetchItem>>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map with selector keys")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = HashMap::with_capacity(access.size_hint().unwrap_or(0));
                while let Some((key, value)) = access.next_entry::<String, Vec<PrefetchItem>>()? {
                    let selector = if key == "*" {
                        None
                    } else {
                        let hex_str = key.strip_prefix("0x").unwrap_or(&key);
                        let bytes = hex::decode(hex_str).map_err(de::Error::custom)?;
                        if bytes.len() != 4 {
                            return Err(de::Error::custom("selector must be 4 bytes"));
                        }
                        Some(FixedBytes::<4>::from_slice(&bytes))
                    };
                    map.insert(selector, value);
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(SelectorMapVisitor)
    }
}

/// Identifies a call target + function selector.
/// Used by the recording inspector to tag recorded accesses by call context.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallKey {
    pub address: Address,
    /// `None` means "any call to this address".
    pub selector: Option<FixedBytes<4>>,
}

/// How a storage slot is determined — an expression tree describing how to
/// compute the concrete slot key from runtime inputs (calldata, caller, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SlotExpression {
    /// A known, constant value.
    Concrete { value: B256 },

    /// 32 bytes of calldata at the given byte offset (includes the 4-byte selector,
    /// so offset 4 = first ABI argument).
    CalldataWord { offset: usize },

    /// `msg.sender`, left-padded to 32 bytes.
    Caller,

    /// `keccak256(concat(inputs))` where each input is padded to 32 bytes.
    Keccak256 { inputs: Vec<SlotExpression> },

    /// Arithmetic addition of two expressions.
    Add {
        left: Box<SlotExpression>,
        right: Box<SlotExpression>,
    },

    /// A dependent storage read — may not be resolvable at prefetch time.
    SLoad { key: Box<SlotExpression> },
}

/// A single prefetch target.
///
/// Storage items are relative to their containing address context in the hint
/// table — the target address is implicit from the `HintTable` key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum PrefetchItem {
    /// Load account info (balance, nonce, code hash) for an address.
    /// Used for cross-contract references (e.g., token addresses referenced by a router).
    /// When `selector` is present, the prefetcher can chain-lookup the target's
    /// hint table to also prefetch its storage slots.
    Account {
        address: Address,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<FixedBytes<4>>,
    },

    /// Load a storage slot on the current contract.
    Storage { slot: SlotExpression },

    /// Load account info for a computed address (e.g., CREATE2-derived pool addresses).
    /// The address is determined by evaluating the expression at runtime.
    /// When `selector` is present, the prefetcher can chain-lookup the target's
    /// hint table to also prefetch its storage slots.
    ComputedAccount {
        address: SlotExpression,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<FixedBytes<4>>,
    },
}

/// A selector key: either a specific 4-byte selector or a wildcard (None = any call).
pub type Selector = Option<FixedBytes<4>>;

/// Per-address hint entries: selector → items.
pub type SelectorMap = HashMap<Selector, Vec<PrefetchItem>>;

/// Metadata about a hint table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HintTableMetadata {
    /// Human-readable description.
    #[serde(default)]
    pub description: String,

    /// Source of the hints (e.g., "bytecode-analysis", "trace-inference", "manual").
    #[serde(default)]
    pub source: String,

    /// Contract name, if known.
    #[serde(default)]
    pub contract_name: Option<String>,
}

/// Complete hint table: code_hash → selector → prefetch items.
///
/// Entries are keyed by bytecode hash so that all contracts sharing the same
/// code (e.g., Uniswap V2 pairs) share a single set of hints. The `code_hashes`
/// map records which addresses map to which code hash, enabling address-based
/// lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintTable {
    pub version: u32,
    pub metadata: HintTableMetadata,
    #[serde(with = "hint_entries_serde")]
    pub entries: HashMap<B256, SelectorMap>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub code_hashes: HashMap<Address, B256>,
}

/// Custom serde for the outer entries map so each inner SelectorMap uses
/// the `selector_map_serde` logic (wildcard = `"*"`).
/// Keys are `B256` code hashes, serialized as `"0x..."` hex strings.
mod hint_entries_serde {
    use super::*;
    use serde::de::{self, MapAccess, Visitor};
    use serde::ser::SerializeMap;
    use std::fmt;

    pub fn serialize<S>(entries: &HashMap<B256, SelectorMap>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Wrapper<'a>(#[serde(serialize_with = "selector_map_serde::serialize")] &'a SelectorMap);

        let mut hashes: Vec<&B256> = entries.keys().collect();
        hashes.sort();

        let mut m = serializer.serialize_map(Some(entries.len()))?;
        for hash in hashes {
            let key_str = format!("0x{}", hex::encode(hash));
            m.serialize_entry(&key_str, &Wrapper(&entries[hash]))?;
        }
        m.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<B256, SelectorMap>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EntriesVisitor;

        impl<'de> Visitor<'de> for EntriesVisitor {
            type Value = HashMap<B256, SelectorMap>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a map of code_hash -> selector map")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                #[derive(Deserialize)]
                struct Wrapper(#[serde(deserialize_with = "selector_map_serde::deserialize")] SelectorMap);

                let mut map = HashMap::with_capacity(access.size_hint().unwrap_or(0));
                while let Some((key, wrapper)) = access.next_entry::<String, Wrapper>()? {
                    let hex_str = key.strip_prefix("0x").unwrap_or(&key);
                    let bytes = hex::decode(hex_str).map_err(de::Error::custom)?;
                    if bytes.len() != 32 {
                        return Err(de::Error::custom("code hash must be 32 bytes"));
                    }
                    let hash = B256::from_slice(&bytes);
                    map.insert(hash, wrapper.0);
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(EntriesVisitor)
    }
}

impl HintTable {
    pub fn new() -> Self {
        Self {
            version: 1,
            metadata: HintTableMetadata::default(),
            entries: HashMap::new(),
            code_hashes: HashMap::new(),
        }
    }

    /// Look up prefetch items for a call. Resolves address → code_hash first,
    /// then tries exact selector match, then falls back to wildcard (None).
    pub fn lookup(&self, address: Address, selector: Selector) -> Option<&[PrefetchItem]> {
        let code_hash = self.code_hashes.get(&address)?;
        let selector_map = self.entries.get(code_hash)?;
        if let Some(sel) = selector {
            if let Some(items) = selector_map.get(&Some(sel)) {
                return Some(items);
            }
        }
        selector_map.get(&None).map(|v| v.as_slice())
    }

    /// Insert prefetch items for an address + code_hash + selector.
    /// Records the address → code_hash mapping and stores entries under the code_hash.
    pub fn insert(&mut self, address: Address, code_hash: B256, selector: Selector, items: Vec<PrefetchItem>) {
        self.code_hashes.insert(address, code_hash);
        self.entries
            .entry(code_hash)
            .or_default()
            .insert(selector, items);
    }

    /// Insert prefetch items by code hash only (no address association).
    /// Used when trimming or transforming entries without a specific address context.
    pub fn insert_by_hash(&mut self, code_hash: B256, selector: Selector, items: Vec<PrefetchItem>) {
        self.entries
            .entry(code_hash)
            .or_default()
            .insert(selector, items);
    }

    /// Register an address → code_hash mapping without inserting entries.
    pub fn register_code_hash(&mut self, address: Address, code_hash: B256) {
        self.code_hashes.insert(address, code_hash);
    }

    /// Check whether entries already exist for a given code hash.
    pub fn has_code_hash(&self, hash: &B256) -> bool {
        self.entries.contains_key(hash)
    }

    /// Merge another hint table into this one. Entries from `other` override on conflict.
    pub fn merge(&mut self, other: HintTable) {
        for (hash, sel_map) in other.entries {
            let entry = self.entries.entry(hash).or_default();
            for (sel, items) in sel_map {
                entry.insert(sel, items);
            }
        }
        for (addr, hash) in other.code_hashes {
            self.code_hashes.insert(addr, hash);
        }
    }

    /// Total number of selector entries across all code hashes.
    pub fn selector_count(&self) -> usize {
        self.entries.values().map(|m| m.len()).sum()
    }

    /// Total number of prefetch items across all entries.
    pub fn item_count(&self) -> usize {
        self.entries
            .values()
            .flat_map(|m| m.values())
            .map(|items| items.len())
            .sum()
    }

    /// All addresses associated with a given code hash.
    pub fn addresses_for_hash(&self, hash: &B256) -> Vec<Address> {
        let mut addrs: Vec<Address> = self.code_hashes
            .iter()
            .filter(|(_, h)| *h == hash)
            .map(|(a, _)| *a)
            .collect();
        addrs.sort();
        addrs
    }

    /// All unique code hashes, sorted.
    pub fn sorted_code_hashes(&self) -> Vec<B256> {
        let mut hashes: Vec<B256> = self.entries.keys().copied().collect();
        hashes.sort();
        hashes
    }
}

impl Default for HintTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Score of how well a hint table predicted actual accesses.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HintScore {
    /// Number of predicted accesses that were actually used.
    pub hits: u64,
    /// Number of predicted accesses that were NOT used.
    pub misses: u64,
    /// Number of actual accesses that were NOT predicted.
    pub uncovered: u64,
}

impl HintScore {
    /// Precision: hits / (hits + misses). Returns 0 if no predictions.
    pub fn precision(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0.0;
        }
        self.hits as f64 / total as f64
    }

    /// Recall: hits / (hits + uncovered). Returns 0 if no actual accesses.
    pub fn recall(&self) -> f64 {
        let total = self.hits + self.uncovered;
        if total == 0 {
            return 0.0;
        }
        self.hits as f64 / total as f64
    }
}

/// Runtime statistics from the prefetch inspector.
#[derive(Debug, Clone, Default)]
pub struct PrefetchStats {
    /// Number of calls where hints were found and prefetching was attempted.
    pub calls_with_hints: u64,
    /// Number of calls where no hints existed.
    pub calls_without_hints: u64,
    /// Number of individual items successfully prefetched.
    pub items_prefetched: u64,
    /// Number of prefetch attempts that failed (DB error, slot resolution failure).
    pub items_failed: u64,
}

/// A recorded storage/account access from the recording inspector.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RecordedAccess {
    Account(Address),
    Storage { address: Address, slot: B256 },
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    const DUMMY_HASH: B256 = B256::repeat_byte(0xAB);

    #[test]
    fn serde_roundtrip_hint_table() {
        let mut table = HintTable::new();
        table.metadata.description = "test".into();
        table.metadata.source = "manual".into();

        let addr = address!("0xdead000000000000000000000000000000000001");
        table.insert(
            addr,
            DUMMY_HASH,
            Some(FixedBytes::from([0xa9, 0x05, 0x9c, 0xbb])),
            vec![
                PrefetchItem::Storage {
                    slot: SlotExpression::Keccak256 {
                        inputs: vec![
                            SlotExpression::CalldataWord { offset: 4 },
                            SlotExpression::Concrete { value: B256::ZERO },
                        ],
                    },
                },
                PrefetchItem::Account {
                    address: address!("0x0000000000000000000000000000000000000002"),
                    selector: None,
                },
                PrefetchItem::ComputedAccount {
                    address: SlotExpression::Keccak256 {
                        inputs: vec![
                            SlotExpression::CalldataWord { offset: 4 },
                            SlotExpression::Concrete { value: B256::with_last_byte(1) },
                        ],
                    },
                    selector: None,
                },
            ],
        );

        let json = serde_json::to_string_pretty(&table).unwrap();
        let restored: HintTable = serde_json::from_str(&json).unwrap();

        assert_eq!(table.version, restored.version);
        assert_eq!(table.selector_count(), restored.selector_count());
    }

    #[test]
    fn hint_table_lookup_fallback() {
        let mut table = HintTable::new();
        let addr = address!("0xdead000000000000000000000000000000000001");

        // Insert wildcard entry
        table.insert(
            addr,
            DUMMY_HASH,
            None,
            vec![PrefetchItem::Account { address: addr, selector: None }],
        );

        // Should find via wildcard
        let sel = FixedBytes::from([0x01, 0x02, 0x03, 0x04]);
        assert!(table.lookup(addr, Some(sel)).is_some());
        assert!(table.lookup(addr, None).is_some());

        // Insert specific selector
        table.insert(
            addr,
            DUMMY_HASH,
            Some(sel),
            vec![PrefetchItem::Storage {
                slot: SlotExpression::Concrete { value: B256::ZERO },
            }],
        );

        // Specific should take priority
        let items = table.lookup(addr, Some(sel)).unwrap();
        assert!(matches!(items[0], PrefetchItem::Storage { .. }));
    }

    #[test]
    fn hint_score_math() {
        let score = HintScore {
            hits: 8,
            misses: 2,
            uncovered: 4,
        };
        assert!((score.precision() - 0.8).abs() < f64::EPSILON);
        assert!((score.recall() - (8.0 / 12.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn serde_slot_expression_variants() {
        let exprs = vec![
            SlotExpression::Concrete {
                value: B256::with_last_byte(5),
            },
            SlotExpression::CalldataWord { offset: 4 },
            SlotExpression::Caller,
            SlotExpression::Keccak256 {
                inputs: vec![
                    SlotExpression::CalldataWord { offset: 4 },
                    SlotExpression::Concrete {
                        value: B256::with_last_byte(1),
                    },
                ],
            },
            SlotExpression::Keccak256 {
                inputs: vec![
                    SlotExpression::CalldataWord { offset: 36 },
                    SlotExpression::Keccak256 {
                        inputs: vec![
                            SlotExpression::CalldataWord { offset: 4 },
                            SlotExpression::Concrete {
                                value: B256::with_last_byte(2),
                            },
                        ],
                    },
                ],
            },
            SlotExpression::Add {
                left: Box::new(SlotExpression::Concrete {
                    value: B256::with_last_byte(3),
                }),
                right: Box::new(SlotExpression::Concrete {
                    value: B256::with_last_byte(1),
                }),
            },
            SlotExpression::SLoad {
                key: Box::new(SlotExpression::Concrete {
                    value: B256::with_last_byte(7),
                }),
            },
        ];

        for expr in &exprs {
            let json = serde_json::to_string(expr).unwrap();
            let restored: SlotExpression = serde_json::from_str(&json).unwrap();
            assert_eq!(*expr, restored);
        }
    }

    /// Wildcard (None) selector keys must serialize as "*" and roundtrip.
    /// Regression: None can't be a JSON object key without custom serde.
    #[test]
    fn serde_roundtrip_wildcard_selector() {
        let mut table = HintTable::new();
        let addr = address!("0xdead000000000000000000000000000000000001");

        // Insert both a wildcard and a specific selector
        table.insert(
            addr,
            DUMMY_HASH,
            None,
            vec![PrefetchItem::Storage {
                slot: SlotExpression::Concrete { value: B256::with_last_byte(99) },
            }],
        );
        table.insert(
            addr,
            DUMMY_HASH,
            Some(FixedBytes::from([0xaa, 0xbb, 0xcc, 0xdd])),
            vec![PrefetchItem::Storage {
                slot: SlotExpression::Concrete { value: B256::with_last_byte(1) },
            }],
        );

        let json = serde_json::to_string_pretty(&table).unwrap();

        // Wildcard should serialize as "*"
        assert!(json.contains("\"*\""), "Wildcard key should serialize as \"*\", got:\n{json}");
        // Specific selector should serialize as hex
        assert!(json.contains("\"0xaabbccdd\""), "Selector key should serialize as hex, got:\n{json}");

        // Roundtrip
        let restored: HintTable = serde_json::from_str(&json).unwrap();
        assert_eq!(table.selector_count(), restored.selector_count());
        assert_eq!(table.item_count(), restored.item_count());

        // Lookup should work on restored table
        assert!(restored.lookup(addr, None).is_some());
        assert!(restored.lookup(addr, Some(FixedBytes::from([0xaa, 0xbb, 0xcc, 0xdd]))).is_some());
    }

    /// Account items with selector field must roundtrip through JSON.
    #[test]
    fn serde_roundtrip_account_with_selector() {
        let mut table = HintTable::new();
        let addr = address!("0xdead000000000000000000000000000000000001");
        let target = address!("0x0000000000000000000000000000000000C0FFEE");

        table.insert(
            addr,
            DUMMY_HASH,
            Some(FixedBytes::from([0xaa, 0xbb, 0xcc, 0xdd])),
            vec![
                PrefetchItem::Account { address: target, selector: None },
                PrefetchItem::Account {
                    address: target,
                    selector: Some(FixedBytes::from([0x70, 0xa0, 0x82, 0x31])),
                },
            ],
        );

        let json = serde_json::to_string_pretty(&table).unwrap();

        // selector: None should be omitted (skip_serializing_if)
        // selector: Some should be present
        assert!(json.contains("0x70a08231"), "Account selector should appear in JSON");

        let restored: HintTable = serde_json::from_str(&json).unwrap();
        let items = restored.lookup(addr, Some(FixedBytes::from([0xaa, 0xbb, 0xcc, 0xdd]))).unwrap();
        assert_eq!(items.len(), 2);
        assert!(matches!(&items[0], PrefetchItem::Account { selector: None, .. }));
        assert!(matches!(&items[1], PrefetchItem::Account { selector: Some(s), .. } if *s == FixedBytes::from([0x70, 0xa0, 0x82, 0x31])));
    }

    /// Serializing the same table twice must produce identical output (deterministic ordering).
    #[test]
    fn serde_deterministic_output() {
        let mut table = HintTable::new();

        // Insert entries in deliberately varied order across multiple code hashes/selectors
        let addr_a = address!("0xaaaa000000000000000000000000000000000001");
        let addr_b = address!("0x1111000000000000000000000000000000000001");
        let hash_a = B256::repeat_byte(0xAA);
        let hash_b = B256::repeat_byte(0x11);

        table.insert(
            addr_a,
            hash_a,
            Some(FixedBytes::from([0xdd, 0xcc, 0xbb, 0xaa])),
            vec![PrefetchItem::Storage { slot: SlotExpression::Concrete { value: B256::with_last_byte(1) } }],
        );
        table.insert(
            addr_a,
            hash_a,
            Some(FixedBytes::from([0x11, 0x22, 0x33, 0x44])),
            vec![PrefetchItem::Storage { slot: SlotExpression::Concrete { value: B256::with_last_byte(2) } }],
        );
        table.insert(
            addr_a,
            hash_a,
            None,
            vec![PrefetchItem::Storage { slot: SlotExpression::Concrete { value: B256::with_last_byte(3) } }],
        );
        table.insert(
            addr_b,
            hash_b,
            Some(FixedBytes::from([0xff, 0xee, 0xdd, 0xcc])),
            vec![PrefetchItem::Storage { slot: SlotExpression::Concrete { value: B256::with_last_byte(4) } }],
        );

        let json1 = serde_json::to_string_pretty(&table).unwrap();
        let json2 = serde_json::to_string_pretty(&table).unwrap();
        assert_eq!(json1, json2, "Two serializations of the same table must be identical");
    }
}
