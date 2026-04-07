use alloy_primitives::{Address, B256, U256, uint};

/// EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
pub const EIP1967_IMPL_SLOT: U256 =
    uint!(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc_U256);

/// OZ legacy implementation slot: keccak256("org.zeppelinos.proxy.implementation")
pub const OZ_LEGACY_IMPL_SLOT: U256 =
    uint!(0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3_U256);

/// EIP-1967 beacon slot: keccak256("eip1967.proxy.beacon") - 1
pub const EIP1967_BEACON_SLOT: U256 =
    uint!(0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50_U256);

/// Extract an address from a storage value (last 20 bytes), returning None if zero.
fn addr_from_storage(val: U256) -> Option<Address> {
    if val == U256::ZERO {
        return None;
    }
    let bytes: B256 = val.into();
    let addr = Address::from_slice(&bytes.as_slice()[12..]);
    if addr == Address::ZERO {
        None
    } else {
        Some(addr)
    }
}

/// Result of proxy detection, indicating which pattern matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyResult {
    /// Direct implementation (EIP-1967 or OZ legacy).
    Implementation(Address),
    /// Beacon proxy: the beacon address and the resolved implementation.
    Beacon {
        beacon: Address,
        implementation: Address,
    },
}

impl ProxyResult {
    /// The implementation address to analyze, regardless of proxy pattern.
    pub fn implementation(&self) -> Address {
        match self {
            ProxyResult::Implementation(addr) => *addr,
            ProxyResult::Beacon { implementation, .. } => *implementation,
        }
    }
}

/// Detect proxy implementation address by reading known storage slots.
///
/// Checks EIP-1967, OZ legacy, and EIP-1967 beacon patterns. For beacon
/// proxies, reads the beacon's EIP-1967 implementation slot to resolve the
/// final implementation address.
///
/// The `read_storage` function should return the `U256` value at the given
/// `(address, slot)`, or `None` if the read failed. This keeps dowse-core
/// sync and provider-agnostic — callers wrap their async provider.
pub fn detect_proxy(
    address: Address,
    read_storage: impl Fn(Address, U256) -> Option<U256>,
) -> Option<ProxyResult> {
    // Try direct implementation slots first
    for slot in [EIP1967_IMPL_SLOT, OZ_LEGACY_IMPL_SLOT] {
        if let Some(val) = read_storage(address, slot) {
            if let Some(addr) = addr_from_storage(val) {
                return Some(ProxyResult::Implementation(addr));
            }
        }
    }

    // Try beacon pattern: slot holds beacon address, beacon's EIP-1967 slot holds impl
    if let Some(val) = read_storage(address, EIP1967_BEACON_SLOT) {
        if let Some(beacon) = addr_from_storage(val) {
            if let Some(impl_val) = read_storage(beacon, EIP1967_IMPL_SLOT) {
                if let Some(implementation) = addr_from_storage(impl_val) {
                    return Some(ProxyResult::Beacon {
                        beacon,
                        implementation,
                    });
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn addr_to_u256(addr: Address) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[12..].copy_from_slice(addr.as_slice());
        U256::from_be_bytes(bytes)
    }

    #[test]
    fn detects_eip1967_proxy() {
        let proxy_addr = address!("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
        let impl_addr = address!("0x0000000000000000000000000000000000C0FFEE");

        let result = detect_proxy(proxy_addr, |_addr, slot| {
            if slot == EIP1967_IMPL_SLOT {
                Some(addr_to_u256(impl_addr))
            } else {
                Some(U256::ZERO)
            }
        });

        assert_eq!(result, Some(ProxyResult::Implementation(impl_addr)));
    }

    #[test]
    fn detects_beacon_proxy() {
        let proxy_addr = address!("0xaaaa000000000000000000000000000000000001");
        let beacon_addr = address!("0xbbbb000000000000000000000000000000000002");
        let impl_addr = address!("0xcccc000000000000000000000000000000000003");

        let result = detect_proxy(proxy_addr, |addr, slot| {
            if addr == proxy_addr && slot == EIP1967_BEACON_SLOT {
                Some(addr_to_u256(beacon_addr))
            } else if addr == beacon_addr && slot == EIP1967_IMPL_SLOT {
                Some(addr_to_u256(impl_addr))
            } else {
                Some(U256::ZERO)
            }
        });

        assert_eq!(
            result,
            Some(ProxyResult::Beacon {
                beacon: beacon_addr,
                implementation: impl_addr,
            })
        );
        assert_eq!(result.unwrap().implementation(), impl_addr);
    }

    #[test]
    fn returns_none_for_non_proxy() {
        let addr = address!("0x4200000000000000000000000000000000000006");
        let result = detect_proxy(addr, |_, _| Some(U256::ZERO));
        assert_eq!(result, None);
    }

    #[test]
    fn returns_none_when_storage_reads_fail() {
        let addr = address!("0x4200000000000000000000000000000000000006");
        let result = detect_proxy(addr, |_, _| None);
        assert_eq!(result, None);
    }

    #[test]
    fn eip1967_takes_priority_over_beacon() {
        let proxy_addr = address!("0xaaaa000000000000000000000000000000000001");
        let impl_addr = address!("0xcccc000000000000000000000000000000000003");

        // Both EIP-1967 impl slot and beacon slot are set — impl wins
        let result = detect_proxy(proxy_addr, |_addr, slot| {
            if slot == EIP1967_IMPL_SLOT {
                Some(addr_to_u256(impl_addr))
            } else if slot == EIP1967_BEACON_SLOT {
                Some(addr_to_u256(address!("0xbbbb000000000000000000000000000000000002")))
            } else {
                Some(U256::ZERO)
            }
        });

        assert_eq!(result, Some(ProxyResult::Implementation(impl_addr)));
    }
}
