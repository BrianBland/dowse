use alloy_primitives::{Address, B256, U256, keccak256};
use dowse_types::SlotExpression;

/// Runtime context needed to resolve slot expressions into concrete keys.
pub struct ResolutionContext<'a> {
    /// Full calldata including 4-byte selector.
    pub calldata: &'a [u8],
    /// The caller (msg.sender) of the transaction.
    pub caller: Address,
}

/// Resolve a `SlotExpression` to a concrete storage key.
///
/// Returns `None` if the expression cannot be resolved (e.g., calldata too short,
/// or it depends on an `SLoad` which requires prior state).
pub fn resolve_slot(expr: &SlotExpression, ctx: &ResolutionContext) -> Option<U256> {
    match expr {
        SlotExpression::Concrete { value } => Some((*value).into()),

        SlotExpression::CalldataWord { offset } => {
            let start = *offset;
            let end = start + 32;
            if ctx.calldata.len() < end {
                return None;
            }
            let word = B256::from_slice(&ctx.calldata[start..end]);
            Some(word.into())
        }

        SlotExpression::Caller => {
            // Left-pad the 20-byte address to 32 bytes.
            let mut buf = [0u8; 32];
            buf[12..32].copy_from_slice(ctx.caller.as_slice());
            Some(B256::from(buf).into())
        }

        SlotExpression::Keccak256 { inputs } => {
            let mut preimage = Vec::new();
            for input in inputs {
                let val = resolve_slot(input, ctx)?;
                preimage.extend_from_slice(&B256::from(val).0);
            }
            Some(keccak256(&preimage).into())
        }

        SlotExpression::Add { left, right } => {
            let l = resolve_slot(left, ctx)?;
            let r = resolve_slot(right, ctx)?;
            Some(l + r)
        }

        SlotExpression::SLoad { .. } => {
            // Can't resolve dependent reads at prefetch time without prior state.
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};

    fn ctx_with_calldata(calldata: &[u8]) -> ResolutionContext {
        ResolutionContext {
            calldata,
            caller: Address::ZERO,
        }
    }

    #[test]
    fn concrete_slot_resolution() {
        let expr = SlotExpression::Concrete {
            value: b256!("0x0000000000000000000000000000000000000000000000000000000000000005"),
        };
        let ctx = ctx_with_calldata(&[]);
        let result = resolve_slot(&expr, &ctx).unwrap();
        assert_eq!(result, U256::from(5));
    }

    #[test]
    fn calldata_word_resolution() {
        // CalldataWord at offset 4 (first arg after selector)
        let expr = SlotExpression::CalldataWord { offset: 4 };

        let mut calldata = vec![0xa9, 0x05, 0x9c, 0xbb]; // selector
        let mut addr_padded = vec![0u8; 31];
        addr_padded.push(0x01);
        calldata.extend_from_slice(&addr_padded);

        let ctx = ctx_with_calldata(&calldata);
        let result = resolve_slot(&expr, &ctx).unwrap();
        assert_eq!(result, U256::from(1));
    }

    #[test]
    fn caller_resolution() {
        let expr = SlotExpression::Caller;
        let caller = address!("0x000000000000000000000000000000000000abcd");
        let ctx = ResolutionContext {
            calldata: &[],
            caller,
        };
        let result = resolve_slot(&expr, &ctx).unwrap();
        // Should be left-padded address
        let mut expected = [0u8; 32];
        expected[12..32].copy_from_slice(caller.as_slice());
        assert_eq!(result, U256::from_be_bytes(expected));
    }

    #[test]
    fn mapping_slot_resolution() {
        // balanceOf(address): keccak256(pad32(arg0) ++ pad32(base_slot_0))
        let expr = SlotExpression::Keccak256 {
            inputs: vec![
                SlotExpression::CalldataWord { offset: 4 },
                SlotExpression::Concrete {
                    value: B256::ZERO,
                },
            ],
        };

        let mut calldata = vec![0xa9, 0x05, 0x9c, 0xbb]; // selector
        let mut addr_padded = vec![0u8; 31];
        addr_padded.push(0x01); // address = 0x...01
        calldata.extend_from_slice(&addr_padded);

        let ctx = ctx_with_calldata(&calldata);
        let result = resolve_slot(&expr, &ctx).unwrap();

        // Manually compute expected: keccak256(pad32(0x01) ++ pad32(0x00))
        let mut preimage = vec![0u8; 64];
        preimage[31] = 0x01; // key
        // base_slot is all zeros
        let expected: U256 = keccak256(&preimage).into();
        assert_eq!(result, expected);
    }

    #[test]
    fn nested_mapping_resolution() {
        // allowance(owner, spender) = keccak256(spender ++ keccak256(owner ++ base_slot_1))
        let expr = SlotExpression::Keccak256 {
            inputs: vec![
                SlotExpression::CalldataWord { offset: 36 }, // spender (2nd arg)
                SlotExpression::Keccak256 {
                    inputs: vec![
                        SlotExpression::CalldataWord { offset: 4 }, // owner (1st arg)
                        SlotExpression::Concrete {
                            value: B256::with_last_byte(1),
                        },
                    ],
                },
            ],
        };

        let mut calldata = vec![0xdd, 0x62, 0xed, 0x3e]; // allowance selector
        let mut owner = vec![0u8; 32];
        owner[31] = 0xAA;
        let mut spender = vec![0u8; 32];
        spender[31] = 0xBB;
        calldata.extend_from_slice(&owner);
        calldata.extend_from_slice(&spender);

        let ctx = ctx_with_calldata(&calldata);
        let result = resolve_slot(&expr, &ctx);
        assert!(result.is_some());
    }

    #[test]
    fn add_resolution() {
        let expr = SlotExpression::Add {
            left: Box::new(SlotExpression::Concrete {
                value: B256::with_last_byte(10),
            }),
            right: Box::new(SlotExpression::Concrete {
                value: B256::with_last_byte(3),
            }),
        };
        let ctx = ctx_with_calldata(&[]);
        let result = resolve_slot(&expr, &ctx).unwrap();
        assert_eq!(result, U256::from(13));
    }

    #[test]
    fn sload_returns_none() {
        let expr = SlotExpression::SLoad {
            key: Box::new(SlotExpression::Concrete {
                value: B256::with_last_byte(5),
            }),
        };
        let ctx = ctx_with_calldata(&[]);
        assert!(resolve_slot(&expr, &ctx).is_none());
    }

    #[test]
    fn short_calldata_returns_none() {
        let expr = SlotExpression::CalldataWord { offset: 4 };
        // Only 4-byte selector, no actual arg data
        let calldata = vec![0x01, 0x02, 0x03, 0x04];
        let ctx = ctx_with_calldata(&calldata);
        assert!(resolve_slot(&expr, &ctx).is_none());
    }

    #[test]
    fn caller_mapping_resolution() {
        // keccak256(caller ++ base_slot_9) — e.g., blacklist[msg.sender]
        let expr = SlotExpression::Keccak256 {
            inputs: vec![
                SlotExpression::Caller,
                SlotExpression::Concrete {
                    value: B256::with_last_byte(9),
                },
            ],
        };

        let caller = address!("0x00000000000000000000000000000000deadbeef");
        let ctx = ResolutionContext {
            calldata: &[],
            caller,
        };
        let result = resolve_slot(&expr, &ctx);
        assert!(result.is_some());
    }
}
