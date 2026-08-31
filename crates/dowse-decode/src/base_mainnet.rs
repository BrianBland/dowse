use alloy_primitives::{address, b256, keccak256, Address, B256, U256};
use dowse_plan::{PlanLimits, PrefetchPlan, StorageTarget};

use crate::abi::{
    address_array, address_word, array, b256_word, bool_word, bytes, bytes_array, tuple_array,
    usize_word, word,
};

const MAX_NESTING: usize = 4;
const MAX_INNER_CALLS: usize = 128;
const MAX_PATH_TOKENS: usize = 32;

const USDC: Address = address!("833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
const WETH: Address = address!("4200000000000000000000000000000000000006");
const CBBTC: Address = address!("cbB7C0000aB88B473b1f5aFd9ef808440eed33Bf");
const PERMIT2: Address = address!("000000000022D473030F116dDEE9F6B43aC78BA3");
const ALLOWANCE_HOLDER: Address = address!("0000000000001fF3684f28c67538d4D072C22734");
const UNISWAP_V3_FACTORY: Address = address!("33128a8fC17869897dcE68Ed026d694621f6FDfD");
const UNISWAP_V3_ROUTER: Address = address!("2626664c2603336E57B271c5C0b26F421741e481");
const UNIVERSAL_ROUTER: Address = address!("6fF5693b99212Da76ad316178A184AB56D299b43");
const UNIVERSAL_ROUTER_2: Address = address!("Fdf682F51FE81Aa4898F0AE2163d8A55c127fbC7");
const UNISWAP_V4_POOL_MANAGER: Address = address!("498581ff718922c3f8e6a244956af099b2652b2b");
const AERODROME_ROUTER: Address = address!("cF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43");
const SLIPSTREAM_ROUTER: Address = address!("BE6D8f0d05cC4be24d5167a3eF062215bE6D18a5");
const SLIPSTREAM_ROUTER_2: Address = address!("cbBb8035cAc7D4B3Ca7aBb74cF7BdF900215Ce0D");
const WORD_BATCH_TRANSFER: Address = address!("C3236716cbDC725b518AC0A5d830FBaDcfd05032");
const PACKED_BATCH_TRANSFER: Address = address!("fA4071b58D87cBc7aF904F4C02F64318167655a2");
const ABI_BATCH_TRANSFER: Address = address!("95562A1bDb6e3C94cB169346a5DA41ac7EfCD36c");
const ENTRY_POINT_V6: Address = address!("5FF137D4b0FDCD49DcA30c7CF57E578a026d2789");
const ENTRY_POINT_V7: Address = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");
const ENTRY_POINT_V8: Address = address!("4337084D9E255Ff0702461CF8895CE9E3b5Ff108");
const SURPLUS_SETTLEMENT_V2: Address = address!("0770d2124C0a581C28Cfc47a659817145e6Cc137");
const RELAY_APPROVAL_PROXY_V3: Address = address!("CcC88a9d1B4ED6b0EABA998850414b24f1c315bE");
const RELAY_ROUTER_V3: Address = address!("b92fe925DC43a0ECdE6c8b1a2709c170Ec4fFf4f");
const LIMITLESS_FEE_MODULE: Address = address!("F94ef760884b0605E433853Aed17DA574160226E");
const LIMITLESS_EXCHANGE: Address = address!("05c748E2f4DcDe0ec9Fa8DDc40DE6b867f923fa5");
const KYBER_ROUTER: Address = address!("6131B5fae19EA4f9D964eAc0408E4408b66337b5");
const OKX_ROUTER: Address = address!("67d03631FE51B741C0C00c4E16eb662AC84381df");
const MSG_SENDER: Address = address!("0000000000000000000000000000000000000001");
const ADDRESS_THIS: Address = address!("0000000000000000000000000000000000000002");
const UNISWAP_V3_POOL_INIT_CODE_HASH: B256 = B256::new([
    0xe3, 0x4f, 0x19, 0x9b, 0x19, 0xb2, 0xb4, 0xf4, 0x7f, 0x68, 0x44, 0x26, 0x19, 0xd5, 0x55, 0x52,
    0x7d, 0x24, 0x4f, 0x78, 0xa3, 0x29, 0x7e, 0xa8, 0x93, 0x25, 0xf8, 0x43, 0xf8, 0x7b, 0x8b, 0x54,
]);
const B20_STORAGE_ROOT: B256 =
    b256!("c78b71fee795ddd74aff64ea9b2474194c938c3196430e10bb5f01ed48434000");

const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const INCREASE_ALLOWANCE: [u8; 4] = [0x39, 0x50, 0x93, 0x51];
const DECREASE_ALLOWANCE: [u8; 4] = [0xa4, 0x57, 0xc2, 0xd7];
const PERMIT: [u8; 4] = [0xd5, 0x05, 0xac, 0xcf];
const TRANSFER_WITH_AUTHORIZATION: [u8; 4] = [0xe3, 0xee, 0x16, 0x0e];
const RECEIVE_WITH_AUTHORIZATION: [u8; 4] = [0xef, 0x55, 0xbe, 0xc6];
const CANCEL_AUTHORIZATION: [u8; 4] = [0x5a, 0x04, 0x9a, 0x70];
const DEPOSIT: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];
const WITHDRAW: [u8; 4] = [0x2e, 0x1a, 0x7d, 0x4d];

const V3_EXACT_INPUT_SINGLE: [u8; 4] = [0x04, 0xe4, 0x5a, 0xaf];
const V3_EXACT_INPUT: [u8; 4] = [0xb8, 0x58, 0x18, 0x3f];
const V3_EXACT_OUTPUT_SINGLE: [u8; 4] = [0x50, 0x23, 0xb4, 0xdf];
const V3_EXACT_OUTPUT: [u8; 4] = [0x09, 0xb8, 0x13, 0x46];
const MULTICALL: [u8; 4] = [0xac, 0x96, 0x50, 0xd8];
const MULTICALL_DEADLINE: [u8; 4] = [0x5a, 0xe4, 0x01, 0xdc];
const MULTICALL_PREVIOUS_BLOCKHASH: [u8; 4] = [0x1f, 0x04, 0x64, 0xd1];
const UNIVERSAL_EXECUTE_DEADLINE: [u8; 4] = [0x35, 0x93, 0x56, 0x4c];
const UNIVERSAL_EXECUTE: [u8; 4] = [0x24, 0x85, 0x6b, 0xc3];

const AERODROME_TOKEN_TO_TOKEN: [u8; 4] = [0xca, 0xc8, 0x8e, 0xa9];
const AERODROME_ETH_TO_TOKEN: [u8; 4] = [0x90, 0x36, 0x38, 0xa4];
const AERODROME_TOKEN_TO_ETH: [u8; 4] = [0xc6, 0xb7, 0xf1, 0xb6];
const SLIPSTREAM_EXACT_INPUT_SINGLE: [u8; 4] = [0xa0, 0x26, 0x38, 0x3e];
const SLIPSTREAM_EXACT_INPUT: [u8; 4] = [0xc0, 0x4b, 0x8d, 0x59];
const SLIPSTREAM_EXACT_OUTPUT_SINGLE: [u8; 4] = [0xc7, 0x14, 0xe8, 0x38];
const SLIPSTREAM_EXACT_OUTPUT: [u8; 4] = [0xf2, 0x8c, 0x04, 0x98];
const BATCH_TRANSFER: [u8; 4] = [0x12, 0x51, 0x4b, 0xba];
const HANDLE_OPS_V6: [u8; 4] = [0x1f, 0xad, 0x94, 0x8c];
const HANDLE_OPS_PACKED: [u8; 4] = [0x76, 0x5e, 0x82, 0x7f];
const ACCOUNT_EXECUTE: [u8; 4] = [0xb6, 0x1d, 0x27, 0xf6];
const ACCOUNT_EXECUTE_USER_OP: [u8; 4] = [0x7b, 0xb3, 0x74, 0x28];
const ACCOUNT_EXECUTE_USER_OP_WITH_ERROR: [u8; 4] = [0x54, 0x1d, 0x63, 0xc8];
const ACCOUNT_EXECUTE_BATCH: [u8; 4] = [0x34, 0xfc, 0xd5, 0xbe];
const ACCOUNT_EXECUTE_BATCH_ARRAYS: [u8; 4] = [0x47, 0xe1, 0xda, 0x2a];
const ACCOUNT_EXECUTE_BATCH_ARRAYS_LEGACY: [u8; 4] = [0x00, 0x00, 0x46, 0x80];
const ACCOUNT_EXECUTE_7579: [u8; 4] = [0xe9, 0xae, 0x5c, 0x53];
const ACCOUNT_EXECUTE_TUPLE: [u8; 4] = [0x5c, 0x1c, 0x6d, 0xcd];
const ACCOUNT_EXECUTE_4337_OPS: [u8; 4] = [0x26, 0xda, 0x7d, 0x88];
const SURPLUS_SETTLE: [u8; 4] = [0x92, 0x66, 0x91, 0x41];
const ALLOWANCE_HOLDER_EXEC: [u8; 4] = [0x22, 0x13, 0xbc, 0x0b];
const SETTLER_EXECUTE: [u8; 4] = [0x1f, 0xff, 0x99, 0x1f];
const SETTLER_BASIC: [u8; 4] = [0x38, 0xc9, 0xc1, 0x47];
const SETTLER_UNISWAP_V3: [u8; 4] = [0x8d, 0x68, 0xa1, 0x56];
const SETTLER_UNISWAP_V3_VIP: [u8; 4] = [0x34, 0xee, 0x90, 0xca];
const SETTLER_TRANSFER_FROM: [u8; 4] = [0xc1, 0xfb, 0x42, 0x5e];
const SETTLER_MAVERICK_V2: [u8; 4] = [0x30, 0x36, 0xd6, 0xa6];
const SETTLER_UNISWAP_V4: [u8; 4] = [0xaf, 0x72, 0x63, 0x4f];
const SETTLER_RFQ: [u8; 4] = [0xd9, 0x2a, 0xad, 0xfb];
const SETTLER_DODO_V2: [u8; 4] = [0x9b, 0x59, 0x75, 0x6f];
const SETTLER_PANCAKE_INFINITY: [u8; 4] = [0xdf, 0x75, 0x3f, 0x1e];
const SETTLER_UNISWAP_V2: [u8; 4] = [0x10, 0x3b, 0x48, 0xbe];
const SETTLER_METATXN_TRANSFER_FROM: [u8; 4] = [0x93, 0x19, 0x97, 0xd3];
const SETTLER_POSITIVE_SLIPPAGE: [u8; 4] = [0x67, 0x03, 0x35, 0xbe];
const SETTLER_BALANCER_V3: [u8; 4] = [0xfd, 0x8c, 0x38, 0xe1];
const RELAY_PERMIT2_TRANSFER_AND_MULTICALL: [u8; 4] = [0x0a, 0x2b, 0x8f, 0x36];
const LIMITLESS_MATCH_ORDERS: [u8; 4] = [0xd2, 0x53, 0x9b, 0x37];
const KYBER_SWAP: [u8; 4] = [0xe2, 0x1f, 0xd0, 0xe9];
const OKX_DAG_SWAP_BY_ORDER_ID: [u8; 4] = [0xf2, 0xc4, 0x26, 0x96];

const LIKELY_CONFIDENCE: f64 = 0.9;
const ROUTER_CONFIDENCE: f64 = 0.6;
const PERMIT2_CONFIDENCE: f64 = 0.4;
const V4_CONFIDENCE: f64 = 0.45;
const AGGREGATOR_CONFIDENCE: f64 = 0.45;
const RELAY_CONFIDENCE: f64 = 0.46;
const LIMITLESS_CONFIDENCE: f64 = 0.8;

/// Deterministic transaction decoder for major Base mainnet tokens and DeFi routers.
#[derive(Debug, Clone, Copy)]
pub struct BaseMainnetDecoder {
    limits: PlanLimits,
}

impl BaseMainnetDecoder {
    /// Creates a decoder with per-transaction target limits.
    pub const fn new(limits: PlanLimits) -> Self {
        Self { limits }
    }

    /// Decodes a top-level call and returns concrete state targets without reading state or
    /// executing EVM bytecode.
    pub fn decode(&self, target: Address, caller: Address, calldata: &[u8]) -> PrefetchPlan {
        let mut plan = PlanAccumulator::default();
        self.decode_call(&mut plan, target, caller, calldata, 0);
        PrefetchPlan::merge([plan.plan], self.limits)
    }

    fn decode_call(
        &self,
        plan: &mut PlanAccumulator,
        target: Address,
        caller: Address,
        calldata: &[u8],
        depth: usize,
    ) {
        if depth > MAX_NESTING || calldata.len() < 4 {
            return;
        }
        let selector: [u8; 4] = calldata[..4].try_into().expect("length checked");
        let body = &calldata[4..];

        if token_layout(target).is_some() {
            self.decode_token(plan, target, caller, selector, body);
        } else if target == UNISWAP_V3_ROUTER {
            self.decode_v3_router(plan, target, caller, selector, body, depth);
        } else if target == UNIVERSAL_ROUTER || target == UNIVERSAL_ROUTER_2 {
            self.decode_universal_router(plan, target, caller, selector, body, depth);
        } else if target == AERODROME_ROUTER {
            self.decode_aerodrome(plan, target, caller, selector, body);
        } else if target == SLIPSTREAM_ROUTER || target == SLIPSTREAM_ROUTER_2 {
            self.decode_slipstream(plan, target, caller, selector, body, depth);
        } else if selector == BATCH_TRANSFER
            && (target == WORD_BATCH_TRANSFER || target == PACKED_BATCH_TRANSFER)
        {
            self.decode_batch_transfers(plan, target, body);
        } else if target == ABI_BATCH_TRANSFER && selector == TRANSFER {
            self.decode_abi_batch_transfers(plan, body);
        } else if matches!(target, ENTRY_POINT_V6 | ENTRY_POINT_V7 | ENTRY_POINT_V8)
            && matches!(selector, HANDLE_OPS_V6 | HANDLE_OPS_PACKED)
        {
            self.decode_entry_point(plan, target, body, depth);
        } else if target == SURPLUS_SETTLEMENT_V2 && selector == SURPLUS_SETTLE {
            self.decode_surplus_settlement(plan, target, body);
        } else if target == ALLOWANCE_HOLDER && selector == ALLOWANCE_HOLDER_EXEC {
            self.decode_allowance_holder(plan, caller, body, depth);
        } else if target == RELAY_APPROVAL_PROXY_V3
            && selector == RELAY_PERMIT2_TRANSFER_AND_MULTICALL
        {
            self.decode_relay_approval_proxy(plan, body, depth);
        } else if target == LIMITLESS_FEE_MODULE && selector == LIMITLESS_MATCH_ORDERS {
            self.decode_limitless_match_orders(plan, caller, body);
        } else if target == KYBER_ROUTER && selector == KYBER_SWAP {
            self.decode_kyber_swap(plan, caller, body, depth);
        } else if target == OKX_ROUTER && selector == OKX_DAG_SWAP_BY_ORDER_ID {
            self.decode_okx_swap(plan, caller, body);
        }
    }

    fn decode_kyber_swap(
        &self,
        plan: &mut PlanAccumulator,
        caller: Address,
        body: &[u8],
        depth: usize,
    ) {
        let Some(execution) = array(body, 0) else {
            return;
        };
        let (Some(call_target), Some(approve_target), Some(target_data), Some(description)) = (
            address_word(execution, 0),
            address_word(execution, 1),
            bytes(execution, 2),
            array(execution, 3),
        ) else {
            return;
        };
        let (Some(source_token), Some(destination_token), Some(destination_receiver)) = (
            address_word(description, 0),
            address_word(description, 1),
            address_word(description, 6),
        ) else {
            return;
        };

        plan.account(KYBER_ROUTER);
        plan.account_with_confidence(call_target, ROUTER_CONFIDENCE);
        plan.account_with_confidence(approve_target, ROUTER_CONFIDENCE);
        plan.balance_with_confidence(source_token, caller, LIKELY_CONFIDENCE);
        plan.spend_allowance_with_confidence(source_token, caller, KYBER_ROUTER, LIKELY_CONFIDENCE);
        plan.balance_with_confidence(source_token, KYBER_ROUTER, ROUTER_CONFIDENCE);
        plan.balance_with_confidence(source_token, call_target, ROUTER_CONFIDENCE);
        plan.allowance_with_confidence(
            source_token,
            KYBER_ROUTER,
            approve_target,
            ROUTER_CONFIDENCE,
        );
        plan.balance_with_confidence(destination_token, destination_receiver, LIKELY_CONFIDENCE);
        plan.balance_with_confidence(destination_token, call_target, ROUTER_CONFIDENCE);
        plan.balance_with_confidence(destination_token, KYBER_ROUTER, ROUTER_CONFIDENCE);

        if let Some(receivers) = address_array(description, 2, MAX_INNER_CALLS) {
            for receiver in receivers {
                plan.balance_with_confidence(source_token, receiver, ROUTER_CONFIDENCE);
            }
        }
        if let Some(receivers) = address_array(description, 4, MAX_INNER_CALLS) {
            for receiver in receivers {
                plan.balance_with_confidence(destination_token, receiver, ROUTER_CONFIDENCE);
            }
        }
        self.decode_call(plan, call_target, KYBER_ROUTER, target_data, depth + 1);
    }

    fn decode_okx_swap(&self, plan: &mut PlanAccumulator, caller: Address, body: &[u8]) {
        let (Some(source_token), Some(destination_token)) =
            (address_word(body, 1), address_word(body, 2))
        else {
            return;
        };

        plan.account(OKX_ROUTER);
        plan.balance_with_confidence(source_token, caller, LIKELY_CONFIDENCE);
        plan.balance_with_confidence(source_token, OKX_ROUTER, ROUTER_CONFIDENCE);
        plan.balance_with_confidence(destination_token, caller, LIKELY_CONFIDENCE);
        plan.balance_with_confidence(destination_token, OKX_ROUTER, ROUTER_CONFIDENCE);

        let Some(paths) = tuple_array(body, 6, MAX_INNER_CALLS) else {
            return;
        };
        for path in paths {
            let Some(path_token) = address_word(path, 4) else {
                continue;
            };
            if let Some(adapters) = address_array(path, 0, MAX_INNER_CALLS) {
                for adapter in adapters {
                    plan.account_with_confidence(adapter, AGGREGATOR_CONFIDENCE);
                }
            }
            if let Some(receivers) = address_array(path, 1, MAX_INNER_CALLS) {
                for receiver in receivers {
                    plan.balance_with_confidence(path_token, receiver, ROUTER_CONFIDENCE);
                }
            }
            let Some(raw_data) = array(path, 2) else {
                continue;
            };
            let Some(length) = usize_word(raw_data, 0).map(|value| value.min(MAX_INNER_CALLS))
            else {
                continue;
            };
            for index in 0..length {
                let Some(pool) = address_word(raw_data, index + 1) else {
                    break;
                };
                plan.account_with_confidence(pool, AGGREGATOR_CONFIDENCE);
                plan.balance_with_confidence(path_token, pool, AGGREGATOR_CONFIDENCE);
            }
        }
    }

    fn decode_limitless_match_orders(
        &self,
        plan: &mut PlanAccumulator,
        caller: Address,
        body: &[u8],
    ) {
        plan.account(LIMITLESS_FEE_MODULE);
        plan.account(LIMITLESS_EXCHANGE);
        plan.account(USDC);
        plan.storage(LIMITLESS_FEE_MODULE, mapping_slot(caller.into_word(), 0));
        plan.balance_with_confidence(USDC, LIMITLESS_FEE_MODULE, ROUTER_CONFIDENCE);

        if let Some(offset) = usize_word(body, 0) {
            if let Some(taker_order) = body.get(offset..) {
                self.decode_limitless_order(plan, taker_order);
            }
        }
        if let Some(maker_orders) = tuple_array(body, 1, MAX_INNER_CALLS) {
            for order in maker_orders {
                self.decode_limitless_order(plan, order);
            }
        }
    }

    fn decode_limitless_order(&self, plan: &mut PlanAccumulator, order: &[u8]) {
        let (Some(maker), Some(side)) = (address_word(order, 1), usize_word(order, 10)) else {
            return;
        };
        plan.balance_with_confidence(USDC, maker, LIMITLESS_CONFIDENCE);
        if side == 0 {
            plan.spend_allowance_with_confidence(
                USDC,
                maker,
                LIMITLESS_EXCHANGE,
                LIMITLESS_CONFIDENCE,
            );
        }
    }

    fn decode_relay_approval_proxy(&self, plan: &mut PlanAccumulator, body: &[u8], depth: usize) {
        let (Some(user), Some(permit), Some(calls)) = (
            address_word(body, 0),
            array(body, 1),
            tuple_array(body, 2, MAX_INNER_CALLS),
        ) else {
            return;
        };
        plan.account(RELAY_APPROVAL_PROXY_V3);
        plan.account(RELAY_ROUTER_V3);
        plan.account(PERMIT2);
        if let Some(permitted) = array(permit, 0) {
            let count = usize_word(permitted, 0)
                .unwrap_or_default()
                .min(MAX_PATH_TOKENS);
            for index in 0..count {
                let Some(token) = address_word(permitted, 1 + index * 2) else {
                    continue;
                };
                plan.balance_with_confidence(token, user, RELAY_CONFIDENCE);
                plan.balance_with_confidence(token, RELAY_ROUTER_V3, RELAY_CONFIDENCE);
                plan.spend_allowance_with_confidence(token, user, PERMIT2, RELAY_CONFIDENCE);
            }
        }
        for call in calls {
            let (Some(target), Some(child)) = (address_word(call, 0), bytes(call, 3)) else {
                continue;
            };
            plan.account(target);
            self.decode_call(plan, target, RELAY_APPROVAL_PROXY_V3, child, depth + 1);
        }
    }

    fn decode_allowance_holder(
        &self,
        plan: &mut PlanAccumulator,
        caller: Address,
        body: &[u8],
        depth: usize,
    ) {
        let (Some(operator), Some(token), Some(target), Some(child)) = (
            address_word(body, 0),
            address_word(body, 1),
            address_word(body, 3),
            bytes(body, 4),
        ) else {
            return;
        };
        plan.account(ALLOWANCE_HOLDER);
        plan.account(operator);
        plan.account(target);
        plan.balance_with_confidence(token, caller, AGGREGATOR_CONFIDENCE);
        plan.spend_allowance_with_confidence(
            token,
            caller,
            ALLOWANCE_HOLDER,
            AGGREGATOR_CONFIDENCE,
        );
        self.decode_settler(plan, target, caller, child, depth + 1);
        self.decode_call(plan, target, ALLOWANCE_HOLDER, child, depth + 1);
    }

    fn decode_settler(
        &self,
        plan: &mut PlanAccumulator,
        settler: Address,
        caller: Address,
        calldata: &[u8],
        depth: usize,
    ) {
        if depth > MAX_NESTING || calldata.get(..4) != Some(SETTLER_EXECUTE.as_slice()) {
            return;
        }
        let body = &calldata[4..];
        let (Some(recipient), Some(buy_token), Some(actions)) = (
            address_word(body, 0),
            address_word(body, 1),
            bytes_array(body, 3, MAX_INNER_CALLS),
        ) else {
            return;
        };
        plan.account(settler);
        plan.balance_with_confidence(buy_token, settler, AGGREGATOR_CONFIDENCE);
        plan.balance_with_confidence(buy_token, recipient, AGGREGATOR_CONFIDENCE);
        for action in actions {
            self.decode_settler_action(plan, settler, caller, action, depth + 1);
        }
    }

    fn decode_settler_action(
        &self,
        plan: &mut PlanAccumulator,
        settler: Address,
        caller: Address,
        action: &[u8],
        depth: usize,
    ) {
        let Some(selector) = action.get(..4).and_then(|value| value.try_into().ok()) else {
            return;
        };
        let body = &action[4..];
        match selector {
            SETTLER_BASIC => {
                let (Some(sell_token), Some(pool), Some(child)) =
                    (address_word(body, 0), address_word(body, 2), bytes(body, 4))
                else {
                    return;
                };
                plan.balance_with_confidence(sell_token, settler, AGGREGATOR_CONFIDENCE);
                plan.balance_with_confidence(sell_token, pool, AGGREGATOR_CONFIDENCE);
                plan.allowance_with_confidence(sell_token, settler, pool, AGGREGATOR_CONFIDENCE);
                plan.account_with_confidence(pool, LIKELY_CONFIDENCE);
                self.decode_call(plan, pool, settler, child, depth + 1);
            }
            SETTLER_UNISWAP_V3 => {
                let (Some(recipient), Some(path)) = (address_word(body, 0), bytes(body, 2)) else {
                    return;
                };
                if let Some(hops) = settler_v3_path(path, None) {
                    self.add_settler_v3_swap(plan, settler, settler, recipient, &hops);
                }
            }
            SETTLER_UNISWAP_V3_VIP => {
                let (Some(recipient), Some(token), Some(path)) =
                    (address_word(body, 0), address_word(body, 1), bytes(body, 5))
                else {
                    return;
                };
                if let Some(hops) = settler_v3_path(path, Some(token)) {
                    self.add_settler_v3_swap(plan, settler, caller, recipient, &hops);
                }
            }
            SETTLER_TRANSFER_FROM | SETTLER_METATXN_TRANSFER_FROM => {
                let (Some(recipient), Some(token)) = (address_word(body, 0), address_word(body, 1))
                else {
                    return;
                };
                plan.balance_with_confidence(token, caller, AGGREGATOR_CONFIDENCE);
                plan.balance_with_confidence(token, recipient, AGGREGATOR_CONFIDENCE);
            }
            SETTLER_MAVERICK_V2 | SETTLER_DODO_V2 | SETTLER_UNISWAP_V2 => {
                let (Some(recipient), Some(sell_token), Some(pool)) = (
                    address_word(body, 0),
                    address_word(body, 1),
                    address_word(body, 3),
                ) else {
                    return;
                };
                self.add_settler_pool_swap(plan, settler, recipient, sell_token, pool);
            }
            SETTLER_UNISWAP_V4 | SETTLER_PANCAKE_INFINITY | SETTLER_BALANCER_V3 => {
                let (Some(recipient), Some(sell_token)) =
                    (address_word(body, 0), address_word(body, 1))
                else {
                    return;
                };
                plan.balance_with_confidence(sell_token, settler, ROUTER_CONFIDENCE);
                plan.balance_with_confidence(sell_token, recipient, V4_CONFIDENCE);
                if selector == SETTLER_UNISWAP_V4 {
                    plan.account_with_confidence(UNISWAP_V4_POOL_MANAGER, V4_CONFIDENCE);
                    plan.balance_with_confidence(
                        sell_token,
                        UNISWAP_V4_POOL_MANAGER,
                        V4_CONFIDENCE,
                    );
                }
            }
            SETTLER_RFQ => {
                let (Some(recipient), Some(maker_token), Some(taker_token)) = (
                    address_word(body, 0),
                    address_word(body, 1),
                    address_word(body, 7),
                ) else {
                    return;
                };
                plan.balance_with_confidence(maker_token, recipient, AGGREGATOR_CONFIDENCE);
                plan.balance_with_confidence(taker_token, settler, AGGREGATOR_CONFIDENCE);
            }
            SETTLER_POSITIVE_SLIPPAGE => {
                let (Some(recipient), Some(token)) = (address_word(body, 0), address_word(body, 1))
                else {
                    return;
                };
                plan.balance_with_confidence(token, settler, AGGREGATOR_CONFIDENCE);
                plan.balance_with_confidence(token, recipient, AGGREGATOR_CONFIDENCE);
            }
            _ => {}
        }
    }

    fn add_settler_pool_swap(
        &self,
        plan: &mut PlanAccumulator,
        settler: Address,
        recipient: Address,
        sell_token: Address,
        pool: Address,
    ) {
        plan.account_with_confidence(pool, LIKELY_CONFIDENCE);
        plan.balance_with_confidence(sell_token, settler, AGGREGATOR_CONFIDENCE);
        plan.balance_with_confidence(sell_token, pool, AGGREGATOR_CONFIDENCE);
        plan.balance_with_confidence(sell_token, recipient, V4_CONFIDENCE);
    }

    fn add_settler_v3_swap(
        &self,
        plan: &mut PlanAccumulator,
        settler: Address,
        source: Address,
        recipient: Address,
        hops: &[SettlerV3Hop],
    ) {
        let (Some(first), Some(last)) = (hops.first(), hops.last()) else {
            return;
        };
        plan.balance_with_confidence(first.token_in, source, AGGREGATOR_CONFIDENCE);
        plan.balance_with_confidence(last.token_out, recipient, AGGREGATOR_CONFIDENCE);
        for hop in hops {
            plan.account_with_confidence(hop.token_in, AGGREGATOR_CONFIDENCE);
            plan.account_with_confidence(hop.token_out, AGGREGATOR_CONFIDENCE);
            if hop.fork_id == 0 {
                let pool = uniswap_v3_pool(hop.token_in, hop.token_out, hop.pool_id);
                plan.account_with_confidence(pool, LIKELY_CONFIDENCE);
                plan.balance_with_confidence(hop.token_in, pool, AGGREGATOR_CONFIDENCE);
                plan.balance_with_confidence(hop.token_out, pool, AGGREGATOR_CONFIDENCE);
            } else {
                plan.balance_with_confidence(hop.token_in, settler, AGGREGATOR_CONFIDENCE);
            }
        }
    }

    fn decode_surplus_settlement(
        &self,
        plan: &mut PlanAccumulator,
        settlement: Address,
        body: &[u8],
    ) {
        let (Some(buyer), Some(seller)) = (address_word(body, 0), address_word(body, 1)) else {
            return;
        };
        plan.account(settlement);
        plan.balance_with_confidence(USDC, buyer, AGGREGATOR_CONFIDENCE);
        plan.balance_with_confidence(USDC, seller, AGGREGATOR_CONFIDENCE);
        plan.spend_allowance_with_confidence(USDC, buyer, settlement, AGGREGATOR_CONFIDENCE);
    }

    fn decode_entry_point(
        &self,
        plan: &mut PlanAccumulator,
        entry_point: Address,
        body: &[u8],
        depth: usize,
    ) {
        plan.account(entry_point);
        let Some(operations) = tuple_array(body, 0, MAX_INNER_CALLS) else {
            return;
        };
        for operation in operations {
            let (Some(account), Some(call)) = (address_word(operation, 0), bytes(operation, 3))
            else {
                continue;
            };
            plan.account(account);
            self.decode_account_call(plan, account, call, depth + 1);
        }
    }

    fn decode_account_call(
        &self,
        plan: &mut PlanAccumulator,
        account: Address,
        calldata: &[u8],
        depth: usize,
    ) {
        if calldata.len() < 4 || depth > MAX_NESTING {
            return;
        }
        let selector: [u8; 4] = calldata[..4].try_into().expect("length checked");
        let body = &calldata[4..];
        match selector {
            ACCOUNT_EXECUTE => self.decode_account_call_tuple(plan, account, body, depth),
            ACCOUNT_EXECUTE_USER_OP | ACCOUNT_EXECUTE_USER_OP_WITH_ERROR => {
                if usize_word(body, 3) == Some(0) {
                    self.decode_account_call_tuple(plan, account, body, depth);
                }
            }
            ACCOUNT_EXECUTE_BATCH | ACCOUNT_EXECUTE_4337_OPS => {
                self.decode_account_call_array(plan, account, body, depth);
            }
            ACCOUNT_EXECUTE_BATCH_ARRAYS | ACCOUNT_EXECUTE_BATCH_ARRAYS_LEGACY => {
                let (Some(targets), Some(values), Some(children)) = (
                    address_array(body, 0, MAX_INNER_CALLS),
                    array(body, 1),
                    bytes_array(body, 2, MAX_INNER_CALLS),
                ) else {
                    return;
                };
                if usize_word(values, 0) != Some(targets.len()) || children.len() != targets.len() {
                    return;
                }
                for (target, child) in targets.into_iter().zip(children) {
                    let target = if target == Address::ZERO {
                        account
                    } else {
                        target
                    };
                    self.decode_call(plan, target, account, child, depth + 1);
                }
            }
            ACCOUNT_EXECUTE_7579 => self.decode_7579(plan, account, body, depth),
            ACCOUNT_EXECUTE_TUPLE => {
                if let Some(call) = array(body, 0) {
                    self.decode_account_call_tuple(plan, account, call, depth);
                }
            }
            _ => {}
        }
    }

    fn decode_7579(&self, plan: &mut PlanAccumulator, account: Address, body: &[u8], depth: usize) {
        let (Some(mode), Some(execution)) = (word(body, 0), bytes(body, 1)) else {
            return;
        };
        let mode_selector = &mode[6..10];
        match mode[0] {
            0 if mode_selector == [0, 0, 0, 0] => {
                let Some((target, child)) = execution
                    .get(..20)
                    .zip(execution.get(52..))
                    .map(|(target, child)| (Address::from_slice(target), child))
                else {
                    return;
                };
                let target = if target == Address::ZERO {
                    account
                } else {
                    target
                };
                self.decode_call(plan, target, account, child, depth + 1);
            }
            1 if mode_selector == [0, 0, 0, 0] || mode_selector == [0x78, 0x21, 0x00, 0x01] => {
                self.decode_account_call_array(plan, account, execution, depth);
            }
            _ => {}
        }
    }

    fn decode_account_call_array(
        &self,
        plan: &mut PlanAccumulator,
        account: Address,
        body: &[u8],
        depth: usize,
    ) {
        let Some(calls) = tuple_array(body, 0, MAX_INNER_CALLS) else {
            return;
        };
        for call in calls {
            self.decode_account_call_tuple(plan, account, call, depth);
        }
    }

    fn decode_account_call_tuple(
        &self,
        plan: &mut PlanAccumulator,
        account: Address,
        call: &[u8],
        depth: usize,
    ) {
        let (Some(target), Some(child)) = (address_word(call, 0), bytes(call, 2)) else {
            return;
        };
        let target = if target == Address::ZERO {
            account
        } else {
            target
        };
        self.decode_call(plan, target, account, child, depth + 1);
    }

    fn decode_batch_transfers(&self, plan: &mut PlanAccumulator, executor: Address, body: &[u8]) {
        plan.account(executor);
        let Some(count) = usize_word(body, 0).map(|count| count.min(MAX_INNER_CALLS)) else {
            return;
        };
        if executor == WORD_BATCH_TRANSFER {
            let Some(values) = body.get(64..) else {
                return;
            };
            if !values.len().is_multiple_of(128) {
                return;
            }
            let stride = values.len() / 128;
            for index in 0..stride.min(MAX_INNER_CALLS) {
                let (Some(token), Some(owner), Some(recipient)) = (
                    address_word(values, index),
                    address_word(values, stride + index),
                    address_word(values, 2 * stride + index),
                ) else {
                    continue;
                };
                plan.balance(token, owner);
                plan.balance(token, recipient);
                plan.spend_allowance(token, owner, executor);
            }
        } else {
            let Some(records) = body.get(32..) else {
                return;
            };
            let Some(required_length) = count.checked_mul(92) else {
                return;
            };
            if records.len() < required_length {
                return;
            }
            for record in records.chunks_exact(92).take(count) {
                let token = Address::from_slice(&record[..20]);
                let owner = Address::from_slice(&record[20..40]);
                let recipient = Address::from_slice(&record[40..60]);
                plan.balance(token, owner);
                plan.balance(token, recipient);
                plan.spend_allowance(token, owner, executor);
            }
        }
    }

    fn decode_abi_batch_transfers(&self, plan: &mut PlanAccumulator, body: &[u8]) {
        let Some(records) = array(body, 2) else {
            return;
        };
        let Some(count) = usize_word(records, 0).map(|value| value.min(MAX_INNER_CALLS)) else {
            return;
        };
        let Some(records) = records.get(32..) else {
            return;
        };
        let Some(required_length) = count.checked_mul(256) else {
            return;
        };
        if records.len() < required_length {
            return;
        }

        plan.account(ABI_BATCH_TRANSFER);
        for record in records.chunks_exact(256).take(count) {
            let (Some(owner), Some(token), Some(recipient)) = (
                address_word(record, 0),
                address_word(record, 1),
                address_word(record, 2),
            ) else {
                continue;
            };
            plan.balance_with_confidence(token, owner, LIKELY_CONFIDENCE);
            plan.balance_with_confidence(token, recipient, LIKELY_CONFIDENCE);
            plan.balance_with_confidence(token, ABI_BATCH_TRANSFER, LIKELY_CONFIDENCE);
        }
    }

    fn decode_token(
        &self,
        plan: &mut PlanAccumulator,
        token: Address,
        caller: Address,
        selector: [u8; 4],
        body: &[u8],
    ) {
        plan.account(token);
        match selector {
            TRANSFER => {
                if let Some(recipient) = address_word(body, 0) {
                    plan.balance(token, caller);
                    plan.balance(token, recipient);
                }
            }
            TRANSFER_FROM => {
                if let (Some(owner), Some(recipient)) =
                    (address_word(body, 0), address_word(body, 1))
                {
                    plan.balance(token, owner);
                    plan.balance(token, recipient);
                    plan.spend_allowance(token, owner, caller);
                }
            }
            APPROVE | INCREASE_ALLOWANCE | DECREASE_ALLOWANCE => {
                if let Some(spender) = address_word(body, 0) {
                    plan.allowance(token, caller, spender);
                }
            }
            PERMIT => {
                if let (Some(owner), Some(spender)) = (address_word(body, 0), address_word(body, 1))
                {
                    plan.allowance(token, owner, spender);
                    plan.permit_nonce(token, owner);
                }
            }
            TRANSFER_WITH_AUTHORIZATION | RECEIVE_WITH_AUTHORIZATION => {
                if let (Some(owner), Some(recipient), Some(nonce)) = (
                    address_word(body, 0),
                    address_word(body, 1),
                    b256_word(body, 5),
                ) {
                    plan.balance(token, owner);
                    plan.balance(token, recipient);
                    plan.authorization(token, owner, nonce);
                }
            }
            CANCEL_AUTHORIZATION => {
                if let (Some(owner), Some(nonce)) = (address_word(body, 0), b256_word(body, 1)) {
                    plan.authorization(token, owner, nonce);
                }
            }
            DEPOSIT | WITHDRAW if token == WETH => plan.balance(token, caller),
            _ => {}
        }
    }

    fn decode_v3_router(
        &self,
        plan: &mut PlanAccumulator,
        router: Address,
        caller: Address,
        selector: [u8; 4],
        body: &[u8],
        depth: usize,
    ) {
        plan.account(router);
        match selector {
            V3_EXACT_INPUT_SINGLE | V3_EXACT_OUTPUT_SINGLE => {
                let Some(token_in) = address_word(body, 0) else {
                    return;
                };
                let Some(token_out) = address_word(body, 1) else {
                    return;
                };
                let Some(fee) = u24_word(body, 2) else { return };
                let Some(recipient) = address_word(body, 3) else {
                    return;
                };
                self.add_v3_swap(
                    plan,
                    router,
                    caller,
                    resolve_recipient(recipient, caller, router),
                    &[SwapHop {
                        token_in,
                        token_out,
                        parameter: fee,
                    }],
                );
            }
            V3_EXACT_INPUT | V3_EXACT_OUTPUT => {
                let Some(tuple) = dynamic_tuple(body) else {
                    return;
                };
                let Some(path) = bytes(tuple, 0) else { return };
                let Some(recipient) = address_word(tuple, 1) else {
                    return;
                };
                let Some(hops) = packed_path(path, selector == V3_EXACT_OUTPUT) else {
                    return;
                };
                self.add_v3_swap(
                    plan,
                    router,
                    caller,
                    resolve_recipient(recipient, caller, router),
                    &hops,
                );
            }
            MULTICALL | MULTICALL_DEADLINE | MULTICALL_PREVIOUS_BLOCKHASH => {
                let argument = usize::from(selector != MULTICALL);
                let Some(calls) = bytes_array(body, argument, MAX_INNER_CALLS) else {
                    return;
                };
                for call in calls {
                    self.decode_call(plan, router, caller, call, depth + 1);
                }
            }
            _ => {}
        }
    }

    fn add_v3_swap(
        &self,
        plan: &mut PlanAccumulator,
        router: Address,
        caller: Address,
        recipient: Address,
        hops: &[SwapHop],
    ) {
        let (Some(first), Some(last)) = (hops.first(), hops.last()) else {
            return;
        };
        plan.balance_with_confidence(first.token_in, caller, ROUTER_CONFIDENCE);
        plan.spend_allowance_with_confidence(first.token_in, caller, router, ROUTER_CONFIDENCE);
        plan.balance_with_confidence(last.token_out, recipient, ROUTER_CONFIDENCE);
        for hop in hops {
            let pool = uniswap_v3_pool(hop.token_in, hop.token_out, hop.parameter);
            plan.account_with_confidence(pool, LIKELY_CONFIDENCE);
            plan.balance_with_confidence(hop.token_in, pool, ROUTER_CONFIDENCE);
            plan.balance_with_confidence(hop.token_out, pool, ROUTER_CONFIDENCE);
        }
    }

    fn decode_universal_router(
        &self,
        plan: &mut PlanAccumulator,
        router: Address,
        caller: Address,
        selector: [u8; 4],
        body: &[u8],
        depth: usize,
    ) {
        if selector != UNIVERSAL_EXECUTE && selector != UNIVERSAL_EXECUTE_DEADLINE {
            return;
        }
        plan.account(router);
        let Some(commands) = bytes(body, 0) else {
            return;
        };
        let Some(inputs) = bytes_array(body, 1, MAX_INNER_CALLS) else {
            return;
        };
        for (command, input) in commands.iter().zip(inputs) {
            match command & 0x3f {
                0x00 | 0x01 => {
                    let Some(path) = bytes(input, 3) else {
                        continue;
                    };
                    let Some(recipient) = address_word(input, 0) else {
                        continue;
                    };
                    let Some(payer_is_user) = bool_word(input, 4) else {
                        continue;
                    };
                    let Some(hops) = packed_path(path, command & 0x3f == 0x01) else {
                        continue;
                    };
                    self.add_universal_v3_swap(
                        plan,
                        router,
                        caller,
                        resolve_recipient(recipient, caller, router),
                        payer_is_user,
                        &hops,
                    );
                }
                0x02 => {
                    if let (Some(token), Some(recipient)) =
                        (address_word(input, 0), address_word(input, 1))
                    {
                        plan.universal_payment(token, caller, router);
                        plan.balance(token, resolve_recipient(recipient, caller, router));
                    }
                }
                0x08 | 0x09 => {
                    let Some(mut path) = address_array(input, 3, MAX_PATH_TOKENS) else {
                        continue;
                    };
                    if command & 0x3f == 0x09 {
                        path.reverse();
                    }
                    let Some(recipient) = address_word(input, 0) else {
                        continue;
                    };
                    let Some(payer_is_user) = bool_word(input, 4) else {
                        continue;
                    };
                    self.add_universal_token_path(
                        plan,
                        router,
                        caller,
                        resolve_recipient(recipient, caller, router),
                        payer_is_user,
                        &path,
                    );
                }
                0x0b | 0x0c => {
                    if let Some(recipient) = address_word(input, 0) {
                        plan.balance_with_confidence(
                            WETH,
                            resolve_recipient(recipient, caller, router),
                            ROUTER_CONFIDENCE,
                        );
                    }
                }
                0x0e => {
                    if let (Some(owner), Some(token)) =
                        (address_word(input, 0), address_word(input, 1))
                    {
                        plan.balance_with_confidence(
                            token,
                            resolve_recipient(owner, caller, router),
                            ROUTER_CONFIDENCE,
                        );
                    }
                }
                0x10 => self.decode_v4_actions(plan, router, caller, input),
                0x21 if depth < MAX_NESTING => {
                    let Some(commands) = bytes(input, 0) else {
                        continue;
                    };
                    let Some(inputs) = bytes_array(input, 1, MAX_INNER_CALLS) else {
                        continue;
                    };
                    self.decode_universal_commands(
                        plan,
                        router,
                        caller,
                        commands,
                        &inputs,
                        depth + 1,
                    );
                }
                _ => {}
            }
        }
    }

    fn decode_universal_commands(
        &self,
        plan: &mut PlanAccumulator,
        router: Address,
        caller: Address,
        commands: &[u8],
        inputs: &[&[u8]],
        depth: usize,
    ) {
        let mut body = vec![0u8; 64];
        body[31] = 64;
        let inputs_offset = 64usize
            .checked_add(32)
            .and_then(|value| value.checked_add(commands.len().div_ceil(32) * 32));
        let Some(inputs_offset) = inputs_offset else {
            return;
        };
        body[56..64].copy_from_slice(&(inputs_offset as u64).to_be_bytes());
        body.resize(96, 0);
        body[88..96].copy_from_slice(&(commands.len() as u64).to_be_bytes());
        let padded_commands = commands.len().div_ceil(32) * 32;
        body.resize(96 + padded_commands, 0);
        body[96..96 + commands.len()].copy_from_slice(commands);
        append_bytes_array(&mut body, inputs);
        self.decode_universal_router(plan, router, caller, UNIVERSAL_EXECUTE, &body, depth);
    }

    fn add_universal_v3_swap(
        &self,
        plan: &mut PlanAccumulator,
        router: Address,
        caller: Address,
        recipient: Address,
        payer_is_user: bool,
        hops: &[SwapHop],
    ) {
        let (Some(first), Some(last)) = (hops.first(), hops.last()) else {
            return;
        };
        if payer_is_user {
            plan.universal_payment(first.token_in, caller, router);
        } else {
            plan.balance_with_confidence(first.token_in, router, ROUTER_CONFIDENCE);
        }
        plan.balance_with_confidence(last.token_out, recipient, ROUTER_CONFIDENCE);
        for hop in hops {
            let pool = uniswap_v3_pool(hop.token_in, hop.token_out, hop.parameter);
            plan.account_with_confidence(pool, LIKELY_CONFIDENCE);
            plan.balance_with_confidence(hop.token_in, pool, ROUTER_CONFIDENCE);
            plan.balance_with_confidence(hop.token_out, pool, ROUTER_CONFIDENCE);
        }
    }

    fn add_universal_token_path(
        &self,
        plan: &mut PlanAccumulator,
        router: Address,
        caller: Address,
        recipient: Address,
        payer_is_user: bool,
        path: &[Address],
    ) {
        let (Some(first), Some(last)) = (path.first(), path.last()) else {
            return;
        };
        if payer_is_user {
            plan.universal_payment(*first, caller, router);
        } else {
            plan.balance_with_confidence(*first, router, ROUTER_CONFIDENCE);
        }
        plan.balance_with_confidence(*last, recipient, ROUTER_CONFIDENCE);
        for token in path {
            plan.account_with_confidence(*token, ROUTER_CONFIDENCE);
        }
    }

    fn decode_v4_actions(
        &self,
        plan: &mut PlanAccumulator,
        router: Address,
        caller: Address,
        input: &[u8],
    ) {
        let Some(actions) = bytes(input, 0) else {
            return;
        };
        let Some(params) = bytes_array(input, 1, MAX_INNER_CALLS) else {
            return;
        };
        plan.account_with_confidence(UNISWAP_V4_POOL_MANAGER, V4_CONFIDENCE);
        for (action, param) in actions.iter().zip(params) {
            match action {
                0x06 | 0x08 => {
                    let tuple = dynamic_tuple(param).unwrap_or(param);
                    if let Some((token0, token1)) = plan_v4_pool(plan, tuple) {
                        plan.balance_with_confidence(
                            token0,
                            UNISWAP_V4_POOL_MANAGER,
                            V4_CONFIDENCE,
                        );
                        plan.balance_with_confidence(
                            token1,
                            UNISWAP_V4_POOL_MANAGER,
                            V4_CONFIDENCE,
                        );
                    }
                }
                0x0b => {
                    if let (Some(token), Some(payer_is_user)) =
                        (address_word(param, 0), bool_word(param, 2))
                    {
                        if payer_is_user {
                            plan.universal_payment(token, caller, router);
                        } else {
                            plan.balance_with_confidence(token, router, V4_CONFIDENCE);
                        }
                        plan.balance_with_confidence(token, UNISWAP_V4_POOL_MANAGER, V4_CONFIDENCE);
                    }
                }
                0x0c => {
                    if let Some(token) = address_word(param, 0) {
                        plan.universal_payment(token, caller, router);
                        plan.balance_with_confidence(token, UNISWAP_V4_POOL_MANAGER, V4_CONFIDENCE);
                    }
                }
                0x0d => {
                    for index in 0..2 {
                        if let Some(token) = address_word(param, index) {
                            plan.universal_payment(token, caller, router);
                            plan.balance_with_confidence(
                                token,
                                UNISWAP_V4_POOL_MANAGER,
                                V4_CONFIDENCE,
                            );
                        }
                    }
                }
                0x0e | 0x0f => {
                    if let (Some(token), Some(recipient)) =
                        (address_word(param, 0), address_word(param, 1))
                    {
                        plan.balance_with_confidence(token, UNISWAP_V4_POOL_MANAGER, V4_CONFIDENCE);
                        plan.balance_with_confidence(
                            token,
                            resolve_recipient(recipient, caller, router),
                            V4_CONFIDENCE,
                        );
                    }
                }
                0x11 => {
                    if let Some(recipient) = address_word(param, 2) {
                        for index in 0..2 {
                            if let Some(token) = address_word(param, index) {
                                plan.balance_with_confidence(
                                    token,
                                    UNISWAP_V4_POOL_MANAGER,
                                    V4_CONFIDENCE,
                                );
                                plan.balance_with_confidence(
                                    token,
                                    resolve_recipient(recipient, caller, router),
                                    V4_CONFIDENCE,
                                );
                            }
                        }
                    }
                }
                0x12 => {
                    if let Some(token) = address_word(param, 0) {
                        plan.balance_with_confidence(token, UNISWAP_V4_POOL_MANAGER, V4_CONFIDENCE);
                    }
                }
                _ => {}
            }
        }
    }

    fn decode_aerodrome(
        &self,
        plan: &mut PlanAccumulator,
        router: Address,
        caller: Address,
        selector: [u8; 4],
        body: &[u8],
    ) {
        plan.account(router);
        let (route_index, recipient_index) = match selector {
            AERODROME_TOKEN_TO_TOKEN | AERODROME_TOKEN_TO_ETH => (2, 3),
            AERODROME_ETH_TO_TOKEN => (1, 2),
            _ => return,
        };
        let Some(routes) = aerodrome_routes(body, route_index) else {
            return;
        };
        let Some(recipient) = address_word(body, recipient_index) else {
            return;
        };
        let (Some(first), Some(last)) = (routes.first(), routes.last()) else {
            return;
        };
        if selector != AERODROME_ETH_TO_TOKEN {
            plan.balance(first.0, caller);
            plan.spend_allowance(first.0, caller, router);
        }
        if selector != AERODROME_TOKEN_TO_ETH {
            plan.balance(last.1, recipient);
        }
        for (token_in, token_out) in routes {
            plan.account(token_in);
            plan.account(token_out);
        }
    }

    fn decode_slipstream(
        &self,
        plan: &mut PlanAccumulator,
        router: Address,
        caller: Address,
        selector: [u8; 4],
        body: &[u8],
        depth: usize,
    ) {
        plan.account(router);
        match selector {
            SLIPSTREAM_EXACT_INPUT_SINGLE | SLIPSTREAM_EXACT_OUTPUT_SINGLE => {
                let Some(tuple) = dynamic_tuple(body).or(Some(body)) else {
                    return;
                };
                let (Some(token_in), Some(token_out), Some(recipient)) = (
                    address_word(tuple, 0),
                    address_word(tuple, 1),
                    address_word(tuple, 3),
                ) else {
                    return;
                };
                self.add_router_token_path(plan, router, caller, recipient, &[token_in, token_out]);
            }
            SLIPSTREAM_EXACT_INPUT | SLIPSTREAM_EXACT_OUTPUT => {
                let Some(tuple) = dynamic_tuple(body) else {
                    return;
                };
                let Some(path) = bytes(tuple, 0) else { return };
                let Some(recipient) = address_word(tuple, 1) else {
                    return;
                };
                let Some(hops) = packed_path(path, selector == SLIPSTREAM_EXACT_OUTPUT) else {
                    return;
                };
                let mut tokens = Vec::with_capacity(hops.len() + 1);
                if let Some(first) = hops.first() {
                    tokens.push(first.token_in);
                    tokens.extend(hops.iter().map(|hop| hop.token_out));
                }
                self.add_router_token_path(plan, router, caller, recipient, &tokens);
            }
            MULTICALL | MULTICALL_DEADLINE | MULTICALL_PREVIOUS_BLOCKHASH => {
                let argument = usize::from(selector != MULTICALL);
                let Some(calls) = bytes_array(body, argument, MAX_INNER_CALLS) else {
                    return;
                };
                for call in calls {
                    self.decode_call(plan, router, caller, call, depth + 1);
                }
            }
            _ => {}
        }
    }

    fn add_router_token_path(
        &self,
        plan: &mut PlanAccumulator,
        router: Address,
        caller: Address,
        recipient: Address,
        path: &[Address],
    ) {
        let (Some(first), Some(last)) = (path.first(), path.last()) else {
            return;
        };
        plan.balance_with_confidence(*first, caller, LIKELY_CONFIDENCE);
        plan.spend_allowance_with_confidence(*first, caller, router, LIKELY_CONFIDENCE);
        plan.balance_with_confidence(*last, recipient, LIKELY_CONFIDENCE);
        for token in path {
            plan.account_with_confidence(*token, LIKELY_CONFIDENCE);
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SwapHop {
    token_in: Address,
    token_out: Address,
    parameter: u32,
}

#[derive(Debug, Clone, Copy)]
struct SettlerV3Hop {
    token_in: Address,
    token_out: Address,
    fork_id: u8,
    pool_id: u32,
}

#[derive(Default)]
struct PlanAccumulator {
    plan: PrefetchPlan,
}

impl PlanAccumulator {
    fn account(&mut self, address: Address) {
        self.account_with_confidence(address, 1.0);
    }

    fn account_with_confidence(&mut self, address: Address, confidence: f64) {
        if address != Address::ZERO {
            self.plan.accounts.push(address);
            self.plan.account_confidence.push(confidence);
        }
    }

    fn storage(&mut self, address: Address, slot: B256) {
        self.storage_with_confidence(address, slot, 1.0);
    }

    fn storage_with_confidence(&mut self, address: Address, slot: B256, confidence: f64) {
        self.plan.storage.push(StorageTarget { address, slot });
        self.plan.storage_confidence.push(confidence);
    }

    fn balance(&mut self, token: Address, owner: Address) {
        self.balance_with_confidence(token, owner, 1.0);
    }

    fn balance_with_confidence(&mut self, token: Address, owner: Address, confidence: f64) {
        let Some(layout) = token_layout(token) else {
            return;
        };
        self.account_with_confidence(token, confidence);
        if matches!(layout, TokenLayout::B20) {
            self.storage_with_confidence(
                token,
                mapping_slot_at(owner.into_word(), add_slot(B20_STORAGE_ROOT, 4)),
                confidence,
            );
            self.storage_with_confidence(token, add_slot(B20_STORAGE_ROOT, 9), confidence);
            self.storage_with_confidence(token, add_slot(B20_STORAGE_ROOT, 11), confidence);
        } else {
            self.storage_with_confidence(
                token,
                mapping_slot(owner.into_word(), layout.balance_slot()),
                confidence,
            );
        }
        if let Some(blacklist_slot) = layout.blacklist_slot() {
            self.storage_with_confidence(
                token,
                mapping_slot(owner.into_word(), blacklist_slot),
                confidence,
            );
        }
    }

    fn allowance(&mut self, token: Address, owner: Address, spender: Address) {
        self.allowance_with_confidence(token, owner, spender, 1.0);
    }

    fn spend_allowance(&mut self, token: Address, owner: Address, spender: Address) {
        self.spend_allowance_with_confidence(token, owner, spender, 1.0);
    }

    fn spend_allowance_with_confidence(
        &mut self,
        token: Address,
        owner: Address,
        spender: Address,
        confidence: f64,
    ) {
        self.allowance_with_confidence(token, owner, spender, confidence);
        if matches!(token_layout(token), Some(TokenLayout::FiatV2_2)) {
            self.storage_with_confidence(
                token,
                mapping_slot(spender.into_word(), TokenLayout::FiatV2_2.balance_slot()),
                confidence,
            );
        }
    }

    fn allowance_with_confidence(
        &mut self,
        token: Address,
        owner: Address,
        spender: Address,
        confidence: f64,
    ) {
        let Some(layout) = token_layout(token) else {
            return;
        };
        self.account_with_confidence(token, confidence);
        let slot = if matches!(layout, TokenLayout::B20) {
            nested_mapping_slot_at(
                owner.into_word(),
                spender.into_word(),
                add_slot(B20_STORAGE_ROOT, 5),
            )
        } else {
            nested_mapping_slot(
                owner.into_word(),
                spender.into_word(),
                layout.allowance_slot(),
            )
        };
        self.storage_with_confidence(token, slot, confidence);
        if let Some(blacklist_slot) = layout.blacklist_slot() {
            self.storage_with_confidence(
                token,
                mapping_slot(owner.into_word(), blacklist_slot),
                confidence,
            );
            self.storage_with_confidence(
                token,
                mapping_slot(spender.into_word(), blacklist_slot),
                confidence,
            );
        }
    }

    fn permit_nonce(&mut self, token: Address, owner: Address) {
        if matches!(
            token_layout(token),
            Some(TokenLayout::FiatV2_1 | TokenLayout::FiatV2_2 | TokenLayout::B20)
        ) {
            let nonce_slot = if matches!(token_layout(token), Some(TokenLayout::B20)) {
                mapping_slot_at(owner.into_word(), add_slot(B20_STORAGE_ROOT, 13))
            } else {
                mapping_slot(owner.into_word(), 17)
            };
            self.storage(token, nonce_slot);
        }
    }

    fn authorization(&mut self, token: Address, owner: Address, nonce: B256) {
        if matches!(
            token_layout(token),
            Some(TokenLayout::FiatV2_1 | TokenLayout::FiatV2_2)
        ) {
            self.storage(token, nested_mapping_slot(owner.into_word(), nonce, 16));
        }
    }

    fn universal_payment(&mut self, token: Address, owner: Address, router: Address) {
        self.balance_with_confidence(token, owner, ROUTER_CONFIDENCE);
        self.spend_allowance_with_confidence(token, owner, PERMIT2, ROUTER_CONFIDENCE);
        self.account_with_confidence(PERMIT2, PERMIT2_CONFIDENCE);
        self.storage_with_confidence(
            PERMIT2,
            permit2_allowance_slot(owner, token, router),
            PERMIT2_CONFIDENCE,
        );
    }
}

#[derive(Clone, Copy)]
enum TokenLayout {
    FiatV2_1,
    FiatV2_2,
    Weth9,
    B20,
}

impl TokenLayout {
    fn balance_slot(self) -> u64 {
        match self {
            Self::FiatV2_1 | Self::FiatV2_2 => 9,
            Self::Weth9 => 3,
            Self::B20 => unreachable!("B20 uses a namespaced mapping root"),
        }
    }

    fn allowance_slot(self) -> u64 {
        match self {
            Self::FiatV2_1 | Self::FiatV2_2 => 10,
            Self::Weth9 => 4,
            Self::B20 => unreachable!("B20 uses a namespaced mapping root"),
        }
    }

    fn blacklist_slot(self) -> Option<u64> {
        match self {
            Self::FiatV2_1 => Some(3),
            Self::FiatV2_2 | Self::Weth9 | Self::B20 => None,
        }
    }
}

fn token_layout(token: Address) -> Option<TokenLayout> {
    match token {
        USDC => Some(TokenLayout::FiatV2_2),
        CBBTC => Some(TokenLayout::FiatV2_1),
        WETH => Some(TokenLayout::Weth9),
        _ if is_supported_b20_address(token) => Some(TokenLayout::B20),
        _ => None,
    }
}

fn is_supported_b20_address(token: Address) -> bool {
    token.as_slice()[0] == 0xb2
        && token.as_slice()[1..10].iter().all(|byte| *byte == 0)
        && token.as_slice()[10] <= 1
}

fn mapping_slot(key: B256, slot: u64) -> B256 {
    mapping_slot_at(key, B256::from(U256::from(slot)))
}

fn mapping_slot_at(key: B256, slot: B256) -> B256 {
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(key.as_slice());
    preimage[32..].copy_from_slice(slot.as_slice());
    keccak256(preimage)
}

fn nested_mapping_slot(first: B256, second: B256, slot: u64) -> B256 {
    nested_mapping_slot_at(first, second, B256::from(U256::from(slot)))
}

fn nested_mapping_slot_at(first: B256, second: B256, slot: B256) -> B256 {
    let first_slot = mapping_slot_at(first, slot);
    let mut preimage = [0u8; 64];
    preimage[..32].copy_from_slice(second.as_slice());
    preimage[32..].copy_from_slice(first_slot.as_slice());
    keccak256(preimage)
}

fn add_slot(slot: B256, offset: u64) -> B256 {
    B256::from(U256::from_be_bytes(slot.0) + U256::from(offset))
}

fn permit2_allowance_slot(owner: Address, token: Address, spender: Address) -> B256 {
    let owner_slot = mapping_slot(owner.into_word(), 1);
    let mut token_preimage = [0u8; 64];
    token_preimage[..32].copy_from_slice(token.into_word().as_slice());
    token_preimage[32..].copy_from_slice(owner_slot.as_slice());
    let token_slot = keccak256(token_preimage);
    let mut spender_preimage = [0u8; 64];
    spender_preimage[..32].copy_from_slice(spender.into_word().as_slice());
    spender_preimage[32..].copy_from_slice(token_slot.as_slice());
    keccak256(spender_preimage)
}

fn dynamic_tuple(data: &[u8]) -> Option<&[u8]> {
    let offset = usize_word(data, 0)?;
    data.get(offset..)
}

fn u24_word(data: &[u8], index: usize) -> Option<u32> {
    let value = word(data, index)?;
    if value[..29].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(u32::from_be_bytes([0, value[29], value[30], value[31]]))
}

fn packed_path(path: &[u8], reversed: bool) -> Option<Vec<SwapHop>> {
    if path.len() < 43 || !(path.len() - 20).is_multiple_of(23) {
        return None;
    }
    let mut hops = path
        .windows(43)
        .step_by(23)
        .take(MAX_PATH_TOKENS - 1)
        .map(|hop| SwapHop {
            token_in: Address::from_slice(&hop[..20]),
            parameter: u32::from_be_bytes([0, hop[20], hop[21], hop[22]]),
            token_out: Address::from_slice(&hop[23..43]),
        })
        .collect::<Vec<_>>();
    if reversed {
        hops = hops
            .into_iter()
            .rev()
            .map(|hop| SwapHop {
                token_in: hop.token_out,
                token_out: hop.token_in,
                parameter: hop.parameter,
            })
            .collect();
    }
    Some(hops)
}

fn settler_v3_path(path: &[u8], first_token: Option<Address>) -> Option<Vec<SettlerV3Hop>> {
    let (mut token_in, mut cursor) = if let Some(first_token) = first_token {
        (first_token, 0)
    } else {
        (Address::from_slice(path.get(..20)?), 20)
    };
    if path.len().saturating_sub(cursor) == 0
        || !path.len().saturating_sub(cursor).is_multiple_of(44)
    {
        return None;
    }

    let mut hops = Vec::new();
    while let Some(hop) = path.get(cursor..cursor.checked_add(44)?) {
        if hops.len() >= MAX_PATH_TOKENS - 1 {
            break;
        }
        let token_out = Address::from_slice(&hop[24..44]);
        hops.push(SettlerV3Hop {
            token_in,
            token_out,
            fork_id: hop[0],
            pool_id: u32::from_be_bytes([0, hop[1], hop[2], hop[3]]),
        });
        token_in = token_out;
        cursor += 44;
    }
    Some(hops)
}

fn uniswap_v3_pool(token_a: Address, token_b: Address, fee: u32) -> Address {
    let (token0, token1) = if token_a < token_b {
        (token_a, token_b)
    } else {
        (token_b, token_a)
    };
    let mut encoded = [0u8; 96];
    encoded[12..32].copy_from_slice(token0.as_slice());
    encoded[44..64].copy_from_slice(token1.as_slice());
    encoded[92..96].copy_from_slice(&fee.to_be_bytes());
    let salt = keccak256(encoded);
    let mut preimage = [0u8; 85];
    preimage[0] = 0xff;
    preimage[1..21].copy_from_slice(UNISWAP_V3_FACTORY.as_slice());
    preimage[21..53].copy_from_slice(salt.as_slice());
    preimage[53..].copy_from_slice(UNISWAP_V3_POOL_INIT_CODE_HASH.as_slice());
    Address::from_slice(&keccak256(preimage)[12..])
}

fn plan_v4_pool(plan: &mut PlanAccumulator, tuple: &[u8]) -> Option<(Address, Address)> {
    let token0 = address_word(tuple, 0)?;
    let token1 = address_word(tuple, 1)?;
    let pool_key = tuple.get(..160)?;
    let pool_id = keccak256(pool_key);
    let mut mapping_preimage = [0u8; 64];
    mapping_preimage[..32].copy_from_slice(pool_id.as_slice());
    mapping_preimage[63] = 6;
    let base = U256::from_be_bytes(keccak256(mapping_preimage).0);
    for offset in 0..4 {
        plan.storage_with_confidence(
            UNISWAP_V4_POOL_MANAGER,
            B256::from(base + U256::from(offset)),
            V4_CONFIDENCE,
        );
    }
    Some((token0, token1))
}

fn aerodrome_routes(data: &[u8], index: usize) -> Option<Vec<(Address, Address)>> {
    let routes = array(data, index)?;
    let length = usize_word(routes, 0)?.min(MAX_PATH_TOKENS - 1);
    let entries = routes.get(32..)?;
    (0..length)
        .map(|route| {
            let entry = entries.get(route.checked_mul(128)?..)?;
            Some((address_word(entry, 0)?, address_word(entry, 1)?))
        })
        .collect()
}

fn resolve_recipient(recipient: Address, caller: Address, router: Address) -> Address {
    match recipient {
        MSG_SENDER => caller,
        ADDRESS_THIS => router,
        _ => recipient,
    }
}

fn append_bytes_array(encoded: &mut Vec<u8>, values: &[&[u8]]) {
    let start = encoded.len();
    encoded.resize(start + 32 + values.len() * 32, 0);
    encoded[start + 24..start + 32].copy_from_slice(&(values.len() as u64).to_be_bytes());
    let heads = start + 32;
    for (index, value) in values.iter().enumerate() {
        let offset = encoded.len() - heads;
        encoded[heads + index * 32 + 24..heads + (index + 1) * 32]
            .copy_from_slice(&(offset as u64).to_be_bytes());
        let value_start = encoded.len();
        encoded.resize(value_start + 32 + value.len().div_ceil(32) * 32, 0);
        encoded[value_start + 24..value_start + 32]
            .copy_from_slice(&(value.len() as u64).to_be_bytes());
        encoded[value_start + 32..value_start + 32 + value.len()].copy_from_slice(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: Address = address!("1111111111111111111111111111111111111111");
    const RECIPIENT: Address = address!("2222222222222222222222222222222222222222");

    fn calldata(selector: [u8; 4], words: &[B256]) -> Vec<u8> {
        let mut data = selector.to_vec();
        for word in words {
            data.extend_from_slice(word.as_slice());
        }
        data
    }

    #[test]
    fn decodes_fiat_token_allowance_and_balances() {
        let data = calldata(
            TRANSFER_FROM,
            &[
                USER.into_word(),
                RECIPIENT.into_word(),
                B256::with_last_byte(1),
            ],
        );
        let plan = BaseMainnetDecoder::new(PlanLimits::new(32, 256)).decode(
            USDC,
            UNISWAP_V3_ROUTER,
            &data,
        );

        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: nested_mapping_slot(USER.into_word(), UNISWAP_V3_ROUTER.into_word(), 10),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(RECIPIENT.into_word(), 9),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(UNISWAP_V3_ROUTER.into_word(), 9),
        }));
    }

    #[test]
    fn derives_uniswap_v3_pool_and_token_state() {
        let fee = B256::from(U256::from(500));
        let data = calldata(
            V3_EXACT_INPUT_SINGLE,
            &[
                USDC.into_word(),
                WETH.into_word(),
                fee,
                RECIPIENT.into_word(),
                B256::ZERO,
                B256::ZERO,
                B256::ZERO,
            ],
        );
        let plan = BaseMainnetDecoder::new(PlanLimits::new(32, 256)).decode(
            UNISWAP_V3_ROUTER,
            USER,
            &data,
        );
        let pool = uniswap_v3_pool(USDC, WETH, 500);

        assert!(plan.accounts.contains(&pool));
        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(pool.into_word(), 9),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: WETH,
            slot: mapping_slot(pool.into_word(), 3),
        }));
    }

    #[test]
    fn derives_uniswap_v4_fixed_pool_state() {
        let mut tuple = vec![0u8; 320];
        tuple[12..32].copy_from_slice(USDC.as_slice());
        tuple[44..64].copy_from_slice(WETH.as_slice());
        tuple[95] = 0xf4;
        tuple[127] = 10;
        let mut plan = PlanAccumulator::default();

        assert_eq!(plan_v4_pool(&mut plan, &tuple), Some((USDC, WETH)));
        assert_eq!(plan.plan.storage.len(), 4);
        assert!(plan
            .plan
            .storage
            .iter()
            .all(|target| target.address == UNISWAP_V4_POOL_MANAGER));
    }

    #[test]
    fn malformed_calldata_returns_an_empty_plan() {
        let plan = BaseMainnetDecoder::new(PlanLimits::new(32, 256)).decode(
            UNISWAP_V3_ROUTER,
            USER,
            &[1, 2, 3],
        );
        assert_eq!(plan.target_count(), 0);
    }

    #[test]
    fn decodes_namespaced_b20_storage_for_supported_variants() {
        let asset = address!("b2000000000000000000001234567890abcdef12");
        let stablecoin = address!("b2000000000000000000011234567890abcdef12");
        let reserved = address!("b2000000000000000000021234567890abcdef12");
        assert!(is_supported_b20_address(asset));
        assert!(is_supported_b20_address(stablecoin));
        assert!(!is_supported_b20_address(reserved));

        let data = calldata(TRANSFER, &[RECIPIENT.into_word(), B256::with_last_byte(1)]);
        let plan = BaseMainnetDecoder::new(PlanLimits::new(32, 256)).decode(asset, USER, &data);

        assert!(plan.storage.contains(&StorageTarget {
            address: asset,
            slot: mapping_slot_at(USER.into_word(), add_slot(B20_STORAGE_ROOT, 4)),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: asset,
            slot: add_slot(B20_STORAGE_ROOT, 9),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: asset,
            slot: add_slot(B20_STORAGE_ROOT, 11),
        }));
    }

    #[test]
    fn decodes_packed_batch_token_transfers() {
        let mut body = vec![0u8; 32 + 92];
        body[31] = 1;
        body[32..52].copy_from_slice(USDC.as_slice());
        body[52..72].copy_from_slice(USER.as_slice());
        body[72..92].copy_from_slice(RECIPIENT.as_slice());
        let mut data = BATCH_TRANSFER.to_vec();
        data.extend_from_slice(&body);

        let plan = BaseMainnetDecoder::new(PlanLimits::new(32, 256)).decode(
            PACKED_BATCH_TRANSFER,
            USER,
            &data,
        );

        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: nested_mapping_slot(USER.into_word(), PACKED_BATCH_TRANSFER.into_word(), 10),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(RECIPIENT.into_word(), 9),
        }));
    }

    #[test]
    fn decodes_abi_batch_token_transfers() {
        let mut data = vec![0u8; 4 + 32 * 12];
        data[..4].copy_from_slice(&TRANSFER);
        data[4 + 88..4 + 96].copy_from_slice(&96_u64.to_be_bytes());
        data[4 + 120..4 + 128].copy_from_slice(&1_u64.to_be_bytes());
        data[4 + 140..4 + 160].copy_from_slice(USER.as_slice());
        data[4 + 172..4 + 192].copy_from_slice(USDC.as_slice());
        data[4 + 204..4 + 224].copy_from_slice(RECIPIENT.as_slice());

        let plan = BaseMainnetDecoder::new(PlanLimits::new(32, 256)).decode(
            ABI_BATCH_TRANSFER,
            Address::repeat_byte(0x33),
            &data,
        );

        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(USER.into_word(), 9),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(ABI_BATCH_TRANSFER.into_word(), 9),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(RECIPIENT.into_word(), 9),
        }));
    }

    #[test]
    fn decodes_erc7579_packed_account_call() {
        let child = calldata(TRANSFER, &[RECIPIENT.into_word(), B256::with_last_byte(1)]);
        let payload_length = 20 + 32 + child.len();
        let mut data = vec![0u8; 4 + 32 * 3 + payload_length.div_ceil(32) * 32];
        data[..4].copy_from_slice(&ACCOUNT_EXECUTE_7579);
        data[4 + 56..4 + 64].copy_from_slice(&64_u64.to_be_bytes());
        data[4 + 88..4 + 96].copy_from_slice(&(payload_length as u64).to_be_bytes());
        data[4 + 96..4 + 116].copy_from_slice(USDC.as_slice());
        data[4 + 148..4 + 148 + child.len()].copy_from_slice(&child);
        let mut plan = PlanAccumulator::default();

        BaseMainnetDecoder::new(PlanLimits::new(32, 256))
            .decode_account_call(&mut plan, USER, &data, 0);

        assert!(plan.plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(USER.into_word(), 9),
        }));
        assert!(plan.plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(RECIPIENT.into_word(), 9),
        }));
    }

    #[test]
    fn decodes_kyber_swap_token_owners() {
        let call_target = Address::repeat_byte(0x44);
        let approve_target = Address::repeat_byte(0x55);
        let mut data = vec![0u8; 4 + 32 + 576];
        data[..4].copy_from_slice(&KYBER_SWAP);
        data[28..36].copy_from_slice(&32_u64.to_be_bytes());
        let execution = &mut data[36..];
        execution[12..32].copy_from_slice(call_target.as_slice());
        execution[44..64].copy_from_slice(approve_target.as_slice());
        execution[88..96].copy_from_slice(&512_u64.to_be_bytes());
        execution[120..128].copy_from_slice(&160_u64.to_be_bytes());
        execution[152..160].copy_from_slice(&544_u64.to_be_bytes());
        execution[172..192].copy_from_slice(USDC.as_slice());
        execution[204..224].copy_from_slice(WETH.as_slice());
        execution[364..384].copy_from_slice(RECIPIENT.as_slice());

        let plan =
            BaseMainnetDecoder::new(PlanLimits::new(32, 256)).decode(KYBER_ROUTER, USER, &data);

        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(USER.into_word(), 9),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: WETH,
            slot: mapping_slot(RECIPIENT.into_word(), 3),
        }));
    }

    #[test]
    fn decodes_okx_swap_token_owners() {
        let mut data = vec![0u8; 4 + 32 * 8];
        data[..4].copy_from_slice(&OKX_DAG_SWAP_BY_ORDER_ID);
        data[48..68].copy_from_slice(USDC.as_slice());
        data[80..100].copy_from_slice(WETH.as_slice());
        data[4 + 216..4 + 224].copy_from_slice(&224_u64.to_be_bytes());

        let plan =
            BaseMainnetDecoder::new(PlanLimits::new(32, 256)).decode(OKX_ROUTER, USER, &data);

        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(USER.into_word(), 9),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: WETH,
            slot: mapping_slot(USER.into_word(), 3),
        }));
    }

    #[test]
    fn decodes_surplus_settlement_usdc_transfers() {
        let data = calldata(
            SURPLUS_SETTLE,
            &[
                USER.into_word(),
                RECIPIENT.into_word(),
                B256::with_last_byte(1),
            ],
        );

        let plan = BaseMainnetDecoder::new(PlanLimits::new(32, 256)).decode(
            SURPLUS_SETTLEMENT_V2,
            Address::repeat_byte(0x33),
            &data,
        );

        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(USER.into_word(), 9),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(RECIPIENT.into_word(), 9),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: nested_mapping_slot(USER.into_word(), SURPLUS_SETTLEMENT_V2.into_word(), 10),
        }));
    }

    #[test]
    fn decodes_allowance_holder_source_token_state() {
        let child = calldata(TRANSFER, &[RECIPIENT.into_word(), B256::with_last_byte(1)]);
        let mut body = vec![0u8; 32 * 6 + child.len().div_ceil(32) * 32];
        body[12..32].copy_from_slice(Address::repeat_byte(0x44).as_slice());
        body[44..64].copy_from_slice(USDC.as_slice());
        body[108..128].copy_from_slice(USDC.as_slice());
        body[152..160].copy_from_slice(&(32_u64 * 5).to_be_bytes());
        body[184..192].copy_from_slice(&(child.len() as u64).to_be_bytes());
        body[192..192 + child.len()].copy_from_slice(&child);
        let mut data = ALLOWANCE_HOLDER_EXEC.to_vec();
        data.extend_from_slice(&body);

        let plan =
            BaseMainnetDecoder::new(PlanLimits::new(32, 256)).decode(ALLOWANCE_HOLDER, USER, &data);

        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(USER.into_word(), 9),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: nested_mapping_slot(USER.into_word(), ALLOWANCE_HOLDER.into_word(), 10),
        }));
        assert!(plan.storage.contains(&StorageTarget {
            address: USDC,
            slot: mapping_slot(RECIPIENT.into_word(), 9),
        }));
    }
}
