//! Current contract ABI, generated from the same pinned artifacts as the TypeScript and Go SDKs.
//! ABI encoding does not establish proof validity, ownership or authorization.
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{sol, SolCall, SolEvent, SolInterface};

sol!(
    #[sol(all_derives)]
    InvisiCore,
    "src/protocol/abi/InvisiCore.abi.json"
);
sol!(
    #[sol(all_derives)]
    InvisiCoreFactory,
    "src/protocol/abi/InvisiCoreFactory.abi.json"
);
sol!(
    #[sol(all_derives)]
    InvisiAddressRegistry,
    "src/protocol/abi/InvisiAddressRegistry.abi.json"
);
sol!(
    #[sol(all_derives)]
    IERC20,
    "src/protocol/abi/IERC20.abi.json"
);
sol!(
    #[sol(all_derives)]
    VerifierRouter,
    "src/protocol/abi/VerifierRouter.abi.json"
);
sol!(
    #[sol(all_derives)]
    CreditVerifierRouter,
    "src/protocol/abi/CreditVerifierRouter.abi.json"
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionCall {
    pub to: Address,
    pub data: Vec<u8>,
    pub value: U256,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolContract {
    address: Address,
}
impl ProtocolContract {
    pub fn new(address: Address) -> Result<Self, String> {
        if address == Address::ZERO {
            return Err("nonzero contract address required".into());
        }
        Ok(Self { address })
    }
    pub fn address(&self) -> Address {
        self.address
    }
    /// Encode any generated read or write: shield, both transact overloads, Credit operations, or registry calls.
    pub fn call<C: SolCall>(&self, call: &C) -> TransactionCall {
        TransactionCall {
            to: self.address,
            data: call.abi_encode(),
            value: U256::ZERO,
        }
    }
    pub fn decode_call(data: &[u8]) -> Result<InvisiCore::InvisiCoreCalls, String> {
        InvisiCore::InvisiCoreCalls::abi_decode_validate(data).map_err(|error| error.to_string())
    }
    pub fn decode_return<C: SolCall>(data: &[u8]) -> Result<C::Return, String> {
        C::abi_decode_returns_validate(data).map_err(|error| error.to_string())
    }
}

sol!(
    #[sol(all_derives)]
    BroadcasterRegistry,
    "src/protocol/abi/BroadcasterRegistry.abi.json"
);

pub fn decode_event<E: SolEvent>(topics: &[B256], data: &[u8]) -> Result<E, String> {
    E::decode_raw_log_validate(topics.iter().copied(), data).map_err(|error| error.to_string())
}

mod receipts;
pub use receipts::*;
