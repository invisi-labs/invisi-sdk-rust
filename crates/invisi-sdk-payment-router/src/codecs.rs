use crate::{abi, ensure, nonzero, uint, Result};
use alloy_primitives::{address, Address, U256};
use alloy_sol_types::SolCall;
pub const NATIVE_TOKEN: Address = address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
/// Forward token order is reversed for V3 exact output.
pub fn encode_v3_exact_output_path(tokens: &[Address], fees: &[u32]) -> Result<Vec<u8>> {
    ensure(
        tokens.len() >= 2 && fees.len() == tokens.len() - 1,
        "invalid V3 path length",
    )?;
    for token in tokens {
        nonzero(*token)?;
    }
    let mut path = tokens[tokens.len() - 1].to_vec();
    for i in (0..fees.len()).rev() {
        ensure(fees[i] > 0 && fees[i] < 1_000_000, "invalid V3 fee")?;
        ensure(tokens[i] != tokens[i + 1], "adjacent V3 tokens must differ")?;
        path.extend_from_slice(&fees[i].to_be_bytes()[1..]);
        path.extend_from_slice(tokens[i].as_slice());
    }
    Ok(path)
}
pub fn validate_v3_path(path: &[u8], weth: Address, output: Address) -> Result<()> {
    ensure(
        path.len() >= 43 && (path.len() - 20).is_multiple_of(23),
        "invalid V3 path length",
    )?;
    let mut tokens = Vec::new();
    let mut fees = Vec::new();
    for offset in (0..path.len()).step_by(23) {
        tokens.push(Address::from_slice(&path[offset..offset + 20]));
        if offset + 20 < path.len() {
            fees.push(u32::from_be_bytes([
                0,
                path[offset + 20],
                path[offset + 21],
                path[offset + 22],
            ]));
        }
    }
    ensure(
        tokens[0] == output && *tokens.last().unwrap() == weth,
        "V3 path endpoints mismatch",
    )?;
    encode_v3_exact_output_path(&tokens, &fees)?;
    Ok(())
}
#[derive(Clone, Debug)]
pub struct ZeroExPayloadOptions {
    pub target: Address,
    pub data: Vec<u8>,
    pub router_address: Address,
    pub token_out: Address,
    pub amount_out: U256,
    pub max_input: U256,
    pub settler_address: Address,
    pub allowance_holder_address: Address,
    pub now: u64,
}
#[derive(Clone, Debug)]
pub struct CheckedZeroExPayload {
    pub target: Address,
    pub data: Vec<u8>,
    pub settler_address: Address,
    pub native_deadline: U256,
}
/// Validate the native envelope and canonicalize its ABI encoding; route actions remain opaque.
pub fn validate_zeroex_payload(o: &ZeroExPayloadOptions) -> Result<CheckedZeroExPayload> {
    for a in [
        o.target,
        o.settler_address,
        o.allowance_holder_address,
        o.router_address,
    ] {
        nonzero(a)?;
    }
    ensure(
        o.settler_address != o.allowance_holder_address && o.settler_address != o.router_address,
        "invalid Settler deployment",
    )?;
    uint(o.max_input, 256, true, "invalid native budget")?;
    uint(o.amount_out, 128, true, "invalid funding amount")?;
    let wrapped = o.target == o.allowance_holder_address;
    let (data, allowance) = if wrapped {
        let args = abi::execCall::abi_decode_validate(&o.data)?;
        ensure(
            args.operator == o.settler_address && args.target == o.settler_address,
            "0x nested target mismatch",
        )?;
        ensure(args.token == NATIVE_TOKEN, "0x input must be native ETH")?;
        ensure(args.amount <= o.max_input, "0x allowance exceeds budget")?;
        (args.data.to_vec(), args.amount)
    } else {
        ensure(
            o.target == o.settler_address,
            "0x target is not the current Settler",
        )?;
        (o.data.clone(), U256::ZERO)
    };
    let args = abi::executeCall::abi_decode_validate(&data)?;
    ensure(
        args.slippage.recipient == o.router_address,
        "0x recipient mismatch",
    )?;
    ensure(
        args.slippage.buyToken == o.token_out,
        "0x output token mismatch",
    )?;
    ensure(
        args.slippage.minAmountOut == o.amount_out,
        "0x exact output amount mismatch",
    )?;
    let mut deadline = None;
    for action in &args.actions {
        ensure(action.len() >= 4, "malformed 0x action")?;
        if action[..4] != abi::NATIVE_CHECKCall::SELECTOR {
            continue;
        }
        ensure(
            action.len() == 68 && deadline.is_none(),
            "invalid or duplicate native guard",
        )?;
        let guard = abi::NATIVE_CHECKCall::abi_decode_validate(action)?;
        ensure(
            guard.deadline >= U256::from(o.now) && guard.msgValue == o.max_input,
            "0x native deadline or budget mismatch",
        )?;
        deadline = Some(guard.deadline);
    }
    let native_deadline = deadline.ok_or(crate::Error::Invalid("missing 0x native guard"))?;
    let canonical = args.abi_encode();
    let data = if wrapped {
        abi::execCall {
            operator: o.settler_address,
            token: NATIVE_TOKEN,
            amount: allowance,
            target: o.settler_address,
            data: canonical.into(),
        }
        .abi_encode()
    } else {
        canonical
    };
    Ok(CheckedZeroExPayload {
        target: o.target,
        data,
        settler_address: o.settler_address,
        native_deadline,
    })
}
