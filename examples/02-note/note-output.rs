//! Build a 70-unit encrypted Note with the memo "Invoice 42", using only the recipient's public
//! receiving address.

use alloy_primitives::{Address, U256};
use invisi_sdk::{
    note::ProtocolContext,
    payload::{encode_funds_v1, FundsDataV1},
    sdk::{NoteOutput, Wallet},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Public fixture receiving address. No private key or network connection is needed.
    let receiving_address = std::env::var("RECIPIENT_ADDRESS").unwrap_or_else(|_| "0i0e0525SFRf53yh2aljmm3sn9JQ5nJk7LqWt0G2ajnRY2pe698y550QXhp9uELXpcCZMf5Y608rRDJ68jJgfEWy5j7U5e5eVNPVz8vW2W2kmyw4p9lVLwW3z3WeFHQs5KdfR980CX".into());
    let recipient = Wallet::from_address(&receiving_address)?;
    let context = ProtocolContext {
        chain_id: std::env::var("CHAIN_ID")
            .unwrap_or_else(|_| "31337".into())
            .parse()?,
        protocol_address: std::env::var("PROTOCOL_ADDRESS")
            .ok()
            .map(|value| {
                value
                    .parse::<Address>()
                    .map(|address| U256::from_be_slice(address.as_slice()))
            })
            .transpose()?
            .unwrap_or(U256::from(0x1234)),
    };

    // Application memo bytes stay inside the encrypted delivery; financial fields remain
    // commitment-bound.
    let payload = encode_funds_v1(&FundsDataV1 {
        memo: b"Invoice 42".to_vec(),
    })?;
    let output = NoteOutput::for_recipient(
        context,
        std::env::var("TOKEN_ADDRESS")
            .unwrap_or_else(|_| "0x0000000000000000000000000000000000005678".into())
            .parse()?,
        &recipient,
        U256::from(70),
        payload,
    )?;

    println!("Commitment: {}", output.commitment());
    println!(
        "Encrypted envelope bytes: {}",
        output.delivery().ciphertext.len()
    );
    println!("FMD clue bytes: {}", output.delivery().clue.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn configured_token_address_is_validated() {
        let old = std::env::var_os("TOKEN_ADDRESS");
        std::env::set_var("TOKEN_ADDRESS", "invalid-address");
        let result = super::main();
        match old {
            Some(value) => std::env::set_var("TOKEN_ADDRESS", value),
            None => std::env::remove_var("TOKEN_ADDRESS"),
        }
        assert!(result.is_err(), "configured token must not be ignored");
    }
}
