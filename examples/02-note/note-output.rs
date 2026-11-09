//! Build a 70-unit encrypted Note with the memo "Invoice 42", using only the recipient's public
//! receiving address.

use alloy_primitives::{address, U256};
use invisi_sdk::{
    note::ProtocolContext,
    payload::{encode_funds_v1, FundsDataV1},
    sdk::{NoteOutput, Wallet},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Public fixture receiving address. No private key or network connection is needed.
    let recipient = Wallet::from_address("0i0e0525SFRf53yh2aljmm3sn9JQ5nJk7LqWt0G2ajnRY2pe698y550QXhp9uELXpcCZMf5Y608rRDJ68jJgfEWy5j7U5e5eVNPVz8vW2W2kmyw4p9lVLwW3z3WeFHQs5KdfR980CX")?;
    let context = ProtocolContext {
        chain_id: 31337,
        protocol_address: U256::from(0x1234),
    };

    // Application memo bytes stay inside the encrypted delivery; financial fields remain
    // commitment-bound.
    let payload = encode_funds_v1(&FundsDataV1 {
        memo: b"Invoice 42".to_vec(),
    })?;
    let output = NoteOutput::for_recipient(
        context,
        address!("0000000000000000000000000000000000005678"),
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
