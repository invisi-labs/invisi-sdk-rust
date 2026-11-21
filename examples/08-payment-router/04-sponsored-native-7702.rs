//! Broadcaster pays outer gas; the delegated payer EOA supplies native principal.
mod support;
pub use support::{payment_intent, payment_preparation, relay_native, RouteSelection};
fn main() {
    println!("Host recipe: relay_native quotes unsigned account/7702 metadata before proving and wallet signing, then simulates and submits the exact envelope. Supply independently pinned account implementation and actual EOA authorization nonce. Delegation persists after a payment revert. Main performs no RPC, proof, signature or submission.");
}
