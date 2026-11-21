//! Payer funds ERC20 principal and signs the Router intent; Broadcaster pays gas.
mod support;
pub use support::{payment_intent, payment_preparation, relay_token, RouteSelection};
fn main() {
    println!("Host recipe: relay_token quotes the unproved Core draft, proves Core, signs Router intent, simulates the final envelope and submits it. Supply a real wallet, prover, Router allowance/permit and trusted Broadcaster. Main does no I/O beyond this message.");
}
