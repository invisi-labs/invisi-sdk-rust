mod support;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !std::env::args().any(|a| a == "--execute") {
        println!("Pass --execute to prove final public Source evidence before submitting the transaction.");
        return Ok(());
    }
    let (chain, ready) = support::load()?;
    let packet = ready.prove_provenance(chain.as_ref())?;
    println!("{}", serde_json::to_string_pretty(&packet)?);
    let client = support::source_client()?;
    let result = invisi_sdk::sdk::submit_provenance_proof(&client, &packet)?;
    println!("{result}");
    Ok(())
}
