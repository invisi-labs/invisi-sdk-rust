mod support;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !std::env::args().any(|a| a == "--execute") {
        println!("Pass --execute to restore and submit a public Provenance packet before or after its transaction.");
        return Ok(());
    }
    let packet: invisi_sdk::provenance::ProvenanceProof =
        serde_json::from_str(&std::env::var("SOURCE_PROOF_JSON")?)?;
    let client = support::source_client()?;
    let result = invisi_sdk::sdk::submit_provenance_proof(&client, &packet)?;
    println!("{result}");
    Ok(())
}
