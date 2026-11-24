//! Resume a public Source tracking lookup without proving or resubmitting a payment.
mod support;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let id = std::env::args().nth(1).ok_or("tracking ID required")?;
    let source = support::source_client()?;
    let result = source.get_tracking(&id)?;
    invisi_sdk::provenance_tracking::tracking_from_result(&result, Some(&id))?;
    println!("{result}");
    Ok(())
}
