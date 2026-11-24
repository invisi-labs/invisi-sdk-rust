//! Host-only initialization: derive v1 public receiving material from a local account key.
use alloy_primitives::{keccak256, Address};
use invisi_sdk::{sdk, wallet};
use std::{env, fs, io::Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !env::args().any(|arg| arg == "--execute") {
        println!(
            "Set OWNER_KEY_FILE and VIEWING_KEY_FILE, then pass --execute. No files were opened."
        );
        return Ok(());
    }
    let key = zeroize::Zeroizing::new(fs::read(env::var("OWNER_KEY_FILE")?)?);
    let signer = k256::ecdsa::SigningKey::from_slice(&key)?;
    let public = signer.verifying_key().to_encoded_point(false);
    let owner = Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]);
    let request = sdk::prepare_wallet_request(
        owner,
        "receiving-v1",
        "wallet.public",
        serde_json::json!({}),
    )?;
    let response = wallet::execute(&key, &serde_json::to_value(&request)?)?;
    let public_wallet = sdk::Wallet::from_response(&request, &serde_json::from_value(response)?)?;
    let viewing = wallet::viewing_key(&key)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(env::var("VIEWING_KEY_FILE")?)?;
    file.write_all(&viewing[..])?;
    let detection = wallet::detection_key(&key)?;
    let mut detector = options.open(env::var("DETECTION_KEY_FILE")?)?;
    detector.write_all(&detection[..])?;
    println!(
        "{}",
        serde_json::json!({"ownerAddress":owner,"receivingAddress":public_wallet.address()?})
    );
    Ok(())
}
