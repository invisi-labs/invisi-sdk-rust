use alloy_primitives::{Address, B256, U256};
use invisi_sdk::broadcaster::{provenance::ProvenanceBroadcasterClient, Configuration};
use invisi_sdk::note::{ModelError, ModelResult};
use invisi_sdk::provenance::*;
use invisi_sdk::provenance_client::ProvenanceClient;
use invisi_sdk::rpc::{HttpTransport, JsonRpc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const PIN: &str = "f90f2ce43218de158c6392fa19e6517dda703c35823a4aa5bfc20b50788ad282";
fn text(v: &Value) -> Result<&str, Box<dyn std::error::Error>> {
    Ok(v.as_str().ok_or("Expected string")?)
}
fn number(v: &Value) -> Result<U256, Box<dyn std::error::Error>> {
    Ok(parse_integer(text(v)?, 256)?)
}

// The SDK deliberately injects this capability. This example host runs local executables,
// authenticates local artifacts/VK, and independently verifies before returning proof bytes.
struct LocalHost {
    assets: PathBuf,
    noir: String,
    bb: String,
}
impl OfflineProver for LocalHost {
    fn prove(
        &self,
        pin: &str,
        capacity: usize,
        witness: &Witness,
        expected: &[String],
    ) -> ModelResult<(Vec<String>, Vec<u8>)> {
        let run = || -> Result<(Vec<String>, Vec<u8>), Box<dyn std::error::Error>> {
            if pin != PIN {
                return Err("Manifest mismatch".into());
            }
            let manifest = fs::read(self.assets.join("manifest.json"))?;
            let identity = authenticate_manifest(&manifest, PIN)?;
            let entry = identity
                .manifest
                .circuits
                .iter()
                .find(|e| e.capacity == capacity)
                .ok_or("Capacity")?;
            let paths: Value = serde_json::from_slice(&manifest)?;
            let paths = paths["circuits"]
                .as_array()
                .ok_or("Manifest circuits")?
                .iter()
                .find(|e| e["capacity"] == capacity)
                .ok_or("Capacity")?;
            let artifact = fs::read(self.assets.join(text(&paths["artifact"])?))?;
            let vk = fs::read(self.assets.join(text(&paths["vk"])?))?;
            if hex::encode(Sha256::digest(&artifact)) != entry.artifact_sha256
                || hex::encode(Sha256::digest(&vk)) != entry.vk_sha256
            {
                return Err("Asset mismatch".into());
            }
            // TempDir is private and removed on every return; witnesses never go to a remote prover.
            let dir = tempfile::tempdir()?;
            let p = dir.path();
            fs::write(p.join("artifact.json"), artifact)?;
            fs::write(p.join("vk"), vk)?;
            fs::write(p.join("witness.json"), serde_json::to_vec(witness)?)?;
            let path = |s: &str| p.join(s).to_string_lossy().into_owned();
            for (binary, args) in [
                (
                    &self.noir,
                    vec![
                        "-a".into(),
                        path("artifact.json"),
                        "-p".into(),
                        path("witness.json"),
                        "-o".into(),
                        path(""),
                        "-w".into(),
                        "witness".into(),
                    ],
                ),
                (
                    &self.bb,
                    vec![
                        "prove".into(),
                        "-t".into(),
                        "evm".into(),
                        "-b".into(),
                        path("artifact.json"),
                        "-w".into(),
                        path("witness.gz"),
                        "-k".into(),
                        path("vk"),
                        "-o".into(),
                        path(""),
                        "--output_format".into(),
                        "json".into(),
                    ],
                ),
            ] {
                if !Command::new(binary)
                    .args(args)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()?
                    .success()
                {
                    return Err("Local proving failed".into());
                }
            }
            let proof: Value = serde_json::from_slice(&fs::read(p.join("proof.json"))?)?;
            if proof["bb_version"] != "6.0.0" {
                return Err("BB version".into());
            }
            let public: Value = serde_json::from_slice(&fs::read(p.join("public_inputs.json"))?)?;
            let public = public["public_inputs"].as_array().ok_or("Public inputs")?;
            if public.len() != 13 || expected.len() != 13 {
                return Err("Statement width".into());
            }
            let mut public_bytes = Vec::new();
            for (v, e) in public.iter().zip(expected) {
                let n = number(v)?;
                if n != parse_integer(e, 256)? {
                    return Err("Statement mismatch".into());
                };
                public_bytes.extend(n.to_be_bytes::<32>())
            }
            let mut bytes = Vec::new();
            for v in proof["proof"].as_array().ok_or("Proof words")? {
                bytes.extend(number(v)?.to_be_bytes::<32>())
            }
            if bytes.is_empty() || bytes.len() > 65536 {
                return Err("Proof size".into());
            }
            fs::write(p.join("proof"), &bytes)?;
            fs::write(p.join("public_inputs"), public_bytes)?;
            if !Command::new(&self.bb)
                .args([
                    "verify",
                    "-t",
                    "evm",
                    "-k",
                    &path("vk"),
                    "-p",
                    &path("proof"),
                    "-i",
                    &path("public_inputs"),
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?
                .success()
            {
                return Err("Independent verification failed".into());
            }
            Ok((expected.to_vec(), bytes))
        };
        run().map_err(|_| ModelError::Invalid("local provenance proving"))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !env::args().any(|a| a == "--execute") {
        println!("Pass --execute to prove/quote; add --submit to broadcast. See README.");
        return Ok(());
    }
    let config: Value = serde_json::from_slice(&fs::read(env::var("PROVENANCE_CONFIG")?)?)?;
    let trust = TrustContext {
        scope: Scope {
            chain_id: number(&config["chainId"])?.to(),
            protocol_address: number(&config["protocolAddress"])?,
            policy_id: number(&config["policyId"])?,
        },
        chain_generation: number(&config["generation"])?.to(),
        provider_id: number(&config["providerId"])?,
        manifest_sha256: PIN.into(),
        signing_keys: BTreeMap::from([(
            number(&config["signingKeyId"])?,
            hex::decode(text(&config["signingPublicKey"])?.trim_start_matches("0x"))?
                .try_into()
                .map_err(|_| "Signing key width")?,
        )]),
        signing_key_validity: BTreeMap::new(),
    };
    let source = ProvenanceClient::new(text(&config["endpoint"])?, trust.clone())?;
    source.get_version()?;
    // Read the host's exact final main-proof statement and one opening locally, never over HTTP.
    let mut local = String::new();
    std::io::stdin().take(1 << 20).read_to_string(&mut local)?;
    let prepared: Value = serde_json::from_str(&local)?;
    drop(local);
    let root = source.get_root(text(&prepared["rootId"])?)?;
    if root["allowedForNewProof"] != true {
        return Err("Root unavailable".into());
    }
    let cert: RootCertificate = serde_json::from_value(root["certificate"].clone())?;
    let primary = JsonRpc::new(HttpTransport::new(text(&config["chainRpcUrl"])?)?);
    if number(&primary.call("eth_chainId", json!([]))?)? != U256::from(trust.scope.chain_id) {
        return Err("Primary chain mismatch".into());
    }
    let anchor = primary.call(
        "eth_getBlockByNumber",
        json!([
            format!("0x{:x}", parse_integer(&cert.confirmed_block_number, 64)?),
            false
        ]),
    )?;
    if anchor["hash"] != cert.confirmed_block_hash {
        return Err("Checkpoint anchor is not canonical".into());
    }
    let tree = source.sync_recognized_tree(text(&prepared["rootId"])?, &cert, 100000)?;
    let opening = Opening {
        owner: number(&prepared["opening"]["owner"])?,
        nonce: number(&prepared["opening"]["nonce"])?,
        amount: number(&prepared["opening"]["amount"])?,
    };
    let token = number(&prepared["tokenAddress"])?;
    let (commitment, nullifier) = note_opening(&trust.scope, token, &opening)?;
    let membership = tree
        .membership_for_commitment(&trust.scope, commitment)?
        .ok_or("Note not recognized")?;
    let public = prepared["publicInputs"]
        .as_array()
        .ok_or("Native public inputs")?
        .iter()
        .map(number)
        .collect::<Result<Vec<_>, _>>()?;
    let capacity: usize = number(&prepared["mainCircuitCapacity"])?
        .try_into()
        .map_err(|_| "Main capacity")?;
    if !(1..=190).contains(&capacity) || public.len() != 17 + 3 * capacity {
        return Err("Native statement width".into());
    }
    if public[0] != U256::from(trust.scope.chain_id)
        || public[1] != trust.scope.protocol_address
        || public[2] != token
        || public[3] != U256::from(1)
        || public[6 + 2 * capacity] != nullifier
    {
        return Err("Main statement does not spend this exact one-input Note".into());
    }
    let digest = operation_digest(
        &trust.scope,
        number(&prepared["mainCircuitCapacity"])?.to(),
        &public,
    )?;
    let assets = PathBuf::from(text(&config["assetRoot"])?);
    let identity = authenticate_manifest(&fs::read(assets.join("manifest.json"))?, PIN)?;
    let host = LocalHost {
        assets,
        noir: env::var("NOIR_EXECUTOR")?,
        bb: env::var("BB_BINARY")?,
    };
    // K1 is one private input, independently of the main circuit's total slots.
    let sidecar = export_sidecar(
        &WitnessRequest {
            scope: trust.scope.clone(),
            capacity: 1,
            token_address: token,
            chain_generation: trust.chain_generation,
            operation_digest: U256::from_be_bytes(digest),
            inputs: vec![WitnessInput {
                opening,
                source_index: 0,
                leaf_index: membership.leaf_index,
                path: membership.path,
            }],
            sources: vec![Source {
                tree_id: parse_integer(&cert.tree_id, 64)?.to(),
                root: parse_integer(&cert.root, 256)?,
                leaf_count: parse_integer(&cert.leaf_count, 64)?.to(),
            }],
        },
        &[cert],
        &trust,
        &identity,
        &host,
        0,
    )?;
    let relay = ProvenanceBroadcasterClient::connect(
        Configuration {
            endpoint: text(&config["broadcaster"]["endpoint"])?.into(),
            quote_signer: text(&config["broadcaster"]["quoteSigner"])?.parse::<Address>()?,
            fee_recipient: text(&config["broadcaster"]["feeRecipient"])?.parse()?,
        },
        B256::from(trust.scope.policy_id.to_be_bytes::<32>()),
    )?;
    let evaluated =
        source.evaluate_transaction(prepared["data"].clone(), std::slice::from_ref(&sidecar))?;
    let tracking = invisi_sdk::provenance_tracking::preflight_tracking(
        &evaluated,
        "0",
        &format!("0x{}", hex::encode(digest)),
    )?;
    let data = hex::decode(text(&prepared["data"])?.trim_start_matches("0x"))?;
    // Fees are already frozen in this calldata; changed fee/data requires fresh main/source proofs.
    let quote = relay.quote(
        &data,
        trust.scope.chain_id,
        text(&config["protocolAddress"])?.parse()?,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        std::slice::from_ref(&sidecar),
    )?;
    let id = env::var("BROADCAST_ID")?;
    if id.is_empty() || id.len() > 63 || !id.bytes().all(|b| (33..=126).contains(&b)) {
        return Err("Stable ASCII BROADCAST_ID required, maximum 63 bytes".into());
    }
    let record = json!({"data":prepared["data"],"sidecar":sidecar,"broadcastId":id,"quote":quote.signed(),"operationDigest":format!("0x{}",hex::encode(digest)),"trackingId":tracking.id});
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(env::var("PROVENANCE_RECORD")?)?;
    file.write_all(&serde_json::to_vec_pretty(&record)?)?;
    file.sync_all()?;
    println!("Public sidecar and verified quote saved; keep the record for confirmation/recovery.");
    if env::args().any(|a| a == "--submit") {
        println!(
            "Broadcaster status: {:?}",
            relay.submit(&data, &quote, &id, &[sidecar])?
        )
    }
    // An uncertain response is not a failed payment: recover this ID without recreating payment.
    Ok(())
}

#[test]
#[ignore = "requires the pinned local release and Noir/BB tools"]
fn real_local_host_proves_and_verifies_k1() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env::var("INVISI_PROTOCOL_ROOT")?);
    let golden: Value = serde_json::from_slice(&fs::read(
        root.join("circuits/provenance/golden-vectors.json"),
    )?)?;
    let witness = golden["witnessK1"].as_object().ok_or("Witness")?;
    let expected = PUBLIC_INPUTS
        .iter()
        .map(|key| {
            Ok(format!(
                "0x{}",
                hex::encode(number(&witness[*key])?.to_be_bytes::<32>())
            ))
        })
        .collect::<Result<Vec<String>, Box<dyn std::error::Error>>>()?;
    let host = LocalHost {
        assets: PathBuf::from(env::var("PROVENANCE_ASSETS")?),
        noir: env::var("NOIR_EXECUTOR")?,
        bb: env::var("BB_BINARY")?,
    };
    let (public, proof) = host.prove(PIN, 1, witness, &expected)?;
    assert_eq!(public, expected);
    assert!(!proof.is_empty());
    let mut changed = expected.clone();
    changed[12] = "0x01".into();
    assert!(host.prove(PIN, 1, witness, &changed).is_err());
    Ok(())
}
