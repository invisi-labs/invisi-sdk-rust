use alloy_primitives::{Address, B256, U256};
use invisi_sdk::broadcaster::{BroadcasterClient, Configuration};
use invisi_sdk::note::{ModelError, ModelResult};
use invisi_sdk::provenance::*;
use invisi_sdk::provenance_client::ProvenanceClient;
use invisi_sdk::rpc::HttpTransport;
use invisi_sdk::{
    rpc::{EthereumChain, ProtocolDeployment, ProtocolRpcClient},
    sdk::{
        self, BroadcasterOptions, ChainState, Invisi, PreparedProvenance, SourceReplayBudgets,
        Wallet,
    },
    session::{MemoryWalletStore, RefreshOptions, WalletSession},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::{
    collections::BTreeMap,
    env, fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
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
    let source = Arc::new(ProvenanceClient::new(
        text(&config["endpoint"])?,
        trust.clone(),
    )?);
    let deployment: ProtocolDeployment =
        serde_json::from_slice(&fs::read(env::var("DEPLOYMENT_JSON")?)?)?;
    let primary_url = text(&config["chainRpcUrl"])?;
    let chain = Arc::new(sdk::RpcChainState::new(
        EthereumChain::new(HttpTransport::new(primary_url)?),
        deployment.clone(),
    )?);
    let assets = PathBuf::from(text(&config["assetRoot"])?);
    let identity = authenticate_manifest(&fs::read(assets.join("manifest.json"))?, PIN)?;
    let invisi = Invisi::new(chain.clone()).with_provenance(Arc::new(PreparedProvenance {
        client: source,
        manifest: identity,
        prover: Arc::new(LocalHost {
            assets,
            noir: env::var("NOIR_EXECUTOR")?,
            bb: env::var("BB_BINARY")?,
        }),
        budgets: SourceReplayBudgets::default(),
    }))?;
    let wallet = Wallet::from_address(&env::var("WALLET_ADDRESS")?)?;
    let recipient = Wallet::from_address(&env::var("RECIPIENT_ADDRESS")?)?;
    let token: Address = env::var("TOKEN_ADDRESS")?.parse()?;
    let rpc = Arc::new(ProtocolRpcClient::new(
        HttpTransport::protocol(&env::var("PROTOCOL_RPC_URL")?, deployment.chain_id()?)?,
        EthereumChain::new(HttpTransport::new(primary_url)?),
        deployment.clone(),
    )?);
    // Discovery only retains openings in local memory; the public source/relay APIs never receive them.
    let discovery = WalletSession::connect(
        invisi.clone(),
        wallet.clone(),
        Arc::new(MemoryWalletStore::default()),
        rpc,
        "provenance-example",
    )?;
    let pending = discovery.refresh(RefreshOptions::from_block(deployment.protocol.from_block))?;
    println!(
        "Native discovery requests: {}",
        serde_json::to_string(pending.wallet_requests())?
    );
    let responses: Vec<sdk::WalletResponse> = if pending.wallet_requests().is_empty() {
        Vec::new()
    } else {
        eprintln!("Execute the discovery array in your native host and paste its response array:");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        serde_json::from_str(&line)?
    };
    pending.apply_wallet_responses(&responses)?;
    let state = discovery.snapshot()?;
    let inputs = state
        .notes
        .values()
        .filter(|n| {
            !n.spent
                && n.reserved_by.is_none()
                && n.input.note.token_address == sdk::address_word(token)
        })
        .map(|n| n.input.clone())
        .collect::<Vec<_>>();
    if inputs.is_empty() {
        return Err("No discovered unspent private Notes".into());
    }
    let output = sdk::NoteOutput::for_recipient(
        chain.context(),
        token,
        &recipient,
        U256::from_str_radix(&env::var("AMOUNT")?, 10)?,
        Vec::new(),
    )?;
    let prepared = invisi.prepare_transfer(
        &wallet,
        sdk::TransferPreparation {
            token,
            inputs,
            outputs: vec![output],
            withdrawal: None,
            funding: sdk::empty_funding(),
            fee: sdk::Fee::default(),
            deadline: env::var("DEADLINE")?.parse()?,
            automatic_change: true,
        },
    )?;
    let relay = Arc::new(
        BroadcasterClient::connect(Configuration {
            endpoint: text(&config["broadcaster"]["endpoint"])?.into(),
            quote_signer: text(&config["broadcaster"]["quoteSigner"])?.parse()?,
            fee_recipient: text(&config["broadcaster"]["feeRecipient"])?.parse()?,
        })?
        .with_provenance_policy(B256::from(trust.scope.policy_id.to_be_bytes::<32>()))?,
    );
    // Fee convergence, local source proving, tracking and the signed quote all precede consent.
    let prepared =
        prepared.with_broadcaster(chain.clone(), relay.clone(), &BroadcasterOptions::default())?;
    let request = prepared.export_wallet_request("provenance-transfer")?;
    println!(
        "Native wallet requests: {}",
        serde_json::to_string(std::slice::from_ref(&request))?
    );
    eprintln!("Approve in your native host and paste its response array:");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let responses: Vec<sdk::WalletResponse> = serde_json::from_str(&line)?;
    wallet.accept_batch(std::slice::from_ref(&request), &responses)?;
    let response = responses
        .iter()
        .find(|r| r.id == request.id)
        .ok_or("Missing wallet response")?;
    let main_prover = invisi_sdk::prover::NativeProver {
        bb_binary: env::var("BB_BINARY")?.into(),
        timeout: std::time::Duration::from_secs(600),
        threads: 4,
        assets: Arc::new(invisi_sdk::prover::DirectoryAssets {
            directory: env::var("PROVER_ASSETS")?.into(),
        }),
        witness_executor: Arc::new(invisi_sdk::prover::NoirCli {
            binary: env::var("NOIR_EXECUTOR")?.into(),
            timeout: std::time::Duration::from_secs(120),
        }),
    };
    let prepared = prepared
        .with_wallet_response(&request, response)?
        .prove(&main_prover, false)?;
    let saved = prepared.broadcaster_state().ok_or("Missing saved quote")?;
    let tracking = saved
        .tracking
        .as_ref()
        .ok_or("Missing automatic tracking")?;
    let data = prepared.calldata(chain.as_ref(), Address::ZERO)?.data;
    let id = env::var("BROADCAST_ID")?;
    let record = json!({"data":format!("0x{}",hex::encode(&data)),"sidecar":saved.sidecars.first().ok_or("Missing source sidecar")?,"broadcastId":id,"quote":saved.quote,"operationDigest":tracking.operation_digest,"trackingId":tracking.id});
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
    println!("Public source context saved before broadcast; retain it after uncertain responses.");
    if env::args().any(|a| a == "--submit") {
        println!(
            "Broadcaster status: {:?}",
            prepared.submit_broadcaster(chain.as_ref(), relay.as_ref(), &id)?
        );
    }
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
