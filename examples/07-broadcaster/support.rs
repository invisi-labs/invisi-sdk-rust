use invisi_sdk::{
    rpc::{EthereumChain, HttpTransport, ProtocolDeployment},
    sdk::{self, ChainState, ManagedPrepared, Wallet},
};
use std::{env, fs, sync::Arc};
#[allow(dead_code)]
pub fn load(
) -> Result<(Arc<dyn sdk::ChainState>, sdk::PreparedTransaction), Box<dyn std::error::Error>> {
    let deployment: ProtocolDeployment =
        serde_json::from_slice(&fs::read(env::var("DEPLOYMENT_JSON")?)?)?;
    let chain = Arc::new(sdk::RpcChainState::new(
        EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?),
        deployment,
    )?);
    let wallet = Wallet::from_address(&env::var("WALLET_ADDRESS")?)?;
    let snapshot: sdk::PreparedSnapshot =
        serde_json::from_slice(&fs::read(env::var("PREPARED_SNAPSHOT")?)?)?;
    let prover = invisi_sdk::prover::NativeProver {
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
    let prepared = match snapshot.restore(&wallet, Some(&prover))? {
        ManagedPrepared::Funds(p) => p,
        _ => return Err("private Note snapshot required".into()),
    };
    let capability = if env::var("SOURCE_PROVIDER_ID").is_ok() {
        Arc::new(sdk::PreparedProvenance::from_local_configuration(
            source_configuration()?,
        )?)
    } else {
        sdk::PreparedProvenance::from_prover(chain.context(), &prover)?
    };
    Ok((chain, prepared.reattach_provenance(capability)?))
}

#[allow(dead_code)]
pub fn source_client(
) -> Result<Arc<invisi_sdk::provenance_client::ProvenanceClient>, Box<dyn std::error::Error>> {
    use invisi_sdk::provenance::{parse_integer, Scope, TrustContext};
    use sha2::Digest;
    if env::var("SOURCE_PROVIDER_ID").is_err() {
        let deployment: ProtocolDeployment =
            serde_json::from_slice(&fs::read(env::var("DEPLOYMENT_JSON")?)?)?;
        return Ok(
            invisi_sdk::provenance_official::OfficialProvenanceClients::new().get(&Scope {
                chain_id: deployment.chain_id.parse()?,
                protocol_address: sdk::address_word(deployment.protocol.address),
            })?,
        );
    }
    let config = source_pins()?;
    let text = |key: &str| -> Result<&str, String> {
        config[key]
            .as_str()
            .ok_or_else(|| format!("missing Source pin {key}"))
    };
    let public: [u8; 32] = hex::decode(text("signingPublicKey")?.trim_start_matches("0x"))?
        .try_into()
        .map_err(|_| "invalid source signing key length")?;
    let key_id = parse_integer(text("signingKeyId")?, 256)?;
    if key_id != alloy_primitives::U256::from_be_slice(&sha2::Sha256::digest(public)) {
        return Err("source signing key ID mismatch".into());
    }
    let trust = TrustContext {
        scope: Scope {
            chain_id: parse_integer(text("chainId")?, 64)?.to::<u64>(),
            protocol_address: parse_integer(text("protocolAddress")?, 160)?,
        },
        chain_generation: parse_integer(text("generation")?, 64)?.to::<u64>(),
        provider_id: parse_integer(text("providerId")?, 256)?,
        signing_keys: std::collections::BTreeMap::from([(key_id, public)]),
        signing_key_validity: std::collections::BTreeMap::new(),
        manifest_sha256: text("manifestSha256")?.into(),
    };
    Ok(Arc::new(
        invisi_sdk::provenance_client::ProvenanceClient::new(
            config["endpoint"].as_str().unwrap_or(""),
            trust,
        )?,
    ))
}

#[allow(dead_code)]
fn source_pins() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(
        serde_json::json!({"endpoint":env::var("SOURCE_ENDPOINT").unwrap_or_else(|_|"https://provenance.invisipay.fi".into()),"chainId":env::var("SOURCE_CHAIN_ID")?,"protocolAddress":env::var("SOURCE_PROTOCOL_ADDRESS")?,"generation":env::var("SOURCE_GENERATION")?,"providerId":env::var("SOURCE_PROVIDER_ID")?,"signingKeyId":env::var("SOURCE_SIGNING_KEY_ID")?,"signingPublicKey":env::var("SOURCE_SIGNING_PUBLIC_KEY")?,"manifestSha256":"6107789c5c0d24c4130bff05da6d389336feb5ccb247c4030eae5198ab05d762"}),
    )
}
#[allow(dead_code)]
pub fn source_configuration(
) -> Result<sdk::LocalProvenanceConfiguration, Box<dyn std::error::Error>> {
    let mut value = source_pins()?;
    value["assetRoot"] = serde_json::json!(env::var("SOURCE_ASSET_ROOT")?);
    value["bbBinary"] = serde_json::json!(env::var("BB_BINARY")?);
    value["noirExecutor"] = serde_json::json!(env::var("NOIR_EXECUTOR")?);
    value["timeoutSeconds"] = serde_json::json!(120);
    value["threads"] = serde_json::json!(4);
    value["budgets"] =
        serde_json::json!({"maxRootPages":10,"maxCertificates":3200,"maxTotalLeaves":100000});
    Ok(serde_json::from_value(value)?)
}
