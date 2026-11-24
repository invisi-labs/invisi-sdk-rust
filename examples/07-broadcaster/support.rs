use invisi_sdk::{rpc::ProtocolDeployment, sdk};
#[cfg(feature = "sqlite")]
use invisi_sdk::{
    rpc::{EthereumChain, HttpTransport},
    sdk::Wallet,
};
use std::{env, fs, sync::Arc};
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

#[cfg(feature = "sqlite")]
#[allow(dead_code)]
pub struct SessionRuntime {
    pub chain: Arc<sdk::RpcChainState<EthereumChain<HttpTransport>>>,
    pub session: invisi_sdk_session::session::WalletSession,
    pub prover: Arc<invisi_sdk::prover::NativeProver>,
    pub from_block: u64,
}
#[cfg(feature = "sqlite")]
#[allow(dead_code)]
pub fn session_runtime() -> Result<SessionRuntime, Box<dyn std::error::Error>> {
    use invisi_sdk_session::session::{sqlite::SQLiteRecords, EncryptedWalletStore, WalletSession};
    let deployment: ProtocolDeployment =
        serde_json::from_slice(&fs::read(env::var("DEPLOYMENT_JSON")?)?)?;
    let from_block = deployment.protocol.from_block;
    let chain = Arc::new(sdk::RpcChainState::new(
        EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?),
        deployment.clone(),
    )?);
    let prover = Arc::new(invisi_sdk::prover::NativeProver {
        bb_binary: env::var("BB_BINARY")?.into(),
        timeout: std::time::Duration::from_secs(600),
        threads: 4,
        assets: invisi_sdk_examples::prover_assets(),
        witness_executor: Arc::new(invisi_sdk::prover::NoirCli {
            binary: env::var("NOIR_EXECUTOR")?.into(),
            timeout: std::time::Duration::from_secs(120),
        }),
    });
    let mut invisi = sdk::Invisi::new(chain.clone()).with_prover(prover.clone())?;
    if env::var("SOURCE_PROVIDER_ID").is_ok() {
        invisi = invisi.with_provenance(Arc::new(
            sdk::PreparedProvenance::from_local_configuration(source_configuration()?)?,
        ))?;
    }
    let source = Arc::new(invisi_sdk::rpc::ProtocolRpcClient::new(
        HttpTransport::protocol(&env::var("PROTOCOL_RPC_URL")?, deployment.chain_id()?)?,
        EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?),
        deployment,
    )?);
    let key = zeroize::Zeroizing::new(fs::read(env::var("WALLET_STORE_KEY_FILE")?)?);
    let storage_key: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| "storage key must contain 32 raw bytes")?;
    let store = Arc::new(EncryptedWalletStore::new(
        Arc::new(SQLiteRecords::open(env::var("WALLET_DB")?)?),
        storage_key,
    )?);
    let wallet = Wallet::from_address(&env::var("WALLET_ADDRESS")?)?;
    let session = WalletSession::connect(invisi, wallet, store, source, "source-examples")?;
    Ok(SessionRuntime {
        chain,
        session,
        prover,
        from_block,
    })
}
#[allow(dead_code)]
pub fn confirmation_timeout() -> Result<std::time::Duration, Box<dyn std::error::Error>> {
    Ok(std::time::Duration::from_secs(
        env::var("CONFIRMATION_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "180".into())
            .parse()?,
    ))
}
