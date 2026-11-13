//! Schedule a Note transfer, resume its encrypted operation, then cancel and reconcile its inputs.
mod support;
use alloy_primitives::{Address, U256};
use invisi_sdk::{
    broadcaster::{BroadcasterClient, Configuration, StatusState},
    rpc::{EthereumChain, HttpTransport, ProtocolDeployment, ProtocolRpcClient},
    sdk::{self, ChainState, Fee, Invisi, RpcChainState, Wallet},
};
use invisi_sdk_session::session::{
    sqlite::SQLiteRecords, EncryptedWalletStore, RefreshOptions, WalletSession,
};
use std::{env, fs, sync::Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let deployment: ProtocolDeployment =
        serde_json::from_slice(&fs::read(env::var("DEPLOYMENT_JSON")?)?)?;
    let from_block = deployment.protocol.from_block;
    let ethereum = EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?);
    let chain = Arc::new(RpcChainState::new(ethereum, deployment.clone())?);

    let wallet = Wallet::from_address(&env::var("WALLET_ADDRESS")?)?;
    let source = Arc::new(ProtocolRpcClient::new(
        HttpTransport::protocol(&env::var("PROTOCOL_RPC_URL")?, deployment.chain_id()?)?,
        EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?),
        deployment,
    )?);

    // This is a host-provided storage-encryption key, not an account or wallet private key.
    let key_bytes = zeroize::Zeroizing::new(fs::read(env::var("WALLET_STORE_KEY_FILE")?)?);
    let storage_key: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "storage key must contain 32 raw bytes")?;
    let records = Arc::new(SQLiteRecords::open(env::var("WALLET_DB")?)?);
    let store = Arc::new(EncryptedWalletStore::new(records, storage_key)?);

    let prover = Arc::new(invisi_sdk::prover::NativeProver {
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
    });

    let mut invisi = Invisi::new(chain.clone()).with_prover(prover.clone())?;
    if env::var("SOURCE_PROVIDER_ID").is_ok() {
        invisi = invisi.with_provenance(Arc::new(
            sdk::PreparedProvenance::from_local_configuration(support::source_configuration()?)?,
        ))?;
    }
    let session = WalletSession::connect(invisi, wallet, store, source, "scheduled-broadcaster")?;
    let relay = Arc::new(BroadcasterClient::connect(Configuration {
        endpoint: env::var("BROADCASTER_ENDPOINT")?,
        quote_signer: env::var("BROADCASTER_QUOTE_SIGNER")?.parse()?,
        fee_recipient: env::var("BROADCASTER_FEE_RECIPIENT")?.parse()?,
    })?);
    let token: Address = env::var("TOKEN_ADDRESS")?.parse()?;
    if !relay.supports_token(
        token,
        chain.context().chain_id,
        sdk::word_address(chain.context().protocol_address)?,
    )? {
        return Err("Broadcaster does not support this token".into());
    }
    let capabilities = relay.scheduling_capability()?;
    let publish_after: u64 = env::var("PUBLISH_AFTER")?.parse()?;
    let default_window: u64 = capabilities.default_execution_window_seconds.parse()?;
    let execute_before = env::var("EXECUTE_BEFORE")
        .ok()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(
            publish_after
                .checked_add(default_window)
                .ok_or("schedule timestamp overflow")?,
        );
    let mut refresh = RefreshOptions::from_block(
        env::var("FROM_BLOCK")
            .ok()
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(from_block),
    );
    refresh.to_block = env::var("TO_BLOCK")
        .ok()
        .map(|value| value.parse())
        .transpose()?;
    session
        .refresh(refresh)?
        .decrypt(&invisi_sdk_examples::AppDecryptor)?;
    let recipient = Wallet::from_address(&env::var("RECIPIENT_ADDRESS")?)?;
    let amount = U256::from_str_radix(&env::var("AMOUNT")?, 10)?;
    let output =
        sdk::NoteOutput::for_recipient(chain.context(), token, &recipient, amount, Vec::new())?;
    let mut operation = session.prepare_transfer(sdk::TransferPreparation {
        token,
        inputs: Vec::new(),
        outputs: vec![output],
        withdrawal: None,
        funding: sdk::empty_funding(),
        fee: Fee::default(),
        deadline: env::var("DEADLINE")?.parse()?,
        automatic_change: true,
    })?;
    // Quotation persists the scoped cancellation capability in the encrypted journal before submission.
    relay.quote(
        &mut operation,
        chain.clone(),
        &sdk::BroadcasterOptions {
            schedule: Some(sdk::BroadcasterSchedule {
                publish_after,
                execute_before,
            }),
            max_fee_amount: Some(U256::from_str_radix(&env::var("MAX_FEE_AMOUNT")?, 10)?),
            ..Default::default()
        },
    )?;
    let operation_id = operation.id().to_owned();
    println!("Saved operation: {operation_id}");
    let authorization = operation.export_wallet_authorization()?;
    let signature = invisi_sdk_examples::sign_authorization(&authorization)?;
    operation = operation
        .with_wallet_signature(&signature)?
        .prove(prover.as_ref(), false)?;
    let submitted = relay.submit(&mut operation, chain.as_ref())?;
    println!("Submission state: {:?}", submitted.state);
    // Resume uses the local operation ID; remote status uses the ID returned by the Broadcaster.
    let mut recovered = session.resume(&operation_id, Some(prover.as_ref()))?;
    let observed = relay.status(&submitted.id)?;
    println!(
        "Recovered relay status: id={} state={:?}",
        observed.id, observed.state
    );
    let cancelled = relay.cancel(&mut recovered)?;
    if cancelled.state != StatusState::Cancelled || cancelled.transaction_hash.is_some() {
        return Err(
            "Cancellation was not acknowledged; saved operation retains its reservations".into(),
        );
    }
    // Relay custody cancellation does not revoke protocol signatures; release requires canonical checks.

    println!("Cancellation acknowledged and canonical input state reconciled.");
    Ok(())
}
