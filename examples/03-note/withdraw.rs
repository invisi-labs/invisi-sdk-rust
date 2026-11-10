//! Discover earlier Notes and withdraw AMOUNT to a public EVM address, returning any excess
//! privately.

use alloy_primitives::{Address, U256};
use invisi_sdk::{
    rpc::{EthereumChain, HttpTransport, ProtocolDeployment},
    sdk::{self, ChainState, Fee, Invisi, RpcChainState, Wallet},
};
use serde_json::json;
use std::{env, fs, sync::Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !std::env::args().any(|arg| arg == "--execute") {
        println!("Pass --execute after configuring the environment described in examples/README.md. No network, files or keys were opened.");
        return Ok(());
    }

    if env::args().any(|a| a == "--submit") && env::var("BROADCASTER_CONFIG").is_err() {
        return Err("BROADCASTER_CONFIG required for explicit relay submission".into());
    }

    let deployment: ProtocolDeployment =
        serde_json::from_slice(&fs::read(env::var("DEPLOYMENT_JSON")?)?)?;
    let ethereum = EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?);
    let chain = Arc::new(RpcChainState::new(ethereum, deployment.clone())?);
    let mut invisi = Invisi::new(chain.clone());
    if let Ok(path) = env::var("SOURCE_CONFIG") {
        let config: sdk::LocalProvenanceConfiguration = serde_json::from_slice(&fs::read(path)?)?;
        invisi = invisi.with_provenance(Arc::new(
            sdk::PreparedProvenance::from_local_configuration(config)?,
        ))?;
    }
    let relay = if let Ok(path) = env::var("BROADCASTER_CONFIG") {
        let config: invisi_sdk::broadcaster::Configuration =
            serde_json::from_slice(&fs::read(path)?)?;
        let mut relay = invisi_sdk::broadcaster::BroadcasterClient::connect(config)?;
        let policy = env::var("BROADCASTER_POLICY_ID")
            .ok()
            .map(|p| p.parse::<alloy_primitives::B256>())
            .transpose()?
            .or_else(|| {
                invisi.provenance.as_ref().map(|c| {
                    alloy_primitives::B256::from(c.client.trust.scope.policy_id.to_be_bytes::<32>())
                })
            });
        if let Some(policy) = policy {
            relay = relay.with_provenance_policy(policy)?;
        }
        Some(Arc::new(relay))
    } else {
        None
    };
    if env::args().any(|a| a == "--confirm") {
        let anchor = chain.snapshot()?;
        chain.canonical(&anchor)?;
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(env::var("BROADCAST_RECORD")?)?)?;
        let saved: sdk::PreparedBroadcasterState =
            serde_json::from_value(record["context"].clone())?;
        let relay = relay
            .as_ref()
            .ok_or("BROADCASTER_CONFIG required for retained quote authentication")?;
        if relay.configuration().endpoint != saved.endpoint
            || relay.configuration().quote_signer != saved.signer
            || relay.configuration().fee_recipient != saved.fee_recipient
            || relay.required_policy() != saved.policy
        {
            return Err("retained relay configuration mismatch".into());
        }
        let source = invisi
            .provenance
            .as_ref()
            .ok_or("SOURCE_CONFIG required for source confirmation")?;
        let tracking = saved
            .tracking
            .as_ref()
            .ok_or("saved automatic tracking required")?;
        let primary = invisi_sdk::rpc::JsonRpc::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?);
        let hash = env::var("TRANSACTION_HASH")?;
        let receipt = primary.call("eth_getTransactionReceipt", json!([hash]))?;
        let tx = primary.call("eth_getTransactionByHash", json!([hash]))?;
        if receipt.is_null() || tx.is_null() || receipt["status"] != "0x1" {
            return Err("successful primary receipt not available".into());
        }
        let block = primary.call(
            "eth_getBlockByNumber",
            json!([receipt["blockNumber"], false]),
        )?;
        let to = tx["to"]
            .as_str()
            .ok_or("primary transaction recipient unavailable")?
            .parse::<Address>()?;
        let data = hex::decode(
            record["data"]
                .as_str()
                .ok_or("saved calldata required")?
                .strip_prefix("0x")
                .ok_or("calldata encoding")?,
        )?;
        if tx["hash"] != hash
            || receipt["transactionHash"] != hash
            || block["hash"] != receipt["blockHash"]
            || tx["blockHash"] != receipt["blockHash"]
            || tx["input"] != record["data"]
            || sdk::address_word(to) != chain.context().protocol_address
        {
            return Err("canonical transaction differs from retained relay request".into());
        }
        invisi_sdk::broadcaster::verify_quote_for_policy(
            &saved.quote,
            &invisi_sdk::broadcaster::Trust {
                chain_id: chain.context().chain_id,
                protocol: to,
                signer: saved.signer,
            },
            &data,
            0,
            saved.policy,
        )?;
        let result = source.client.wait_tracking(
            &tracking.id,
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(120),
        )?;
        let current =
            invisi_sdk::provenance_tracking::tracking_from_result(&result, Some(&tracking.id))?;
        let matched = current.matched.ok_or("tracking transaction not matched")?;
        if current.status != "recognized"
            || current.operation_digest != tracking.operation_digest
            || matched.tx_hash != hash
            || matched.block_hash
                != receipt["blockHash"]
                    .as_str()
                    .ok_or("primary block hash unavailable")?
            || matched.operation_index != "0"
        {
            return Err("automatic source recognition not complete for this transaction".into());
        }
        let operation = source.client.get_operation_recognition(
            json!({"txHash":hash,"blockHash":receipt["blockHash"],"operationIndex":"0"}),
        )?;
        if operation["recognitionState"] != "recognized" {
            return Err(
                "source publication pending; retain the same transaction/tracking IDs".into(),
            );
        }
        println!("Source service confirms the primary-confirmed operation; receiver membership verification remains separate.");
        return Ok(());
    }

    let wallet = Wallet::from_address(&env::var("WALLET_ADDRESS")?)?;
    let token: Address = env::var("TOKEN_ADDRESS")?.parse()?;
    let deadline: u64 = env::var("DEADLINE")?.parse()?;

    let (discovery, pending) = invisi_sdk_examples::discover(
        &invisi,
        &wallet,
        deployment.clone(),
        &env::var("PROTOCOL_RPC_URL")?,
        &env::var("ETH_RPC_URL")?,
        env::var("FROM_BLOCK").ok().map(|s| s.parse()).transpose()?,
        env::var("TO_BLOCK").ok().map(|s| s.parse()).transpose()?,
    )?;

    // Only the native host can unlock the account and decrypt these candidates.
    println!(
        "Native discovery requests: {}",
        serde_json::to_string(pending.wallet_requests())?
    );
    let responses: Vec<sdk::WalletResponse> = if pending.wallet_requests().is_empty() {
        Vec::new()
    } else {
        eprintln!(
            "Execute the discovery array in your native host, then paste its response JSON array:"
        );
        let mut response_json = String::new();
        std::io::stdin().read_line(&mut response_json)?;
        serde_json::from_str(&response_json)?
    };

    // Canonical receipts, commitments and membership are checked before any input is selected.
    pending.apply_wallet_responses(&responses)?;
    let discovered = discovery.snapshot()?;

    let to: Address = env::var("WITHDRAWAL_ADDRESS")?.parse()?;
    let amount = U256::from_str_radix(&env::var("AMOUNT")?, 10)?;
    let selection_amount = if let Some(relay) = &relay {
        amount
            .checked_add(U256::from_str_radix(
                &relay.fee(token, None)?.fee_amount,
                10,
            )?)
            .ok_or("selection overflow")?
    } else {
        amount
    };
    let inputs = invisi_sdk_examples::select_notes(&discovered, token, selection_amount)?;
    let mut prepared = invisi.prepare_withdrawal(
        &wallet,
        sdk::WithdrawalPreparation {
            token,
            inputs,
            to,
            amount,
            fee: Fee::default(),
            deadline,
            automatic_change: true,
        },
    )?;

    // Only the restricted owner sweep can omit private approval; ordinary withdrawals require it.
    if let Some(relay) = &relay {
        prepared = prepared.with_broadcaster(
            chain.clone(),
            relay.clone(),
            &sdk::BroadcasterOptions::default(),
        )?;
    }

    if prepared.needs_authorization() {
        let request = prepared.export_wallet_request("withdraw-example")?;
        println!(
            "Native wallet requests: {}",
            serde_json::to_string(std::slice::from_ref(&request))?
        );
        eprintln!("Approve in your native host and paste the one-line response JSON array:");
        let mut response_json = String::new();
        std::io::stdin().read_line(&mut response_json)?;
        prepared = {
            let responses: Vec<sdk::WalletResponse> = serde_json::from_str(&response_json)?;
            wallet.accept_batch(std::slice::from_ref(&request), &responses)?;
            let response = responses
                .iter()
                .find(|response| response.id == request.id)
                .ok_or("missing wallet response")?;
            prepared.with_wallet_response(&request, response)?
        };
    }

    // Keep the prepared withdrawal unchanged while generating and verifying its proof.
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

    let prepared = prepared.prove(&prover, false)?;

    if let Some(relay) = &relay {
        let saved = prepared
            .broadcaster_state()
            .ok_or("saved relay context required")?;
        let data = prepared.calldata(chain.as_ref(), Address::ZERO)?.data;
        let id = env::var("BROADCAST_ID")?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(env::var("BROADCAST_RECORD")?)?;
        use std::io::Write;
        file.write_all(&serde_json::to_vec_pretty(
            &json!({"data":format!("0x{}",hex::encode(data)),"broadcastId":id,"context":saved}),
        )?)?;
        file.sync_all()?;
        println!("Public quote/source/tracking context saved before possible relay submission.");
        if env::args().any(|a| a == "--submit") {
            println!(
                "{:?}",
                prepared.submit_broadcaster(chain.as_ref(), relay.as_ref(), &id)?
            );
        }
        return Ok(());
    }

    let caller: Address = env::var("CALLER_ADDRESS")?.parse()?;
    let call = prepared.calldata(&*chain, caller)?;

    // An EVM signer in the host reviews, signs and broadcasts this unsigned transaction.
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "chainId": chain.context().chain_id.to_string(),
            "from": caller,
            "to": call.to,
            "data": format!("0x{}", hex::encode(call.data)),
            "value": call.value.to_string(),
        }))?
    );
    Ok(())
}
