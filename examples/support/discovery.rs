//! Application discovery and signing adapters; wallet flows remain visible in each example main.
use alloy_primitives::{Address, U256};
use invisi_sdk::{
    credit::{apply_credit_draw_usage, credit_periods},
    delivery::CreditRole,
    rpc::{EthereumChain, HttpTransport, ProtocolDeployment, ProtocolRpcClient},
    sdk::{self, CreditInput, Invisi, NoteInput, Wallet},
};
use invisi_sdk_session::session::{
    MemoryWalletStore, PendingWalletRefresh, RefreshOptions, WalletSession, WalletState,
};
use std::sync::Arc;

type Result<T> = std::result::Result<T, String>;

pub fn discover(
    invisi: &Invisi,
    wallet: &Wallet,
    deployment: ProtocolDeployment,
    protocol_rpc_url: &str,
    ethereum_rpc_url: &str,
    from_block: Option<u64>,
    to_block: Option<u64>,
) -> Result<(WalletSession, PendingWalletRefresh)> {
    let from_block = from_block.unwrap_or(deployment.protocol.from_block);
    let source = Arc::new(
        ProtocolRpcClient::new(
            HttpTransport::protocol(
                protocol_rpc_url,
                deployment.chain_id().map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?,
            EthereumChain::new(HttpTransport::new(ethereum_rpc_url).map_err(|e| e.to_string())?),
            deployment,
        )
        .map_err(|e| e.to_string())?,
    );
    let session = WalletSession::connect(
        invisi.clone(),
        wallet.clone(),
        Arc::new(MemoryWalletStore::default()),
        source,
        "example-discovery",
    )?;
    let mut options = RefreshOptions::from_block(from_block);
    options.to_block = to_block;
    let pending = refresh_receipt_ranges(&session, options)?;
    Ok((session, pending))
}

pub fn note_inputs(state: &WalletState, token: Address) -> Vec<NoteInput> {
    state
        .notes
        .values()
        .filter(|value| {
            !value.spent
                && value.reserved_by.is_none()
                && value.input.note.token_address == sdk::address_word(token)
        })
        .map(|value| value.input.clone())
        .collect()
}

pub fn select_notes(state: &WalletState, token: Address, amount: U256) -> Result<Vec<NoteInput>> {
    if amount == U256::ZERO {
        return Err("positive amount required".into());
    }
    let mut selected = Vec::new();
    let mut total = U256::ZERO;
    for input in note_inputs(state, token) {
        total = total
            .checked_add(input.note.amount)
            .ok_or("Note selection overflow")?;
        selected.push(input);
        if total >= amount {
            return Ok(selected);
        }
    }
    Err("insufficient discovered unspent Notes; wait for the earlier deposit to be indexed".into())
}

pub fn credit_inputs(state: &WalletState, token: Address, role: CreditRole) -> Vec<CreditInput> {
    state
        .credits
        .values()
        .filter(|value| {
            value.role == role
                && value.status == 1
                && !value.consumed
                && !value.revoked
                && value.reserved_by.is_none()
                && value.delivery.note.token_address == sdk::address_word(token)
        })
        .map(|value| CreditInput {
            payload: None,
            delivery: value.delivery.clone(),
            tree_id: value.tree_id,
            leaf_index: value.leaf_index,
            path: value.path,
            root: value.root,
            debit: U256::ZERO,
        })
        .collect()
}

pub fn select_credit_draw(
    state: &WalletState,
    token: Address,
    amount: U256,
    timestamp: u64,
) -> Result<Vec<CreditInput>> {
    if amount == U256::ZERO {
        return Err("positive draw amount required".into());
    }
    let mut remaining = amount;
    let mut selected = Vec::new();
    let (day, month) = credit_periods(timestamp);
    for mut input in credit_inputs(state, token, CreditRole::Spender) {
        let grant = &input.delivery.note;
        if grant.expiry <= timestamp || day < grant.usage.last_day || month < grant.usage.last_month
        {
            continue;
        }
        let mut limit = remaining.min((U256::from(1) << 126) - U256::from(1));
        if !grant.unlimited {
            limit = limit.min(grant.available_credit);
        }
        if grant.policy.single_limit != U256::ZERO {
            limit = limit.min(grant.policy.single_limit);
        }
        for (cap, used) in [
            (
                grant.policy.daily_limit,
                if day == grant.usage.last_day {
                    grant.usage.daily_spent
                } else {
                    U256::ZERO
                },
            ),
            (
                grant.policy.monthly_limit,
                if month == grant.usage.last_month {
                    grant.usage.monthly_spent
                } else {
                    U256::ZERO
                },
            ),
        ] {
            limit = limit.min(U256::from(u128::MAX).saturating_sub(used));
            if cap != U256::ZERO {
                limit = limit.min(cap.saturating_sub(used));
            }
        }
        limit = limit.min(U256::from(u128::MAX).saturating_sub(grant.usage.total_spent));
        if limit == U256::ZERO {
            continue;
        }
        apply_credit_draw_usage(grant, limit, timestamp).map_err(|e| e.to_string())?;
        input.debit = limit;
        remaining -= limit;
        selected.push(input);
        if remaining == U256::ZERO {
            return Ok(selected);
        }
    }
    Err("insufficient discovered drawable Credit; wait for the earlier grant to be indexed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use invisi_sdk::{
        credit::{CreditPolicy, CreditState, CreditUsage},
        delivery::CreditDeliveryState,
        note::{Note, ProtocolContext},
        rpc::CanonicalBlock,
    };
    use invisi_sdk_session::session::{StoredCredit, StoredNote};
    fn block() -> CanonicalBlock {
        CanonicalBlock {
            number: 10,
            hash: B256::with_last_byte(10),
            parent_hash: B256::with_last_byte(9),
            timestamp: 2_000_000_000,
        }
    }
    fn context() -> ProtocolContext {
        ProtocolContext {
            chain_id: 31337,
            protocol_address: U256::from(4660),
        }
    }
    fn note(amount: u64, token: u64) -> StoredNote {
        let note = Note {
            context: context(),
            owner_address: U256::from(1),
            token_address: U256::from(token),
            amount: U256::from(amount),
            nonce: U256::from(amount),
            payload: Vec::new(),
        };
        StoredNote {
            input: NoteInput {
                note,
                tree_id: 1,
                leaf_index: 0,
                path: [U256::ZERO; 16],
                root: U256::from(1),
            },
            commitment: B256::with_last_byte(amount as u8),
            nullifier: B256::with_last_byte(amount as u8),
            block: block(),
            transaction_hash: B256::with_last_byte(1),
            spent: false,
            reserved_by: None,
        }
    }
    fn grant() -> StoredCredit {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/wallet-wire-vectors.json"
        ))
        .unwrap();
        let request = serde_json::from_value(fixture["cases"][0]["request"].clone()).unwrap();
        let response = serde_json::from_value(fixture["cases"][0]["response"].clone()).unwrap();
        let wallet = Wallet::from_response(&request, &response).unwrap();
        let keys = wallet.receiving_keys().clone();
        let note = CreditState {
            context: context(),
            token_address: U256::from(2),
            owner_wallet_identity: U256::from(1),
            spender_wallet_identity: U256::from(2),
            grant_id: 1,
            nonce: U256::from(678),
            expiry: 2_000_000_123,
            credit_shared_key: U256::from(999),
            available_credit: U256::from(70),
            unlimited: false,
            policy: CreditPolicy::default(),
            usage: CreditUsage::default(),
            payload: Vec::new(),
        };
        StoredCredit {
            delivery: CreditDeliveryState {
                note,
                owner_receiving_keys: keys.clone(),
                spender_receiving_keys: keys,
            },
            commitment: B256::with_last_byte(1),
            nullifier: B256::with_last_byte(1),
            tree_id: 1,
            leaf_index: 0,
            path: [U256::ZERO; 16],
            root: U256::from(1),
            block: block(),
            transaction_hash: B256::with_last_byte(1),
            role: CreditRole::Spender,
            consumed: false,
            status: 1,
            revoked: false,
            reserved_by: None,
        }
    }
    #[test]
    fn note_selection_excludes_spent_reserved_and_other_tokens() {
        let mut state = WalletState::default();
        for value in [note(30, 2), note(40, 2), note(90, 3)] {
            state.notes.insert(value.commitment, value);
        }
        let token = sdk::word_address(U256::from(2)).unwrap();
        assert_eq!(
            select_notes(&state, token, U256::from(60)).unwrap().len(),
            2
        );
        assert!(select_notes(&state, token, U256::from(71)).is_err());
        state
            .notes
            .get_mut(&B256::with_last_byte(30))
            .unwrap()
            .spent = true;
        state
            .notes
            .get_mut(&B256::with_last_byte(40))
            .unwrap()
            .reserved_by = Some("operation".into());
        assert!(note_inputs(&state, token).is_empty());
    }
    #[test]
    fn credit_draw_selection_respects_status_role_revocation_expiry_and_period_limits() {
        let mut state = WalletState::default();
        let mut credit = grant();
        credit.delivery.note.policy.daily_limit = U256::from(50);
        credit.delivery.note.usage.last_day = credit_periods(block().timestamp).0;
        credit.delivery.note.usage.daily_spent = U256::from(30);
        state.credits.insert("grant".into(), credit);
        let token = sdk::word_address(U256::from(2)).unwrap();
        assert_eq!(
            select_credit_draw(&state, token, U256::from(20), block().timestamp).unwrap()[0].debit,
            U256::from(20)
        );
        assert!(select_credit_draw(&state, token, U256::from(21), block().timestamp).is_err());
        assert!(credit_inputs(&state, token, CreditRole::Owner).is_empty());
        for status in [0, 2, 255] {
            state.credits.get_mut("grant").unwrap().status = status;
            assert!(credit_inputs(&state, token, CreditRole::Spender).is_empty());
            assert!(select_credit_draw(&state, token, U256::from(1), block().timestamp).is_err());
        }
        state.credits.get_mut("grant").unwrap().status = 1;
        state.credits.get_mut("grant").unwrap().revoked = true;
        assert!(select_credit_draw(&state, token, U256::from(1), block().timestamp).is_err());
        state.credits.get_mut("grant").unwrap().revoked = false;
        assert!(select_credit_draw(&state, token, U256::from(1), 2_000_000_124).is_err());
    }
}

/// Host-owned viewing capability. No spending account key enters the payment SDK.
pub struct ViewingKeyDecryptor(zeroize::Zeroizing<[u8; 32]>);
impl ViewingKeyDecryptor {
    pub fn new(key: &[u8]) -> Result<Self> {
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| "viewing key must contain 32 raw bytes")?;
        k256::SecretKey::from_slice(&key).map_err(|_| "invalid viewing key")?;
        Ok(Self(zeroize::Zeroizing::new(key)))
    }
    fn open(
        &self,
        envelope: &[u8],
        context: &invisi_sdk::delivery::DeliveryContext,
        role: u8,
        owner: U256,
    ) -> Result<Option<Vec<u8>>> {
        use invisi_sdk::delivery::{decode_credit, decode_note, open_payload, payload_key};
        let key = payload_key(&self.0[..], envelope, role != 0).map_err(|e| e.to_string())?;
        let plain = match open_payload(&key[..], envelope, context, role) {
            Ok(plain) => plain,
            Err(invisi_sdk::note::ModelError::Invalid("delivery authentication")) => {
                return Err("delivery authentication".into())
            }
            Err(error) => return Err(error.to_string()),
        };
        if role == 0 {
            if decode_note(&plain, context)
                .map_err(|e| e.to_string())?
                .owner_address
                != owner
            {
                return Err("note recipient mismatch".into());
            }
        } else {
            let state = decode_credit(&plain, context).map_err(|e| e.to_string())?;
            let expected = if role == 1 {
                state.note.owner_wallet_identity
            } else {
                state.note.spender_wallet_identity
            };
            if expected != owner {
                return Err("credit recipient mismatch".into());
            }
        }
        Ok(Some(plain.to_vec()))
    }
}
impl invisi_sdk::delivery::DeliveryDecryptor for ViewingKeyDecryptor {
    fn decrypt_note(
        &self,
        envelope: &[u8],
        context: &invisi_sdk::delivery::DeliveryContext,
        owner: U256,
    ) -> Result<Option<Vec<u8>>> {
        self.open(envelope, context, 0, owner)
    }
    fn decrypt_credit(
        &self,
        envelope: &[u8],
        context: &invisi_sdk::delivery::DeliveryContext,
        role: CreditRole,
        owner: U256,
    ) -> Result<Option<Vec<u8>>> {
        self.open(
            envelope,
            context,
            if role == CreditRole::Owner { 1 } else { 2 },
            owner,
        )
    }
    fn decrypt_note_outcome(
        &self,
        envelope: &[u8],
        context: &invisi_sdk::delivery::DeliveryContext,
        owner: U256,
    ) -> Result<invisi_sdk::delivery::DecryptionOutcome> {
        use invisi_sdk::delivery::DecryptionOutcome;
        match self.decrypt_note(envelope, context, owner) {
            Ok(Some(plain)) => Ok(DecryptionOutcome::Plaintext(plain)),
            Ok(None) => Ok(DecryptionOutcome::NonRecipient),
            Err(error) if error == "delivery authentication" => {
                Ok(DecryptionOutcome::AuthenticationFailed)
            }
            Err(error) => Err(error),
        }
    }
    fn decrypt_credit_outcome(
        &self,
        envelope: &[u8],
        context: &invisi_sdk::delivery::DeliveryContext,
        role: CreditRole,
        owner: U256,
    ) -> Result<invisi_sdk::delivery::DecryptionOutcome> {
        use invisi_sdk::delivery::DecryptionOutcome;
        match self.decrypt_credit(envelope, context, role, owner) {
            Ok(Some(plain)) => Ok(DecryptionOutcome::Plaintext(plain)),
            Ok(None) => Ok(DecryptionOutcome::NonRecipient),
            Err(error) if error == "delivery authentication" => {
                Ok(DecryptionOutcome::AuthenticationFailed)
            }
            Err(error) => Err(error),
        }
    }
}

/// File-backed application adapter used by the executable recipes.
/// Set VIEWING_KEY_FILE to a file containing 32 raw v1 viewing-key bytes.
pub struct AppDecryptor;
impl AppDecryptor {
    fn capability() -> Result<ViewingKeyDecryptor> {
        let file = std::env::var("VIEWING_KEY_FILE")
            .map_err(|_| "VIEWING_KEY_FILE required for local delivery decryption")?;
        let key = zeroize::Zeroizing::new(std::fs::read(file).map_err(|e| e.to_string())?);
        ViewingKeyDecryptor::new(&key)
    }
}
impl invisi_sdk::delivery::DeliveryDecryptor for AppDecryptor {
    fn detect(&self, candidates: &[invisi_sdk::delivery::DetectionCandidate]) -> Result<Vec<bool>> {
        let file = std::env::var("DETECTION_KEY_FILE")
            .map_err(|_| "DETECTION_KEY_FILE required for local clue detection")?;
        let key = zeroize::Zeroizing::new(std::fs::read(file).map_err(|e| e.to_string())?);
        candidates
            .iter()
            .map(|candidate| {
                invisi_sdk::fmd::detect_clue(&key, &candidate.clue).map_err(|e| e.to_string())
            })
            .collect()
    }
    fn decrypt_note_outcome(
        &self,
        envelope: &[u8],
        context: &invisi_sdk::delivery::DeliveryContext,
        owner: U256,
    ) -> Result<invisi_sdk::delivery::DecryptionOutcome> {
        Self::capability()?.decrypt_note_outcome(envelope, context, owner)
    }
    fn decrypt_credit_outcome(
        &self,
        envelope: &[u8],
        context: &invisi_sdk::delivery::DeliveryContext,
        role: CreditRole,
        owner: U256,
    ) -> Result<invisi_sdk::delivery::DecryptionOutcome> {
        Self::capability()?.decrypt_credit_outcome(envelope, context, role, owner)
    }
    fn decrypt_note(
        &self,
        envelope: &[u8],
        context: &invisi_sdk::delivery::DeliveryContext,
        owner: U256,
    ) -> Result<Option<Vec<u8>>> {
        Self::capability()?.decrypt_note(envelope, context, owner)
    }
    fn decrypt_credit(
        &self,
        envelope: &[u8],
        context: &invisi_sdk::delivery::DeliveryContext,
        role: CreditRole,
        owner: U256,
    ) -> Result<Option<Vec<u8>>> {
        Self::capability()?.decrypt_credit(envelope, context, role, owner)
    }
}

/// Example application signer. Production apps can replace this with any EIP-712 capable wallet.
pub fn sign_authorization(request: &sdk::EvmSigningRequest) -> Result<Vec<u8>> {
    let key =
        zeroize::Zeroizing::new(std::env::var("OWNER_PRIVATE_KEY").map_err(|e| e.to_string())?);
    let bytes = zeroize::Zeroizing::new(
        hex::decode(key.trim().trim_start_matches("0x")).map_err(|e| e.to_string())?,
    );
    let signer = k256::ecdsa::SigningKey::from_slice(&bytes).map_err(|e| e.to_string())?;
    let (signature, recovery) = signer
        .sign_prehash_recoverable(request.digest.as_slice())
        .map_err(|e| e.to_string())?;
    let mut output = signature.to_bytes().to_vec();
    output.push(recovery.to_byte() + 27);
    Ok(output)
}

/// Example host adapter, sharing OWNER_PRIVATE_KEY with the application authorization helper.
/// Production apps can inject a hardware wallet or external signer instead.
pub struct AppTransactionSender {
    rpc: invisi_sdk::rpc::JsonRpc<HttpTransport>,
    signer: k256::ecdsa::SigningKey,
    address: Address,
}
impl AppTransactionSender {
    pub fn connect(endpoint: &str) -> Result<Self> {
        let key =
            zeroize::Zeroizing::new(std::env::var("OWNER_PRIVATE_KEY").map_err(|e| e.to_string())?);
        let bytes = zeroize::Zeroizing::new(
            hex::decode(key.trim().trim_start_matches("0x")).map_err(|e| e.to_string())?,
        );
        let signer = k256::ecdsa::SigningKey::from_slice(&bytes).map_err(|e| e.to_string())?;
        let public = signer.verifying_key().to_encoded_point(false);
        let address =
            Address::from_slice(&alloy_primitives::keccak256(&public.as_bytes()[1..])[12..]);
        Ok(Self {
            rpc: invisi_sdk::rpc::JsonRpc::new(
                HttpTransport::new(endpoint).map_err(|e| e.to_string())?,
            ),
            signer,
            address,
        })
    }
    fn quantity(&self, method: &str, params: serde_json::Value) -> Result<U256> {
        let value = self.rpc.call(method, params).map_err(|e| e.to_string())?;
        U256::from_str_radix(
            value
                .as_str()
                .ok_or("invalid host RPC quantity")?
                .trim_start_matches("0x"),
            16,
        )
        .map_err(|e| e.to_string())
    }
}
impl invisi_sdk_session::session::TransactionSender for AppTransactionSender {
    fn address(&self) -> Result<Address> {
        Ok(self.address)
    }
    fn chain_id(&self) -> Result<u64> {
        self.quantity("eth_chainId", serde_json::json!([]))?
            .try_into()
            .map_err(|_| "host chain ID overflow".into())
    }
    fn send_transaction(
        &self,
        call: &invisi_sdk::protocol::TransactionCall,
        gas_limit: u64,
    ) -> std::result::Result<
        alloy_primitives::B256,
        invisi_sdk_session::session::TransactionSendError,
    > {
        use invisi_sdk_session::session::TransactionSendError;
        let chain_id = self.chain_id()?;
        let nonce = self.quantity(
            "eth_getTransactionCount",
            serde_json::json!([self.address, "pending"]),
        )?;
        let gas_price = self.quantity("eth_gasPrice", serde_json::json!([]))?;
        let append_quantity = |stream: &mut rlp::RlpStream, value: U256| {
            let bytes = value.to_be_bytes::<32>();
            let offset = bytes.iter().position(|b| *b != 0).unwrap_or(32);
            stream.append(&&bytes[offset..]);
        };
        let prefix = |stream: &mut rlp::RlpStream| {
            append_quantity(stream, nonce);
            append_quantity(stream, gas_price);
            append_quantity(stream, U256::from(gas_limit));
            stream.append(&call.to.as_slice());
            append_quantity(stream, call.value);
            stream.append(&call.data.as_slice());
        };
        let mut unsigned = rlp::RlpStream::new_list(9);
        prefix(&mut unsigned);
        append_quantity(&mut unsigned, U256::from(chain_id));
        unsigned.append_empty_data();
        unsigned.append_empty_data();
        let digest = alloy_primitives::keccak256(unsigned.out());
        let (signature, recovery) = self
            .signer
            .sign_prehash_recoverable(digest.as_slice())
            .map_err(|e| e.to_string())?;
        let mut signed = rlp::RlpStream::new_list(9);
        prefix(&mut signed);
        append_quantity(
            &mut signed,
            U256::from(chain_id) * U256::from(2) + U256::from(35 + recovery.to_byte()),
        );
        let bytes = signature.to_bytes();
        append_quantity(&mut signed, U256::from_be_slice(&bytes[..32]));
        append_quantity(&mut signed, U256::from_be_slice(&bytes[32..]));
        let raw = signed.out();
        let hash = alloy_primitives::keccak256(&raw);
        let value = self
            .rpc
            .call(
                "eth_sendRawTransaction",
                serde_json::json!([format!("0x{}", hex::encode(raw))]),
            )
            .map_err(|e| TransactionSendError {
                message: e.to_string(),
                transaction_hash: Some(hash),
            })?;
        if value
            .as_str()
            .and_then(|v| v.parse::<alloy_primitives::B256>().ok())
            != Some(hash)
        {
            return Err(TransactionSendError {
                message: "host RPC returned unexpected transaction hash".into(),
                transaction_hash: Some(hash),
            });
        }
        Ok(hash)
    }
}

/// Keep explicit legacy directories available; otherwise fetch public circuits lazily.
pub fn prover_assets() -> std::sync::Arc<dyn invisi_sdk::prover::Assets> {
    if let Some(directory) = std::env::var_os("PROVER_ASSETS") {
        std::sync::Arc::new(invisi_sdk::prover::DirectoryAssets {
            directory: directory.into(),
        })
    } else {
        std::sync::Arc::new(invisi_sdk::prover::ResourceProvider::default())
    }
}

#[cfg(test)]
mod viewing_decryptor_tests {
    use super::*;
    use invisi_sdk::delivery::{DeliveryContext, DeliveryDecryptor};
    #[test]
    fn local_viewing_capability_opens_note_without_account_key() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/wallet-note-vectors.json"
        ))
        .unwrap();
        let key = hex::decode(
            fixture["owner"]["viewingPrivateKey"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let decryptor = ViewingKeyDecryptor::new(&key).unwrap();
        let context = DeliveryContext {
            context: invisi_sdk::note::ProtocolContext {
                chain_id: 31337,
                protocol_address: U256::from(4660),
            },
            token_address: U256::from(22136),
            output_commitment: U256::from_str_radix(
                fixture["note"]["commitment"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap(),
        };
        let envelope = hex::decode(
            fixture["note"]["ciphertext"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let owner =
            U256::from_str_radix(fixture["owner"]["ownerAddress"].as_str().unwrap(), 10).unwrap();
        let plain = decryptor
            .decrypt_note(&envelope, &context, owner)
            .unwrap()
            .unwrap();
        assert_eq!(
            invisi_sdk::delivery::decode_note(&plain, &context)
                .unwrap()
                .amount,
            U256::from(70)
        );
        let mut corrupted = envelope.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(matches!(
            decryptor
                .decrypt_note_outcome(&corrupted, &context, owner)
                .unwrap(),
            invisi_sdk::delivery::DecryptionOutcome::AuthenticationFailed
        ));
        assert!(decryptor
            .decrypt_note(&envelope, &context, owner + U256::from(1))
            .is_err());
        assert!(ViewingKeyDecryptor::new(&[1; 31]).is_err());
        assert!(ViewingKeyDecryptor::new(&[1; 32])
            .unwrap()
            .decrypt_note(&envelope, &context, owner)
            .is_err());
        assert!(matches!(
            ViewingKeyDecryptor::new(&[1; 32])
                .unwrap()
                .decrypt_note_outcome(&envelope, &context, owner)
                .unwrap(),
            invisi_sdk::delivery::DecryptionOutcome::AuthenticationFailed
        ));
    }
}

/// Optional host receipt windows avoid claiming or scanning unrequested history.
/// Every window still uses the SDK's ordinary canonical refresh and strict decryption.
pub fn refresh_receipt_ranges(
    session: &WalletSession,
    options: RefreshOptions,
) -> Result<PendingWalletRefresh> {
    let path = match std::env::var("RECEIPT_RANGES_JSON") {
        Ok(path) => path,
        Err(std::env::VarError::NotPresent) => return session.refresh(options),
        Err(error) => return Err(error.to_string()),
    };
    let ranges = receipt_ranges(&std::fs::read(path).map_err(|error| error.to_string())?)?;
    let count = ranges.len();
    for (index, (from_block, to_block)) in ranges.into_iter().enumerate() {
        let mut bounded = options.clone();
        bounded.from_block = from_block;
        bounded.to_block = Some(to_block);
        bounded.reset = options.reset && index == 0;
        let pending = session.refresh(bounded)?;
        if index + 1 == count {
            return Ok(pending);
        }
        pending.decrypt(&AppDecryptor)?;
    }
    Err("at least one receipt range is required".into())
}

fn receipt_ranges(bytes: &[u8]) -> Result<Vec<(u64, u64)>> {
    let values: Vec<serde_json::Value> =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if values.is_empty() || values.len() > 64 {
        return Err("receipt ranges must contain between one and 64 windows".into());
    }
    let mut ranges = Vec::with_capacity(values.len());
    let mut previous = None;
    for value in values {
        let object = value.as_object().ok_or("receipt range must be an object")?;
        if object.len() != 2 {
            return Err("receipt range accepts only fromBlock and toBlock".into());
        }
        let from = value["fromBlock"]
            .as_u64()
            .ok_or("receipt range fromBlock must be an integer")?;
        let to = value["toBlock"]
            .as_u64()
            .ok_or("receipt range toBlock must be an integer")?;
        if from == 0
            || to < from
            || to > 9_007_199_254_740_991
            || to - from >= 256
            || previous.is_some_and(|end| from <= end)
        {
            return Err("receipt windows must be ordered, disjoint, and at most 256 blocks".into());
        }
        previous = Some(to);
        ranges.push((from, to));
    }
    Ok(ranges)
}

#[cfg(test)]
mod receipt_range_tests {
    #[test]
    fn sparse_receipt_ranges_are_explicit_bounded_and_ordered() {
        assert_eq!(
            super::receipt_ranges(
                br#"[{"fromBlock":100,"toBlock":100},{"fromBlock":900,"toBlock":901}]"#
            )
            .unwrap(),
            vec![(100, 100), (900, 901)]
        );
        for malformed in [
            r#"[]"#,
            r#"[{"fromBlock":100,"toBlock":99}]"#,
            r#"[{"fromBlock":100,"toBlock":356}]"#,
            r#"[{"fromBlock":100,"toBlock":101},{"fromBlock":101,"toBlock":102}]"#,
            r#"[{"fromBlock":9007199254740992,"toBlock":9007199254740992}]"#,
            r#"[{"fromBlock":100,"toBlock":100,"skipCanonical":true}]"#,
        ] {
            assert!(super::receipt_ranges(malformed.as_bytes()).is_err());
        }
    }
}
