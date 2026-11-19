//! Request-based Credit construction keeps allocation and recovery state inside the SDK.
use super::*;
#[derive(Clone, Debug)]
pub struct InitialCreditPayment {
    /// Gross owner debit, including the actual broadcaster fee.
    pub amount: U256,
    pub payload: Vec<u8>,
}
#[derive(Clone)]
pub struct CreateCreditRequest {
    pub token: Address,
    /// Optional caller-selected nonzero canonical field element; defaults to random.
    pub credit_shared_key: Option<U256>,
    pub initial_payment: Option<InitialCreditPayment>,
    pub spender: String,
    pub policy: crate::credit::CreditPolicy,
    pub available_credit: U256,
    pub unlimited: bool,
    pub expiry: u64,
    pub payload: Vec<u8>,
    pub deadline: u64,
    pub fee: Fee,
}
impl std::fmt::Debug for CreateCreditRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateCreditRequest")
            .field("token", &self.token)
            .field("expiry", &self.expiry)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug)]
pub struct UpdateCreditRequest {
    pub input: CreditInput,
    pub changes: crate::credit::CreditUpdateChanges,
    pub deadline: u64,
    pub fee: Fee,
}
#[derive(Clone, Debug)]
pub struct DrawCreditRequest {
    pub inputs: Vec<CreditInput>,
    pub recipient: String,
    pub payload: Vec<u8>,
    pub deadline: u64,
    pub fee: Fee,
}
#[derive(Clone, Debug)]
pub struct RevokeCreditRequest {
    pub token: Address,
    pub shard: u64,
    pub slot: u16,
    pub deadline: u64,
    pub fee: Fee,
}
fn recipient_wallet(
    address: &str,
    context: ProtocolContext,
    resolver: Option<&dyn ReceivingKeyResolver>,
) -> PreparationResult<Wallet> {
    let parsed = ReceivingAddress::parse(address).map_err(|cause| {
        InvisiError::new(
            InvisiErrorCode::InvalidRecipient,
            cause.to_string(),
            json!({"address":address}),
        )
    })?;
    let owner = word_address(parsed.owner_address).map_err(|cause| {
        InvisiError::new(
            InvisiErrorCode::InvalidRecipient,
            cause,
            json!({"address":address}),
        )
    })?;
    let keys = match parsed.keys {
        Some(keys) => keys,
        None => resolver
            .ok_or_else(|| {
                InvisiError::new(
                    InvisiErrorCode::MissingCapability,
                    "receiving key resolver required for EVM recipient",
                    json!({"capability":"receiving key resolver"}),
                )
            })?
            .resolve(
                owner,
                context,
                crate::payment_request::AddressLookup::ProtocolRpc,
            )?,
    };
    Wallet::from_keys(owner, keys).map_err(|cause| {
        InvisiError::new(
            InvisiErrorCode::InvalidRecipient,
            cause,
            json!({"address":address}),
        )
    })
}
impl Invisi {
    pub fn prepare_create_credit(
        &self,
        wallet: &Wallet,
        request: CreateCreditRequest,
        resolver: Option<&dyn ReceivingKeyResolver>,
    ) -> PreparationResult<PreparedCredit> {
        let spender = recipient_wallet(&request.spender, self.chain.context(), resolver)
            .map_err(|error| error.with_operation("prepare_create_credit"))?;
        let build = || -> Result<PreparedCredit> {
            let anchor = self.chain.snapshot()?;
            let (shard, slot) =
                self.chain
                    .credit_allocation(wallet.owner_address(), request.token, &anchor)?;
            self.chain.canonical(&anchor)?;
            let delivery = CreditDeliveryState {
                note: crate::credit::CreditState {
                    context: self.chain.context(),
                    token_address: address_word(request.token),
                    owner_wallet_identity: address_word(wallet.owner_address()),
                    spender_wallet_identity: address_word(spender.owner_address()),
                    revocation_shard: shard,
                    revocation_slot: slot,
                    nonce: nonce(),
                    expiry: request.expiry,
                    credit_shared_key: request.credit_shared_key.unwrap_or_else(nonce),
                    policy: request.policy,
                    usage: crate::credit::CreditUsage::default(),
                    available_credit: request.available_credit,
                    unlimited: request.unlimited,
                    payload: request.payload,
                },
                owner_receiving_keys: wallet.receiving_keys().clone(),
                spender_receiving_keys: spender.receiving_keys().clone(),
            };
            self.prepare_create_credit_with_initial_payment(
                wallet,
                delivery,
                request.initial_payment,
                request.deadline,
                request.fee,
            )
            .map_err(String::from)
        };
        build().map_err(|cause| InvisiError::preparation("prepare_create_credit", cause))
    }
    pub fn prepare_update_credit(
        &self,
        wallet: &Wallet,
        request: UpdateCreditRequest,
    ) -> PreparationResult<PreparedCredit> {
        self.prepare_update_credit_explicit(
            wallet,
            request.input,
            request.changes,
            request.deadline,
            request.fee,
        )
    }
    pub fn prepare_draw_credit(
        &self,
        wallet: &Wallet,
        request: DrawCreditRequest,
        resolver: Option<&dyn ReceivingKeyResolver>,
    ) -> PreparationResult<PreparedCredit> {
        let recipient = recipient_wallet(&request.recipient, self.chain.context(), resolver)
            .map_err(|error| error.with_operation("prepare_draw_credit"))?;
        self.prepare_draw_credit_explicit(
            wallet,
            request.inputs,
            &recipient,
            request.deadline,
            request.fee,
            request.payload,
        )
    }
    pub fn prepare_revoke_credit(
        &self,
        wallet: &Wallet,
        request: RevokeCreditRequest,
    ) -> PreparationResult<PreparedCredit> {
        self.prepare_revoke_credit_explicit(
            wallet.owner_address(),
            request.token,
            request.shard,
            request.slot,
            request.deadline,
            request.fee,
        )
    }
}
