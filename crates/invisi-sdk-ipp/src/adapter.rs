//! Optional SDK preparation boundary. No authorization, proving, or submission occurs here.
use crate::{
    validation::{text, uint},
    *,
};
use alloy_primitives::{Address, U256};
use invisi_sdk::{
    note::ProtocolContext,
    sdk::{self, Invisi, ReceivingKeyResolver, Wallet},
};
/// Validate the request against a trusted deployment and the caller's current Unix time.
pub fn validate_preparation(request: &Request, context: ProtocolContext, now: i64) -> Result<()> {
    let r = &request.0;
    if r["status"] != "requires_action" || timestamp(&r["expiresAt"])? <= now {
        return Err(Error::ExecutionNotAllowed);
    }
    let d = &r[text(&r["mode"])?];
    let chain = text(&d["network"])?[7..]
        .parse::<u64>()
        .map_err(|_| Error::InvalidMessage)?;
    let protocol = text(&d["protocolAddress"])?
        .parse::<U256>()
        .map_err(|_| Error::InvalidMessage)?;
    if chain != context.chain_id || protocol != context.protocol_address {
        return Err(Error::DeploymentMismatch);
    }
    Ok(())
}
/// Caller-controlled funding and fees. Inputs are never selected implicitly.
pub struct PreparationOptions {
    pub inputs: Vec<sdk::NoteInput>,
    pub funding: invisi_sdk::protocol::IInvisiCore::FundingParams,
    pub fee: sdk::Fee,
    pub automatic_change: bool,
}
pub enum PreparedIppOperation {
    Payment(sdk::PreparedTransaction),
    Credit(sdk::PreparedCredit),
}
/// Payment terms converted for a managed session to select and reserve inputs itself.
pub struct PaymentPreparation {
    pub token: Address,
    pub output: sdk::NoteOutput,
    pub deadline: u64,
}
/// Structural boundary for managed sessions. Each callback should invoke only preparation.
/// The caller provides its trusted deployment; no session crate dependency is needed.
pub fn prepare_invisi_request_with<T>(
    request: &Request,
    context: ProtocolContext,
    now: i64,
    fee: sdk::Fee,
    payment: impl FnOnce(PaymentPreparation) -> sdk::PreparationResult<T>,
    credit: impl FnOnce(sdk::CreateCreditRequest) -> sdk::PreparationResult<T>,
) -> Result<T> {
    validate_preparation(request, context, now)?;
    let r = &request.0;
    let d = &r[text(&r["mode"])?];
    let token = text(&d["tokenAddress"])?
        .parse::<Address>()
        .map_err(|_| Error::InvalidMessage)?;
    let deadline =
        u64::try_from(timestamp(&r["expiresAt"])?).map_err(|_| Error::ExecutionNotAllowed)?;
    if r["mode"] == "payment" {
        let identity = text(&d["recipient"]["identity"])?
            .parse::<U256>()
            .map_err(|_| Error::InvalidMessage)?;
        let output =
            sdk::NoteOutput::identity(context, token, identity, uint(&d["amount"], 128, true)?)
                .map_err(|_| Error::Preparation)?;
        payment(PaymentPreparation {
            token,
            output,
            deadline,
        })
        .map_err(|_| Error::Preparation)
    } else {
        let key = text(&d["creditSharedKey"])?
            .parse::<U256>()
            .map_err(|_| Error::InvalidMessage)?;
        credit(sdk::CreateCreditRequest {
            token,
            credit_shared_key: Some(key),
            spender: text(&d["spender"])?.into(),
            policy: invisi_sdk::credit::CreditPolicy {
                single_limit: uint(&d["singleLimit"], 126, false)?,
                daily_limit: uint(&d["dailyLimit"], 126, false)?,
                monthly_limit: uint(&d["monthlyLimit"], 126, false)?,
            },
            available_credit: uint(&d["availableCredit"], 128, false)?,
            unlimited: d["unlimited"].as_bool().ok_or(Error::InvalidMessage)?,
            expiry: u64::try_from(timestamp(&d["expiresAt"])?)
                .map_err(|_| Error::ExecutionNotAllowed)?,
            payload: vec![],
            deadline,
            fee,
        })
        .map_err(|_| Error::Preparation)
    }
}
/// Prepare exactly the authenticated request terms using the existing stateless SDK.
pub fn prepare_invisi_request(
    request: &Request,
    target: &Invisi,
    wallet: &Wallet,
    options: PreparationOptions,
    resolver: Option<&dyn ReceivingKeyResolver>,
    now: i64,
) -> Result<PreparedIppOperation> {
    prepare_invisi_request_with(
        request,
        target.context(),
        now,
        options.fee.clone(),
        |p| {
            target
                .prepare_transfer(
                    wallet,
                    sdk::TransferPreparation {
                        token: p.token,
                        inputs: options.inputs,
                        outputs: vec![p.output],
                        withdrawal: None,
                        funding: options.funding,
                        fee: options.fee,
                        deadline: p.deadline,
                        automatic_change: options.automatic_change,
                    },
                )
                .map(PreparedIppOperation::Payment)
        },
        |c| {
            target
                .prepare_create_credit(wallet, c, resolver)
                .map(PreparedIppOperation::Credit)
        },
    )
}
