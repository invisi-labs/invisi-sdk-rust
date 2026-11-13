//! The host owns EVM account access and transaction signing.
use super::*;

pub trait TransactionSender {
    fn chain_id(&self) -> Result<u64>;
    fn address(&self) -> Result<Address>;
    fn send_transaction(
        &self,
        call: &crate::protocol::TransactionCall,
        gas_limit: u64,
    ) -> std::result::Result<B256, TransactionSendError>;
}
#[derive(Clone, Copy, Debug)]
pub struct SessionTransactionOptions {
    pub caller: Address,
    pub gas_limit: u64,
}
#[derive(Debug, thiserror::Error)]
#[error("{message}{recovery}", recovery = transaction_hash.map(|h| format!("; transaction {h}; track this hash and reconcile; do not resend")).unwrap_or_default())]
pub struct TransactionSendError {
    pub message: String,
    pub transaction_hash: Option<B256>,
}
impl From<String> for TransactionSendError {
    fn from(message: String) -> Self {
        Self {
            message,
            transaction_hash: None,
        }
    }
}
mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::protocol::TransactionCall {}
    impl Sealed for super::Operation {}
}
/// Only raw calls and managed operations can cross this host sending boundary.
pub trait SessionTransactionTarget: sealed::Sealed {
    #[doc(hidden)]
    fn prepare_send(
        &mut self,
        session: &WalletSession,
        caller: Address,
    ) -> Result<crate::protocol::TransactionCall>;
    #[doc(hidden)]
    fn record_sent(&mut self, hash: B256) -> Result<()>;
}
impl SessionTransactionTarget for crate::protocol::TransactionCall {
    fn prepare_send(
        &mut self,
        _: &WalletSession,
        _: Address,
    ) -> Result<crate::protocol::TransactionCall> {
        if self.to == Address::ZERO {
            return Err("transaction target must be nonzero".into());
        }
        Ok(self.clone())
    }
    fn record_sent(&mut self, _: B256) -> Result<()> {
        Ok(())
    }
}
impl WalletSession {
    /// Sends exactly once; a failed send may have reached the host's network and must be recovered explicitly.
    pub fn send_transaction<Q: SessionTransactionTarget>(
        &self,
        target: &mut Q,
        sender: &dyn TransactionSender,
        options: SessionTransactionOptions,
    ) -> std::result::Result<B256, TransactionSendError> {
        if options.gas_limit == 0 {
            return Err("positive explicit gas limit required".to_owned().into());
        }
        if sender.chain_id()? != self.scope.context.chain_id
            || self.invisi.chain.context() != self.scope.context
        {
            return Err("transaction sender chain mismatch".to_owned().into());
        }
        if options.caller == Address::ZERO || sender.address()? != options.caller {
            return Err("transaction sender caller mismatch".to_owned().into());
        }
        let call = target.prepare_send(self, options.caller)?;
        let hash = sender.send_transaction(&call, options.gas_limit)?;
        if hash == B256::ZERO {
            return Err(
                "sender returned zero hash; execution uncertain; do not resend"
                    .to_owned()
                    .into(),
            );
        }
        target
            .record_sent(hash)
            .map_err(|message| TransactionSendError {
                message,
                transaction_hash: Some(hash),
            })?;
        Ok(hash)
    }
}
