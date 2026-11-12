//! Authenticate native heads and receipts against the independent canonical chain.
use super::*;
use alloy_primitives::B256;
fn status(error: &Error) -> FinalityStatus {
    match error {
        Error::FinalityUnsupported => FinalityStatus::Unsupported,
        Error::FinalityInconsistent | Error::Invalid(_) => FinalityStatus::Inconsistent,
        _ => FinalityStatus::Unavailable,
    }
}
fn read_head<C: CanonicalChain + ?Sized>(chain: &C, tag: FinalityTag) -> FinalityHead {
    match chain.block_by_tag(tag) {
        Ok(Some(block)) => match chain.block(block.number) {
            Ok(canonical) if canonical == block => FinalityHead {
                status: FinalityStatus::Available,
                block: Some(block),
            },
            Ok(_) => FinalityHead::absent(FinalityStatus::Inconsistent),
            Err(e) => FinalityHead::absent(status(&e)),
        },
        Ok(None) => FinalityHead::absent(FinalityStatus::Unavailable),
        Err(e) => FinalityHead::absent(status(&e)),
    }
}
pub fn read_chain_finality<C: CanonicalChain + ?Sized>(chain: &C) -> ChainFinality {
    for attempt in 0..2 {
        let finalized = read_head(chain, FinalityTag::Finalized);
        let safe = read_head(chain, FinalityTag::Safe);
        let latest = read_head(chain, FinalityTag::Latest);
        let mut out = ChainFinality {
            latest,
            safe,
            finalized,
        };
        let conflict = !out.ordered();
        if !conflict
            && [&out.latest, &out.safe, &out.finalized]
                .iter()
                .all(|h| h.status != FinalityStatus::Inconsistent)
        {
            return out;
        }
        if attempt == 1 {
            if conflict {
                for h in [&mut out.latest, &mut out.safe, &mut out.finalized] {
                    if h.status == FinalityStatus::Available {
                        *h = FinalityHead::absent(FinalityStatus::Inconsistent)
                    }
                }
            }
            return out;
        }
    }
    unreachable!()
}
pub fn read_transaction_confirmation<C: CanonicalChain + ?Sized>(
    chain: &C,
    hash: B256,
) -> Result<TransactionConfirmation> {
    if hash == B256::ZERO {
        return Err(Error::Invalid("nonzero transaction hash required"));
    }
    let pending = |status| TransactionConfirmation {
        level: ConfirmationLevel::Pending,
        status,
        block: None,
    };
    let receipt = match chain.confirmation_receipt(hash) {
        Ok(Some(r)) => r,
        Ok(None) => return Ok(pending(FinalityStatus::Available)),
        Err(e) => return Ok(pending(status(&e))),
    };
    if receipt.transaction_hash != hash {
        return Ok(pending(FinalityStatus::Inconsistent));
    }
    match chain.block(receipt.block.number) {
        Ok(b) if b == receipt.block => (),
        Ok(_) => return Ok(pending(FinalityStatus::Inconsistent)),
        Err(_) => return Ok(pending(FinalityStatus::Unavailable)),
    }
    let heads = read_chain_finality(chain);
    let mut out = TransactionConfirmation {
        level: ConfirmationLevel::Included,
        status: heads.finalized.status,
        block: Some(receipt.block.clone()),
    };
    for (head, level) in [
        (&heads.safe, ConfirmationLevel::Safe),
        (&heads.finalized, ConfirmationLevel::Finalized),
    ] {
        if head.status == FinalityStatus::Available
            && head
                .block
                .as_ref()
                .is_some_and(|b| b.number >= receipt.block.number)
        {
            out.level = level
        }
    }
    if out.level == ConfirmationLevel::Finalized {
        out.status = FinalityStatus::Available
    }
    if [&heads.latest, &heads.safe, &heads.finalized]
        .iter()
        .any(|h| h.status == FinalityStatus::Inconsistent)
    {
        out.status = FinalityStatus::Inconsistent
    }
    match chain.block(receipt.block.number) {
        Ok(b) if b == receipt.block => (),
        Ok(_) => return Ok(pending(FinalityStatus::Inconsistent)),
        Err(_) => out.status = FinalityStatus::Unavailable,
    }
    Ok(out)
}
pub(crate) fn authenticate_claim<C: CanonicalChain + ?Sized>(
    chain: &C,
    claim: ChainFinality,
) -> ChainFinality {
    let primary = read_chain_finality(chain);
    let authenticate = |claimed: FinalityHead, native: &FinalityHead| -> FinalityHead {
        let Some(block) = claimed.block.as_ref() else {
            return claimed;
        };
        if native.status != FinalityStatus::Available {
            return FinalityHead::absent(native.status);
        }
        if native
            .block
            .as_ref()
            .is_none_or(|h| h.number < block.number)
        {
            return FinalityHead::absent(FinalityStatus::Unavailable);
        }
        match chain.block(block.number) {
            Ok(b) if b == *block => claimed,
            Ok(_) => FinalityHead::absent(FinalityStatus::Inconsistent),
            Err(_) => FinalityHead::absent(FinalityStatus::Unavailable),
        }
    };
    ChainFinality {
        latest: authenticate(claim.latest, &primary.latest),
        safe: authenticate(claim.safe, &primary.safe),
        finalized: authenticate(claim.finalized, &primary.finalized),
    }
}
