use super::*;
use crate::public_history::{CoverageRange, PublicHistoryScope, PublicHistorySnapshot};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanRange {
    pub from_block: u64,
    pub to_block: u64,
    pub direction: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockProgress {
    pub from_block: u64,
    pub to_block: Option<u64>,
    pub total_blocks: u64,
    pub scanned_blocks: u64,
    pub complete: bool,
    pub ratio: Option<f64>,
    pub unit: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanProgress {
    pub recent: BlockProgress,
    pub recovery: BlockProgress,
    pub overall: BlockProgress,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStatus {
    pub public_through: Option<CanonicalBlock>,
    pub account_through: Option<CanonicalBlock>,
    pub unresolved_count: usize,
    pub asset_completeness: String,
    pub invalidated: bool,
    pub recovery_start_height: u64,
    pub recovery_boundary: u64,
    pub chain_height: Option<u64>,
    pub indexed_height: Option<u64>,
    pub max_scanned_height: Option<u64>,
    pub fully_scanned_height: Option<u64>,
    pub scan_complete: bool,
    pub is_synced: bool,
    pub unscanned_ranges: Vec<ScanRange>,
    pub suggested_scan_ranges: Vec<ScanRange>,
    pub next_action: String,
    pub credit_recovery_pending: bool,
    pub progress: Option<ScanProgress>,
}
pub fn account_coverage(state: &WalletState, deployment: u64) -> Vec<CoverageRange> {
    if !state.discovery_ranges.is_empty() {
        state.discovery_ranges.clone()
    } else {
        state
            .discovery_through
            .as_ref()
            .map(|b| {
                vec![CoverageRange {
                    from_block: deployment,
                    block: b.clone(),
                }]
            })
            .unwrap_or_default()
    }
}
pub fn missing_ranges(ranges: &[CoverageRange], from: u64, to: u64) -> Vec<ScanRange> {
    if from > to {
        return vec![];
    }
    let mut gaps = vec![];
    let mut next = from;
    for range in ranges {
        if range.block.number < next {
            continue;
        }
        if range.from_block > to {
            break;
        }
        if range.from_block > next {
            gaps.push(ScanRange {
                from_block: next,
                to_block: (range.from_block - 1).min(to),
                direction: "backward".into(),
            })
        }
        if range.block.number >= to {
            return gaps;
        }
        next = range.block.number + 1
    }
    if next <= to {
        gaps.push(ScanRange {
            from_block: next,
            to_block: to,
            direction: "backward".into(),
        })
    }
    gaps
}
fn progress(ranges: &[CoverageRange], from: u64, to: Option<u64>) -> BlockProgress {
    let total = to.filter(|to| *to >= from).map_or(0, |to| to - from + 1);
    let scanned = to.map_or(0, |to| {
        ranges
            .iter()
            .map(|r| {
                let start = from.max(r.from_block);
                let end = to.min(r.block.number);
                if end >= start {
                    end - start + 1
                } else {
                    0
                }
            })
            .sum::<u64>()
    });
    BlockProgress {
        from_block: from,
        to_block: to,
        total_blocks: total,
        scanned_blocks: scanned,
        complete: total == scanned,
        ratio: if total == 0 {
            None
        } else {
            Some(((scanned as u128 * 10000 / total as u128) as f64) / 10000.0)
        },
        unit: "blocks".into(),
    }
}
pub fn first_scan_range(
    state: &WalletState,
    history: &PublicHistorySnapshot,
    deployment: u64,
    lower: u64,
    target: u64,
    size: u64,
    reset: bool,
) -> Option<ScanRange> {
    if lower > target || size == 0 {
        return None;
    }
    let ranges = if reset {
        vec![]
    } else {
        account_coverage(state, deployment)
    };
    let highest = ranges.last().map(|r| r.block.number);
    if highest.is_some_and(|n| n >= target) {
        let (from, to) = crate::public_history::highest_gap(&ranges, lower, target)?;
        return Some(ScanRange {
            from_block: from.max(to.saturating_sub(size - 1)),
            to_block: to,
            direction: "backward".into(),
        });
    }
    let cached = history
        .pages
        .iter()
        .filter(|p| p.from_block <= target && p.block.number >= lower)
        .next_back();
    let from = highest
        .map_or_else(
            || cached.map_or(target.saturating_sub(size - 1), |p| p.from_block),
            |n| n.saturating_add(1),
        )
        .max(lower);
    Some(ScanRange {
        from_block: from,
        to_block: from.saturating_add(size - 1).min(target),
        direction: "forward".into(),
    })
}
pub fn scan_status(
    state: &WalletState,
    history: &PublicHistorySnapshot,
    scope: &PublicHistoryScope,
    unresolved_count: usize,
) -> ScanStatus {
    let ranges = if state.invalidated {
        vec![]
    } else {
        account_coverage(state, scope.deployment_block)
    };
    let indexed = history
        .indexed_head
        .as_ref()
        .or_else(|| history.coverage.last().map(|r| &r.block))
        .or(history.through.as_ref());
    let known = history.known_head.as_ref().or(indexed);
    let fully = if state.invalidated {
        None
    } else {
        state.discovery_through.clone()
    };
    let max = ranges.last().map(|r| r.block.number);
    let complete = !state.invalidated
        && known.is_some()
        && fully
            .as_ref()
            .zip(known)
            .is_some_and(|(a, b)| a.number == b.number && a.hash == b.hash);
    let synced = complete && state.credit_replay_from.is_none();
    let first = indexed.and_then(|h| {
        first_scan_range(
            state,
            history,
            scope.deployment_block,
            scope.deployment_block,
            h.number,
            100,
            false,
        )
    });
    let boundary = state.recovery_boundary.unwrap_or_else(|| {
        first.as_ref().map_or_else(
            || {
                fully
                    .as_ref()
                    .map_or(scope.deployment_block, |b| b.number.saturating_add(1))
            },
            |r| r.from_block,
        )
    });
    let gaps = known.map_or_else(Vec::new, |h| {
        missing_ranges(&ranges, scope.deployment_block, h.number)
    });
    let mut suggestions = vec![];
    if let Some(first) = &first {
        if first.direction == "forward" {
            suggestions.push(ScanRange {
                from_block: first.from_block,
                to_block: indexed.unwrap().number,
                direction: "forward".into(),
            })
        }
    }
    let older = if first.as_ref().is_some_and(|r| r.direction == "forward") {
        first.as_ref().unwrap().from_block.checked_sub(1)
    } else {
        indexed.map(|b| b.number)
    };
    if let Some(to) = older {
        suggestions.extend(
            missing_ranges(&ranges, scope.deployment_block, to)
                .into_iter()
                .rev(),
        )
    }
    let action = if state.invalidated {
        "rebuild"
    } else if indexed.is_none() {
        "discover-head"
    } else if max.is_none_or(|n| n < indexed.unwrap().number) {
        "update-head"
    } else if !suggestions.is_empty() {
        "recover-history"
    } else if state.credit_replay_from.is_some() {
        "recover-credit"
    } else if unresolved_count > 0 {
        "retry-unresolved"
    } else if !synced {
        "wait-for-indexer"
    } else {
        "none"
    };
    ScanStatus {
        public_through: history.through.clone(),
        account_through: fully.clone(),
        unresolved_count,
        asset_completeness: if synced && unresolved_count == 0 {
            "complete"
        } else {
            "unknown"
        }
        .into(),
        invalidated: state.invalidated,
        recovery_start_height: scope.deployment_block,
        recovery_boundary: boundary,
        chain_height: known.map(|b| b.number),
        indexed_height: indexed.map(|b| b.number),
        max_scanned_height: max,
        fully_scanned_height: fully.map(|b| b.number),
        scan_complete: complete,
        is_synced: synced,
        unscanned_ranges: gaps,
        suggested_scan_ranges: suggestions,
        next_action: action.into(),
        credit_recovery_pending: state.credit_replay_from.is_some(),
        progress: known.map(|h| ScanProgress {
            recent: progress(&ranges, boundary, Some(h.number)),
            recovery: progress(&ranges, scope.deployment_block, boundary.checked_sub(1)),
            overall: progress(&ranges, scope.deployment_block, Some(h.number)),
        }),
    }
}
#[derive(Clone, Debug)]
pub struct FundsStatus {
    pub token_address: Address,
    pub spendable_known: U256,
    pub reserved_known: U256,
    pub checked_through: Option<CanonicalBlock>,
    pub are_funds_spendable: bool,
    pub requires_preparation_validation: bool,
    pub invalidated: bool,
}
impl WalletSession {
    pub fn scan_status(&self) -> Result<ScanStatus> {
        self.fence_public_history()?;
        let state = self.store.read_summary(&self.scope.key())?;
        let history = self
            .public_history
            .as_ref()
            .ok_or("scan status requires shared public history")?;
        Ok(scan_status(
            &state,
            &history.snapshot()?,
            &history.scope,
            state
                .unresolved_delivery_count
                .unwrap_or(state.unresolved_deliveries.len()),
        ))
    }
    pub fn funds_status(&self, token: Address) -> Result<FundsStatus> {
        self.fence_public_history()?;
        let state = self.snapshot()?;
        let public = self
            .public_history
            .as_ref()
            .map(|h| h.snapshot())
            .transpose()?;
        let head = public
            .as_ref()
            .and_then(|h| h.known_head.clone().or(h.indexed_head.clone()))
            .or_else(|| state.observed_through.clone());
        let mut spendable = U256::ZERO;
        let mut reserved = U256::ZERO;
        let fresh = state
            .observed_through
            .as_ref()
            .zip(head.as_ref())
            .is_some_and(|(checked, head)| checked == head);
        for note in state
            .notes
            .values()
            .filter(|n| n.input.note.token_address == sdk::address_word(token) && !n.spent)
        {
            if note.reserved_by.is_some() {
                reserved = reserved
                    .checked_add(note.input.note.amount)
                    .ok_or("funds balance overflow")?
            } else if fresh && !state.invalidated {
                spendable = spendable
                    .checked_add(note.input.note.amount)
                    .ok_or("funds balance overflow")?
            }
        }
        Ok(FundsStatus {
            token_address: token,
            spendable_known: spendable,
            reserved_known: reserved,
            checked_through: if fresh { head } else { None },
            are_funds_spendable: !state.invalidated && spendable > U256::ZERO,
            requires_preparation_validation: true,
            invalidated: state.invalidated,
        })
    }
}
