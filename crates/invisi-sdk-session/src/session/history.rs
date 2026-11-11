use super::*;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum HistoryKind {
    Note,
    Credit,
    Operation,
}
pub struct SessionHistoryEntry {
    pub record: WalletRecord,
    pub canonical: String,
}
pub struct SessionHistoryPage {
    pub entries: Vec<SessionHistoryEntry>,
    pub next_cursor: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Cursor {
    scope: String,
    revision: u64,
    kind: Option<HistoryKind>,
    active: Option<usize>,
    archive_after: Option<String>,
}
fn kind(record: &WalletRecord) -> HistoryKind {
    match record {
        WalletRecord::Note(_) => HistoryKind::Note,
        WalletRecord::Credit(_) => HistoryKind::Credit,
        WalletRecord::Operation(_) => HistoryKind::Operation,
    }
}
fn height(record: &WalletRecord) -> u64 {
    match record {
        WalletRecord::Note(v) => v.block.number,
        WalletRecord::Credit(v) => v.block.number,
        WalletRecord::Operation(v) => v.resolved_at.as_ref().map_or(0, |b| b.number),
    }
}
impl WalletSession {
    pub fn history_page(&self, after: Option<&str>, limit: usize) -> Result<SessionHistoryPage> {
        self.history_page_filtered(after, limit, None, None)
    }
    /// Token filtering applies to the selected page; an empty page may still have a continuation.
    pub fn history_page_filtered(
        &self,
        after: Option<&str>,
        limit: usize,
        selected: Option<HistoryKind>,
        token: Option<Address>,
    ) -> Result<SessionHistoryPage> {
        if limit == 0 || limit > 1000 {
            return Err("history page limit must be 1..1000".into());
        }
        self.fence_public_history()?;
        let state = self.snapshot()?;
        let scope = hex::encode(alloy_primitives::keccak256(self.scope.key().as_bytes()));
        let mut cursor = if let Some(after) = after {
            if after.len() > 8192 {
                return Err("invalid history cursor".into());
            }
            let bytes = hex::decode(after).map_err(|_| "invalid history cursor")?;
            let c: Cursor = serde_json::from_slice(&bytes).map_err(|_| "invalid history cursor")?;
            if c.scope != scope || c.revision != state.revision || c.kind != selected {
                return Err("history cursor belongs to another account, kind or revision".into());
            }
            c
        } else {
            Cursor {
                scope,
                revision: state.revision,
                kind: selected,
                active: Some(0),
                archive_after: None,
            }
        };
        let mut output = vec![];
        if let Some(offset) = cursor.active {
            let mut records = state
                .notes
                .values()
                .cloned()
                .map(WalletRecord::Note)
                .chain(state.credits.values().cloned().map(WalletRecord::Credit))
                .chain(
                    state
                        .operations
                        .values()
                        .cloned()
                        .map(WalletRecord::Operation),
                )
                .filter(|r| selected.is_none_or(|k| kind(r) == k))
                .collect::<Vec<_>>();
            records.sort_by_key(|r| std::cmp::Reverse(height(r)));
            if offset > records.len() {
                return Err("history cursor offset outside active inventory".into());
            }
            let records_len = records.len();
            let take = limit.min(records_len - offset);
            output.extend(records.into_iter().skip(offset).take(take).map(|record| {
                SessionHistoryEntry {
                    record,
                    canonical: if state.invalidated {
                        "unknown"
                    } else {
                        "validated"
                    }
                    .into(),
                }
            }));
            if offset + take < records_len && output.len() == limit {
                cursor.active = Some(offset + take);
            } else {
                cursor.active = None;
            }
        }
        let mut more = cursor.active.is_some();
        if cursor.active.is_none() && output.len() < limit && self.store.supports_history_paging() {
            let page = self.store.history_page(
                &self.scope.key(),
                cursor.archive_after.as_deref(),
                limit - output.len(),
            )?;
            output.extend(
                page.entries
                    .into_iter()
                    .filter(|e| selected.is_none_or(|k| kind(&e.record) == k))
                    .map(|e| SessionHistoryEntry {
                        record: e.record,
                        canonical: "unknown".into(),
                    }),
            );
            cursor.archive_after = page.next_cursor;
            more = cursor.archive_after.is_some();
        } else if cursor.active.is_none()
            && output.len() == limit
            && self.store.supports_history_paging()
        {
            more = true;
        }
        if self.store.read_summary(&self.scope.key())?.revision != state.revision {
            return Err("wallet changed during history page".into());
        }
        output.retain(|e| {
            token.is_none_or(|token| match &e.record {
                WalletRecord::Note(n) => n.input.note.token_address == sdk::address_word(token),
                WalletRecord::Credit(c) => {
                    c.delivery.note.token_address == sdk::address_word(token)
                }
                WalletRecord::Operation(o) => o.snapshot.token() == token,
            })
        });
        let next_cursor = if more {
            Some(hex::encode(
                serde_json::to_vec(&cursor).map_err(|_| "history cursor encoding failed")?,
            ))
        } else {
            None
        };
        Ok(SessionHistoryPage {
            entries: output,
            next_cursor,
        })
    }
}
