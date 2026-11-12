use super::*;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecordKind {
    Note,
    Credit,
    Operation,
}
pub struct SessionRecordEntry {
    pub record: WalletRecord,
    pub canonical: String,
    pub archived: bool,
}
pub struct SessionRecordPage {
    pub entries: Vec<SessionRecordEntry>,
    pub next_cursor: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct Cursor {
    scope: String,
    revision: u64,
    kind: Option<RecordKind>,
    token: Option<Address>,
    generation: Option<u64>,
    active: Option<usize>,
    archive_after: Option<String>,
}
fn kind(record: &WalletRecord) -> RecordKind {
    match record {
        WalletRecord::Note(_) => RecordKind::Note,
        WalletRecord::Credit(_) => RecordKind::Credit,
        WalletRecord::Operation(_) => RecordKind::Operation,
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
    pub(crate) fn history_generation(&self) -> Result<Option<u64>> {
        self.public_history
            .as_ref()
            .map(|h| h.snapshot().map(|s| s.generation))
            .transpose()
    }
    pub(crate) fn ensure_history_generation(
        &self,
        generation: Option<u64>,
        revision: u64,
    ) -> Result<()> {
        if self.history_generation()? != generation {
            self.fence_public_history()?;
            return Err("public history changed during history read".into());
        }
        if self.store.read_summary(&self.scope.key())?.revision != revision {
            return Err("wallet changed during history read".into());
        }
        Ok(())
    }

    pub fn record_page(&self, after: Option<&str>, limit: usize) -> Result<SessionRecordPage> {
        self.record_page_filtered(after, limit, None, None)
    }
    /// Token filtering applies to the selected page; an empty page may still have a continuation.
    pub fn record_page_filtered(
        &self,
        after: Option<&str>,
        limit: usize,
        selected: Option<RecordKind>,
        token: Option<Address>,
    ) -> Result<SessionRecordPage> {
        if limit == 0 || limit > 1000 {
            return Err("history page limit must be 1..1000".into());
        }
        self.fence_public_history()?;
        let generation = self.history_generation()?;
        let state = self.snapshot()?;
        let scope = hex::encode(alloy_primitives::keccak256(self.scope.key().as_bytes()));
        let mut cursor = if let Some(after) = after {
            if after.len() > 8192 {
                return Err("invalid history cursor".into());
            }
            let bytes = hex::decode(after).map_err(|_| "invalid history cursor")?;
            let c: Cursor = serde_json::from_slice(&bytes).map_err(|_| "invalid history cursor")?;
            if c.scope != scope
                || c.revision != state.revision
                || c.kind != selected
                || c.token != token
                || c.generation != generation
            {
                return Err("history cursor belongs to another account, kind or revision".into());
            }
            c
        } else {
            Cursor {
                scope,
                revision: state.revision,
                kind: selected,
                token,
                generation,
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
                SessionRecordEntry {
                    record,
                    archived: false,
                    canonical: if state.invalidated {
                        "unknown"
                    } else {
                        "current"
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
                    .map(|e| SessionRecordEntry {
                        record: e.record,
                        archived: true,
                        canonical: if state.invalidated
                            || e.public_history_generation.is_none()
                            || e.public_history_generation != state.public_history_generation
                        {
                            "unknown"
                        } else {
                            "current"
                        }
                        .into(),
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
        self.ensure_history_generation(generation, state.revision)?;
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
        Ok(SessionRecordPage {
            entries: output,
            next_cursor,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryDirection {
    Incoming,
    Outgoing,
}
#[derive(Clone, Debug)]
pub enum BusinessHistoryEntry {
    Incoming(IncomingHistory),
    Outgoing(OutgoingHistory),
}
#[derive(Clone, Debug)]
pub struct BusinessHistoryItem {
    pub entry: BusinessHistoryEntry,
    pub archived: bool,
    pub canonical: String,
}
#[derive(Clone, Debug)]
pub struct WalletHistoryPage {
    pub revision: u64,
    pub checked_through: Option<CanonicalBlock>,
    pub invalidated: bool,
    pub items: Vec<BusinessHistoryItem>,
    pub next_cursor: Option<String>,
}
impl WalletSession {
    /// Project authenticated business fields without exporting witnesses or authorizations.
    pub fn history_page(
        &self,
        direction: HistoryDirection,
        after: Option<&str>,
        limit: usize,
        token: Option<Address>,
    ) -> Result<WalletHistoryPage> {
        self.fence_public_history()?;
        let generation = self.history_generation()?;
        let summary = self.store.read_summary(&self.scope.key())?;
        let selected = match direction {
            HistoryDirection::Incoming => RecordKind::Note,
            HistoryDirection::Outgoing => RecordKind::Operation,
        };
        let page = self.record_page_filtered(after, limit, Some(selected), token)?;
        let mut items = Vec::new();
        for item in page.entries {
            let entry = match item.record {
                WalletRecord::Note(n) => BusinessHistoryEntry::Incoming(IncomingHistory {
                    commitment: n.commitment,
                    tree_id: n.input.tree_id,
                    leaf_index: n.input.leaf_index,
                    token: sdk::word_address(n.input.note.token_address)?,
                    amount: n.input.note.amount,
                    payload: n.input.note.payload,
                    transaction_hash: n.transaction_hash,
                    block: n.block,
                    spent: n.spent,
                    reserved_by: n.reserved_by,
                }),
                WalletRecord::Operation(o) => BusinessHistoryEntry::Outgoing(OutgoingHistory {
                    id: o.id,
                    kind: o.kind,
                    status: o.status,
                    transaction_hash: o.transaction_hash,
                    deadline: o.deadline,
                    prepared_at: o.snapshot.anchor().clone(),
                    token: o.snapshot.token(),
                    input_count: o.inputs.len(),
                    intent: o.snapshot.history()?,
                }),
                WalletRecord::Credit(_) => return Err("unexpected business history record".into()),
            };
            items.push(BusinessHistoryItem {
                entry,
                archived: item.archived,
                canonical: if summary.invalidated {
                    "unknown".into()
                } else {
                    item.canonical
                },
            });
        }
        self.ensure_history_generation(generation, summary.revision)?;
        Ok(WalletHistoryPage {
            revision: summary.revision,
            checked_through: summary.discovery_through,
            invalidated: summary.invalidated,
            items,
            next_cursor: page.next_cursor,
        })
    }
}
