use super::*;
#[derive(Clone, Debug)]
pub struct CreditInput {
    pub payload: Option<Vec<u8>>,
    pub delivery: CreditDeliveryState,
    pub tree_id: u64,
    pub leaf_index: u16,
    pub path: [U256; 16],
    pub root: U256,
    pub debit: U256,
}
impl CreditInput {
    fn validate(
        &self,
        chain: &dyn ChainState,
        block: &CanonicalBlock,
        context: ProtocolContext,
        token: Address,
    ) -> Result<()> {
        model(self.delivery.validate())?;
        let s = &self.delivery.note;
        if self.tree_id == 0
            || s.context != context
            || s.token_address != address_word(token)
            || merkle_root(model(s.commitment())?, self.leaf_index, &self.path)? != self.root
            || !chain.known_root(self.tree_id, field_word(self.root), block)?
            || chain.nullifier_spent(field_word(model(s.nullifier())?), block)?
            || chain.credit_revoked(
                word_address(s.owner_wallet_identity)?,
                token,
                s.revocation_shard,
                s.revocation_slot,
                block,
            )?
        {
            return Err(
                "Credit input context, membership, consumption or revocation mismatch".into(),
            );
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(crate) enum CreditPlan {
    Create {
        params: abi::CreateCreditParams,
        created: CreditDeliveryState,
    },
    Update {
        params: abi::UpdateCreditParams,
        input: CreditInput,
        changes: crate::credit::CreditUpdateChanges,
        next: CreditDeliveryState,
    },
    Draw {
        params: abi::CreditDrawParams,
        inputs: Vec<CreditInput>,
        successors: Vec<CreditDeliveryState>,
        output: NoteOutput,
    },
    Revoke {
        owner: Address,
        token: Address,
        shard: u64,
        slot: u16,
        deadline: u64,
        fee: Fee,
        signature: Vec<u8>,
    },
}
#[derive(Clone)]
pub struct PreparedCredit {
    pub(crate) preparation_reads: Option<Arc<PreparationChain>>,
    pub(crate) wallet: Option<Wallet>,
    pub(crate) owner_address: Address,
    pub(crate) context: ProtocolContext,
    pub(crate) token: Address,
    pub(crate) anchor: CanonicalBlock,
    pub(crate) constructed_at: u64,
    pub(crate) plan: CreditPlan,
    pub(crate) deliveries: Vec<abi::Delivery>,
    pub(crate) phase: Phase,
    pub(crate) authorization: Option<WalletAuthorization>,
    pub(crate) proof: Option<ProofBundle>,
    pub(crate) provenance: Option<Arc<PreparedProvenance>>,
    pub(crate) provenance_factory: Option<ProvenanceFactory>,
    pub(crate) broadcaster: Option<PreparedBroadcasterState>,
    pub(crate) reprice: Option<CreditRepriceTemplate>,
}
#[derive(Clone)]
pub(crate) enum CreditRepriceTemplate {
    Create(CreditDeliveryState, u64),
    Update(CreditInput, crate::credit::CreditUpdateChanges, u64),
    Draw(Vec<CreditInput>, Wallet, u64, Vec<u8>),
    Revoke(Address, u64, u16, u64),
}
impl std::fmt::Debug for PreparedCredit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedCredit")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}
fn credit_deliveries(state: &CreditDeliveryState) -> Result<Vec<abi::Delivery>> {
    model(state.validate())?;
    let context = DeliveryContext {
        context: state.note.context,
        token_address: state.note.token_address,
        output_commitment: model(state.note.commitment())?,
    };
    [CreditRole::Owner, CreditRole::Spender]
        .into_iter()
        .map(|role| {
            let keys = if role == CreditRole::Owner {
                &state.owner_receiving_keys
            } else {
                &state.spender_receiving_keys
            };
            Ok(abi::Delivery {
                ciphertext: model(crate::delivery::encrypt_credit(
                    &keys.viewing_public_key,
                    state,
                    &context,
                    role,
                ))?
                .into(),
                clue: model(crate::fmd::create_clue(&keys.clue_key))?.into(),
            })
        })
        .collect()
}
fn fee_balance(
    chain: &dyn ChainState,
    owner: Address,
    token: Address,
    fee: U256,
    block: &CanonicalBlock,
) -> Result<()> {
    if fee != U256::ZERO && !chain.historical_preparation() {
        let (balance, allowance) = chain.token_balance_allowance(owner, token, block)?;
        if balance < fee || allowance < fee {
            return Err("ERC20 balance or Protocol allowance insufficient".into());
        }
    }
    Ok(())
}
fn credit_capacity(n: usize) -> Result<usize> {
    if n == 0 || n > 80 {
        return Err("Credit draw requires one through eighty grants".into());
    }
    ([1, 2, 3, 4, 5].into_iter().chain((10..=80).step_by(10)))
        .find(|c| *c >= n)
        .ok_or_else(|| "unsupported Credit draw capacity".into())
}
impl Invisi {
    pub fn prepare_create_credit_explicit(
        &self,
        wallet: &Wallet,
        state: CreditDeliveryState,
        deadline: u64,
        fee: Fee,
    ) -> PreparationResult<PreparedCredit> {
        self.prepare_create_credit_explicit_internal(wallet, state, deadline, fee)
            .map_err(|cause| InvisiError::preparation("prepare_create_credit", cause))
    }
    fn prepare_create_credit_explicit_internal(
        &self,
        wallet: &Wallet,
        state: CreditDeliveryState,
        deadline: u64,
        fee: Fee,
    ) -> Result<PreparedCredit> {
        let template = CreditRepriceTemplate::Create(state.clone(), deadline);
        let reads = Arc::new(PreparationChain::new(self.chain.clone()));
        let chain = &*reads;
        let anchor = chain.snapshot()?;
        let constructed_at = chain.construction_timestamp(&anchor);
        let context = chain.context();
        fee.validate()?;
        model(state.validate())?;
        let s = &state.note;
        let token = word_address(s.token_address)?;
        if s.context != context
            || s.owner_wallet_identity != address_word(wallet.owner_address)
            || s.expiry < deadline
            || s.expiry <= constructed_at
            || deadline < constructed_at
            || s.usage != crate::credit::CreditUsage::default()
            || s.revocation_shard == 0
        {
            return Err("invalid initial Credit owner, usage, expiry or context".into());
        }
        if chain.credit_allocation(wallet.owner_address, token, &anchor)?
            != (s.revocation_shard, s.revocation_slot)
        {
            return Err("Credit allocation changed".into());
        }
        fee_balance(chain, wallet.owner_address, token, fee.amount, &anchor)?;
        let params = abi::CreateCreditParams {
            token,
            owner: wallet.owner_address,
            revocationShard: s.revocation_shard,
            revocationSlot: s.revocation_slot,
            creditCommitment: field_word(model(s.commitment())?),
            deadline: U256::from(deadline),
            feeRecipient: fee.recipient,
            feeAmount: fee.amount,
        };
        let deliveries = credit_deliveries(&state)?;
        chain.canonical(&anchor)?;
        Ok(PreparedCredit {
            preparation_reads: Some(reads),
            wallet: Some(wallet.clone()),
            owner_address: wallet.owner_address,
            context,
            token,
            anchor,
            constructed_at,
            plan: CreditPlan::Create {
                params,
                created: state,
            },
            deliveries,
            phase: Phase::Prepared,
            authorization: None,
            proof: None,
            provenance: self.provenance.clone(),
            provenance_factory: self.provenance_factory.clone(),
            broadcaster: None,
            reprice: Some(template),
        })
    }
    pub fn prepare_update_credit_explicit(
        &self,
        wallet: &Wallet,
        input: CreditInput,
        changes: crate::credit::CreditUpdateChanges,
        deadline: u64,
        fee: Fee,
    ) -> PreparationResult<PreparedCredit> {
        self.prepare_update_credit_explicit_internal(wallet, input, changes, deadline, fee)
            .map_err(|cause| InvisiError::preparation("prepare_update_credit", cause))
    }
    fn prepare_update_credit_explicit_internal(
        &self,
        wallet: &Wallet,
        input: CreditInput,
        changes: crate::credit::CreditUpdateChanges,
        deadline: u64,
        fee: Fee,
    ) -> Result<PreparedCredit> {
        let template = CreditRepriceTemplate::Update(input.clone(), changes.clone(), deadline);
        let reads = Arc::new(PreparationChain::new(self.chain.clone()));
        let chain = &*reads;
        let anchor = chain.snapshot()?;
        let constructed_at = chain.construction_timestamp(&anchor);
        let context = chain.context();
        fee.validate()?;
        let s = &input.delivery.note;
        let token = word_address(s.token_address)?;
        input.validate(chain, &anchor, context, token)?;
        if s.owner_wallet_identity != address_word(wallet.owner_address)
            || deadline < constructed_at
        {
            return Err("Credit update owner or deadline mismatch".into());
        }
        let updated = model(crate::credit::derive_credit_update(s, &changes, deadline))?;
        let next = CreditDeliveryState {
            note: updated.state,
            owner_receiving_keys: input.delivery.owner_receiving_keys.clone(),
            spender_receiving_keys: input.delivery.spender_receiving_keys.clone(),
        };
        let params = abi::UpdateCreditParams {
            token,
            owner: wallet.owner_address,
            source: abi::InputSource {
                treeId: U256::from(input.tree_id),
                merkleRoot: field_word(input.root),
            },
            nullifier: field_word(updated.nullifier),
            creditCommitment: field_word(updated.state_commitment),
            revocationShard: s.revocation_shard,
            revocationSlot: s.revocation_slot,
            deadline: U256::from(deadline),
            feeRecipient: fee.recipient,
            feeAmount: fee.amount,
        };
        fee_balance(chain, wallet.owner_address, token, fee.amount, &anchor)?;
        let deliveries = credit_deliveries(&next)?;
        chain.canonical(&anchor)?;
        Ok(PreparedCredit {
            preparation_reads: Some(reads),
            wallet: Some(wallet.clone()),
            owner_address: wallet.owner_address,
            context,
            token,
            anchor,
            constructed_at,
            plan: CreditPlan::Update {
                params,
                input,
                changes,
                next,
            },
            deliveries,
            phase: Phase::Prepared,
            authorization: None,
            proof: None,
            provenance: self.provenance.clone(),
            provenance_factory: self.provenance_factory.clone(),
            broadcaster: None,
            reprice: Some(template),
        })
    }
    pub fn prepare_draw_credit_explicit(
        &self,
        wallet: &Wallet,
        inputs: Vec<CreditInput>,
        recipient: &Wallet,
        deadline: u64,
        fee: Fee,
        payload: Vec<u8>,
    ) -> PreparationResult<PreparedCredit> {
        self.prepare_draw_credit_explicit_internal(
            wallet, inputs, recipient, deadline, fee, payload,
        )
        .map_err(|cause| InvisiError::preparation("prepare_draw_credit", cause))
    }
    fn prepare_draw_credit_explicit_internal(
        &self,
        wallet: &Wallet,
        mut inputs: Vec<CreditInput>,
        recipient: &Wallet,
        deadline: u64,
        fee: Fee,
        payload: Vec<u8>,
    ) -> Result<PreparedCredit> {
        let template = CreditRepriceTemplate::Draw(
            inputs.clone(),
            recipient.clone(),
            deadline,
            payload.clone(),
        );
        let reads = Arc::new(PreparationChain::new(self.chain.clone()));
        let chain = &*reads;
        let anchor = chain.snapshot()?;
        let constructed_at = chain.construction_timestamp(&anchor);
        let context = chain.context();
        fee.validate()?;
        let c = credit_capacity(inputs.len())?;
        if deadline < constructed_at {
            return Err("Credit draw deadline expired".into());
        }
        let token = word_address(inputs[0].delivery.note.token_address)?;
        inputs.sort_by_key(|input| {
            (
                input.delivery.note.owner_wallet_identity,
                input.delivery.note.revocation_shard,
                input.delivery.note.revocation_slot,
            )
        });
        let mut groups: BTreeMap<Address, U256> = BTreeMap::new();
        let mut sources: BTreeMap<u64, U256> = BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut seen_refs = BTreeSet::new();
        let mut transitions = Vec::new();
        let mut successors = Vec::new();
        let mut deliveries = Vec::new();
        let prepared_inputs = map_preparation(inputs.len(), |i| {
            let input = &inputs[i];
            input.validate(chain, &anchor, context, token)?;
            let mut transition = model(crate::credit::derive_credit_state(
                &input.delivery.note,
                input.debit,
                constructed_at,
            ))?;
            if let Some(payload) = &input.payload {
                transition.state.payload = payload.clone();
            }
            let next = CreditDeliveryState {
                note: transition.state.clone(),
                owner_receiving_keys: input.delivery.owner_receiving_keys.clone(),
                spender_receiving_keys: input.delivery.spender_receiving_keys.clone(),
            };
            let ds = credit_deliveries(&next)?;
            Ok((transition, next, ds))
        })?;
        for (input, (transition, next, ds)) in inputs.iter().zip(prepared_inputs) {
            let s = &input.delivery.note;
            if s.spender_wallet_identity != address_word(wallet.owner_address)
                || s.expiry < deadline
                || !seen_refs.insert((
                    s.owner_wallet_identity,
                    s.revocation_shard,
                    s.revocation_slot,
                ))
            {
                return Err("Credit spender, expiry or duplicate grant reference mismatch".into());
            }
            if !seen.insert(transition.nullifier) {
                return Err("duplicate Credit input".into());
            }
            let owner = word_address(s.owner_wallet_identity)?;
            let amount = groups.entry(owner).or_default();
            *amount = amount
                .checked_add(input.debit)
                .ok_or("payer receipt overflow")?;
            if sources
                .insert(input.tree_id, input.root)
                .is_some_and(|root| root != input.root)
            {
                return Err("Credit input tree root conflict".into());
            }
            deliveries.extend(ds);
            successors.push(next);
            transitions.push(transition);
        }
        let total = sum(groups.values().copied())?;
        model(crate::note::uint(total, 128, "Credit total debit"))?;
        if total <= fee.amount {
            return Err("Credit fee must leave positive ordinary Note".into());
        }
        let payer_checks = groups.iter().collect::<Vec<_>>();
        map_preparation(payer_checks.len(), |i| {
            let (owner, amount) = payer_checks[i];
            fee_balance(chain, *owner, token, *amount, &anchor)
        })?;
        let payers: Vec<abi::CreditPayer> = groups
            .iter()
            .map(|(owner, amount)| abi::CreditPayer {
                payer: *owner,
                amount: *amount,
            })
            .collect();
        let refs = inputs
            .iter()
            .map(|i| {
                let s = &i.delivery.note;
                Ok(abi::CreditGrantRef {
                    payerIndex: U256::from(
                        payers
                            .iter()
                            .position(|p| address_word(p.payer) == s.owner_wallet_identity)
                            .ok_or("Credit payer missing")?,
                    ),
                    shard: s.revocation_shard,
                    slot: s.revocation_slot,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let output =
            NoteOutput::for_recipient(context, token, recipient, total - fee.amount, payload)?;
        deliveries.push(output.delivery.clone());
        let params = abi::CreditDrawParams {
            token,
            sources: sources
                .into_iter()
                .map(|(tree, root)| abi::InputSource {
                    treeId: U256::from(tree),
                    merkleRoot: field_word(root),
                })
                .collect(),
            payers,
            grantRefs: refs,
            nullifiers: transitions
                .iter()
                .map(|t| field_word(t.nullifier))
                .collect(),
            creditCommitments: transitions
                .iter()
                .map(|t| field_word(t.state_commitment))
                .collect(),
            recoveryAmounts: transitions
                .iter()
                .map(|t| field_word(t.recovery_amount))
                .collect(),
            noteCommitment: output.commitment,
            totalAmount: total,
            deadline: U256::from(deadline),
            feeRecipient: fee.recipient,
            feeAmount: fee.amount,
        };
        if params.sources.len() > c {
            return Err("Credit source count exceeds capacity".into());
        }
        chain.canonical(&anchor)?;
        Ok(PreparedCredit {
            preparation_reads: Some(reads),
            wallet: Some(wallet.clone()),
            owner_address: wallet.owner_address,
            context,
            token,
            anchor,
            constructed_at,
            plan: CreditPlan::Draw {
                params,
                inputs,
                successors,
                output,
            },
            deliveries,
            phase: Phase::Prepared,
            authorization: None,
            proof: None,
            provenance: self.provenance.clone(),
            provenance_factory: self.provenance_factory.clone(),
            broadcaster: None,
            reprice: Some(template),
        })
    }
    pub fn prepare_revoke_credit_explicit(
        &self,
        owner_address: Address,
        token: Address,
        shard: u64,
        slot: u16,
        deadline: u64,
        fee: Fee,
    ) -> PreparationResult<PreparedCredit> {
        self.prepare_revoke_credit_explicit_internal(
            owner_address,
            token,
            shard,
            slot,
            deadline,
            fee,
        )
        .map_err(|cause| InvisiError::preparation("prepare_revoke_credit", cause))
    }
    fn prepare_revoke_credit_explicit_internal(
        &self,
        owner_address: Address,
        token: Address,
        shard: u64,
        slot: u16,
        deadline: u64,
        fee: Fee,
    ) -> Result<PreparedCredit> {
        if owner_address == Address::ZERO {
            return Err("nonzero owner address required".into());
        }
        let template = CreditRepriceTemplate::Revoke(token, shard, slot, deadline);
        let reads = Arc::new(PreparationChain::new(self.chain.clone()));
        let chain = &*reads;
        let anchor = chain.snapshot()?;
        let constructed_at = chain.construction_timestamp(&anchor);
        let context = chain.context();
        fee.validate()?;
        let current = chain.credit_allocation(owner_address, token, &anchor)?;
        if deadline < constructed_at
            || shard == 0
            || (shard, slot) >= current
            || chain.credit_revoked(owner_address, token, shard, slot, &anchor)?
        {
            return Err("Credit revocation reference is unallocated, revoked or expired".into());
        }
        fee_balance(chain, owner_address, token, fee.amount, &anchor)?;
        chain.canonical(&anchor)?;
        Ok(PreparedCredit {
            preparation_reads: Some(reads),
            wallet: None,
            owner_address: owner_address,
            context,
            token,
            anchor,
            constructed_at,
            plan: CreditPlan::Revoke {
                owner: owner_address,
                token,
                shard,
                slot,
                deadline,
                fee,
                signature: Vec::new(),
            },
            deliveries: Vec::new(),
            phase: Phase::Prepared,
            authorization: None,
            proof: None,
            provenance: self.provenance.clone(),
            provenance_factory: self.provenance_factory.clone(),
            broadcaster: None,
            reprice: Some(template),
        })
    }
}
fn policy_fields(p: &crate::credit::CreditPolicy) -> Vec<String> {
    vec![
        p.single_limit.to_string(),
        p.daily_limit.to_string(),
        p.monthly_limit.to_string(),
    ]
}
fn usage_fields(p: &crate::credit::CreditUsage) -> Vec<String> {
    vec![
        p.last_day.to_string(),
        p.daily_spent.to_string(),
        p.last_month.to_string(),
        p.monthly_spent.to_string(),
        p.total_spent.to_string(),
    ]
}
fn bool_field(v: bool) -> String {
    if v { "1" } else { "0" }.into()
}
impl PreparedCredit {
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn wallet(&self) -> Option<&Wallet> {
        self.wallet.as_ref()
    }
    pub fn owner_address(&self) -> Address {
        self.owner_address
    }
    pub fn anchor(&self) -> &CanonicalBlock {
        &self.anchor
    }
    pub fn output_note(&self) -> Option<&NoteOutput> {
        match &self.plan {
            CreditPlan::Draw { output, .. } => Some(output),
            _ => None,
        }
    }
    pub fn successor_states(&self) -> Vec<&CreditDeliveryState> {
        match &self.plan {
            CreditPlan::Create { created, .. } => vec![created],
            CreditPlan::Update { next, .. } => vec![next],
            CreditPlan::Draw { successors, .. } => successors.iter().collect(),
            _ => Vec::new(),
        }
    }
    pub(crate) fn credit_inputs(&self) -> Vec<&CreditInput> {
        match &self.plan {
            CreditPlan::Update { input, .. } => vec![input],
            CreditPlan::Draw { inputs, .. } => inputs.iter().collect(),
            _ => Vec::new(),
        }
    }
    fn operation(&self) -> Result<(&'static str, String, usize)> {
        Ok(match &self.plan {
            CreditPlan::Create { .. } => ("create-credit", "create_credit".into(), 1),
            CreditPlan::Update { .. } => ("update-credit", "credit_update".into(), 1),
            CreditPlan::Draw { inputs, .. } => {
                let c = credit_capacity(inputs.len())?;
                ("credit-draw", format!("credit_draw_slots{c}"), c)
            }
            _ => return Err("Credit revocation uses public EVM authorization".into()),
        })
    }
    pub fn public_inputs(&self) -> Result<Vec<U256>> {
        let (operation, _, capacity) = self.operation()?;
        let mut words = vec![
            U256::from(self.context.chain_id),
            self.context.protocol_address,
            address_word(self.token),
        ];
        let hash = split(hash_deliveries(&self.deliveries));
        match &self.plan {
            CreditPlan::Create { params: p, .. } => {
                words.extend([
                    address_word(p.owner),
                    U256::from(p.revocationShard),
                    U256::from(p.revocationSlot),
                    U256::from_be_slice(p.creditCommitment.as_slice()),
                    p.deadline,
                    hash[0],
                    hash[1],
                    address_word(p.feeRecipient),
                    p.feeAmount,
                ]);
            }
            CreditPlan::Update { params: p, .. } => {
                words.extend([
                    address_word(p.owner),
                    p.source.treeId,
                    U256::from_be_slice(p.source.merkleRoot.as_slice()),
                    U256::from_be_slice(p.nullifier.as_slice()),
                    U256::from_be_slice(p.creditCommitment.as_slice()),
                    U256::from(p.revocationShard),
                    U256::from(p.revocationSlot),
                    p.deadline,
                    hash[0],
                    hash[1],
                    address_word(p.feeRecipient),
                    p.feeAmount,
                ]);
            }
            CreditPlan::Draw { params: p, .. } => {
                words.extend([
                    U256::from(p.nullifiers.len()),
                    U256::from(p.sources.len()),
                    U256::from(p.payers.len()),
                ]);
                let mut arrays = vec![Vec::new(); 10];
                for source in &p.sources {
                    arrays[0].push(source.treeId);
                    arrays[1].push(U256::from_be_slice(source.merkleRoot.as_slice()));
                }
                for payer in &p.payers {
                    arrays[2].push(address_word(payer.payer));
                    arrays[3].push(payer.amount);
                }
                for (i, r) in p.grantRefs.iter().enumerate() {
                    arrays[4].push(r.payerIndex);
                    arrays[5].push(U256::from(r.shard));
                    arrays[6].push(U256::from(r.slot));
                    arrays[7].push(U256::from_be_slice(p.nullifiers[i].as_slice()));
                    arrays[8].push(U256::from_be_slice(p.creditCommitments[i].as_slice()));
                    arrays[9].push(U256::from_be_slice(p.recoveryAmounts[i].as_slice()));
                }
                for mut row in arrays {
                    row.resize(capacity, U256::ZERO);
                    words.extend(row);
                }
                let (day, month) = crate::credit::credit_periods(self.constructed_at);
                words.extend([
                    U256::from_be_slice(p.noteCommitment.as_slice()),
                    p.totalAmount,
                    p.deadline,
                    hash[0],
                    hash[1],
                    U256::from(day),
                    U256::from(month),
                    address_word(p.feeRecipient),
                    p.feeAmount,
                ]);
            }
            _ => return Err("revocation has no ZK statement".into()),
        };
        auth_words(self.context, operation, capacity, words)
    }
    pub fn export_wallet_authorization(&self) -> Result<EvmSigningRequest> {
        if ![Phase::Prepared, Phase::Authorized].contains(&self.phase) {
            return Err("Credit operation is not awaiting authorization".into());
        }
        let (operation, _, capacity) = self.operation()?;
        let words = self.public_inputs()?;
        wallet_authorization_request(self.context, operation, capacity, &words[..words.len() - 2])
    }
    pub fn with_wallet_signature(mut self, signature: &[u8]) -> Result<Self> {
        self.authorization = Some(accept_wallet_signature(
            self.owner_address,
            &self.export_wallet_authorization()?,
            signature,
        )?);
        self.phase = Phase::Authorized;
        Ok(self)
    }
    pub fn export_wallet_request(&self, id: impl Into<String>) -> Result<WalletRequest> {
        if ![Phase::Prepared, Phase::Authorized].contains(&self.phase) {
            return Err("Credit operation is not awaiting authorization".into());
        }
        let (operation, _, capacity) = self.operation()?;
        let words = self.public_inputs()?;
        prepare_wallet_request(
            self.owner_address,
            id,
            "wallet.authorize",
            authorization_params(self.context, operation, capacity, &words[..words.len() - 2]),
        )
    }
    pub fn with_wallet_response(mut self, q: &WalletRequest, r: &WalletResponse) -> Result<Self> {
        let expected = self.export_wallet_request(q.id.clone())?;
        if expected.params != q.params {
            return Err("Credit response differs from frozen statement".into());
        }
        match accept_wallet_response(
            self.owner_address,
            self.wallet.as_ref().map(|w| &w.receiving_keys),
            q,
            r,
        )? {
            WalletResult::Authorized(a) => self.authorization = Some(a),
            _ => return Err("wallet authorization response required".into()),
        }
        self.phase = Phase::Authorized;
        Ok(self)
    }
    fn private_inputs(&self) -> Result<Value> {
        let a = self
            .authorization
            .as_ref()
            .ok_or("Credit wallet authorization required")?;
        let mut v = json!({"public_key_x":a.spending_public_key[1..33].to_vec(),"public_key_y":a.spending_public_key[33..].to_vec(),"signature":a.signature.to_vec()});
        match &self.plan {
            CreditPlan::Create { created, .. } => {
                let s = &created.note;
                v["spender_wallet_identity"] = json!(s.spender_wallet_identity.to_string());
                v["credit_nonce"] = json!(s.nonce.to_string());
                v["expiry"] = json!(s.expiry.to_string());
                v["credit_shared_key"] = json!(s.credit_shared_key.to_string());
                v["limits"] = json!(policy_fields(&s.policy));
                v["available_credit"] = json!(s.available_credit.to_string());
                v["unlimited"] = json!(bool_field(s.unlimited));
            }
            CreditPlan::Update {
                input,
                changes,
                next,
                ..
            } => {
                let s = &input.delivery.note;
                let n = &next.note;
                v["spender_wallet_identity"] = json!(s.spender_wallet_identity.to_string());
                v["input_nonce"] = json!(s.nonce.to_string());
                v["old_expiry"] = json!(s.expiry.to_string());
                v["new_expiry"] = json!(n.expiry.to_string());
                v["credit_shared_key"] = json!(s.credit_shared_key.to_string());
                v["old_available_credit"] = json!(s.available_credit.to_string());
                v["old_unlimited"] = json!(bool_field(s.unlimited));
                v["new_unlimited"] = json!(bool_field(n.unlimited));
                v["increase_available_credit"] =
                    json!(changes.increase_available_credit.to_string());
                v["decrease_available_credit"] =
                    json!(changes.decrease_available_credit.to_string());
                v["old_limits"] = json!(policy_fields(&s.policy));
                v["new_limits"] = json!(policy_fields(&n.policy));
                v["usage"] = json!(usage_fields(&s.usage));
                v["leaf_index"] = json!(input.leaf_index.to_string());
                v["merkle_path"] =
                    json!(input.path.iter().map(U256::to_string).collect::<Vec<_>>());
            }
            CreditPlan::Draw {
                params,
                inputs,
                output,
                ..
            } => {
                let c = credit_capacity(inputs.len())?;
                v["spender_wallet_identity"] = json!(address_word(self.owner_address).to_string());
                let mut arrays: BTreeMap<&str, Vec<String>> = [
                    "input_nonces",
                    "expiries",
                    "credit_shared_keys",
                    "available_credits",
                    "unlimited_flags",
                    "leaf_indices",
                    "input_source_indices",
                    "draw_amounts",
                ]
                .into_iter()
                .map(|name| (name, vec!["0".into(); c]))
                .collect();
                let mut limits = vec![vec!["0".to_string(); 3]; c];
                let mut usages = vec![vec!["0".to_string(); 5]; c];
                let mut paths = vec![vec!["0".to_string(); 16]; c];
                for (i, input) in inputs.iter().enumerate() {
                    let s = &input.delivery.note;
                    for (key, value) in [
                        ("input_nonces", s.nonce.to_string()),
                        ("expiries", s.expiry.to_string()),
                        ("credit_shared_keys", s.credit_shared_key.to_string()),
                        ("available_credits", s.available_credit.to_string()),
                        ("unlimited_flags", bool_field(s.unlimited)),
                        ("leaf_indices", input.leaf_index.to_string()),
                        (
                            "input_source_indices",
                            params
                                .sources
                                .iter()
                                .position(|source| source.treeId == U256::from(input.tree_id))
                                .ok_or("missing Credit source")?
                                .to_string(),
                        ),
                        ("draw_amounts", input.debit.to_string()),
                    ] {
                        arrays.get_mut(key).unwrap()[i] = value;
                    }
                    limits[i] = policy_fields(&s.policy);
                    usages[i] = usage_fields(&s.usage);
                    paths[i] = input.path.iter().map(U256::to_string).collect();
                }
                for (name, row) in arrays {
                    v[name] = json!(row);
                }
                v["limits"] = json!(limits);
                v["usages"] = json!(usages);
                v["merkle_paths"] = json!(paths);
                v["output_identity"] = json!(output.identity.to_string());
            }
            _ => return Err("revocation has no local witness".into()),
        };
        Ok(v)
    }
    pub fn prove(mut self, backend: &dyn Prover) -> Result<Self> {
        if self.phase != Phase::Authorized {
            return Err("authorize Credit before proving".into());
        }
        let (_, name, _) = self.operation()?;
        let request = prover::request(
            &name,
            "evm",
            self.private_inputs()?,
            self.public_inputs()?.into_iter().map(field_word).collect(),
        )?;
        let proof = backend.prove(&request)?;
        prover::assert_bundle(&proof, &request.statement)?;
        if !backend.verify(&proof, &request.statement)? {
            return Err("independent Credit proof verification failed".into());
        }
        self.proof = Some(proof);
        self.authorization = None;
        self.phase = Phase::Proved;
        Ok(self)
    }
    pub fn proof(&self) -> Option<&ProofBundle> {
        self.proof.as_ref()
    }

    pub fn validate_submission(&self, chain: &dyn ChainState, caller: Address) -> Result<()> {
        if chain.historical_preparation() {
            return Err("live chain required for submission validation".into());
        }
        self.calldata(chain, caller).map(|_| ())
    }
    pub fn calldata(&self, chain: &dyn ChainState, caller: Address) -> Result<TransactionCall> {
        let block = chain.snapshot()?;
        if chain.context() != self.context {
            return Err("Credit deployment mismatch".into());
        }
        chain.canonical(&self.anchor)?;
        let inputs = self.credit_inputs();
        map_preparation(inputs.len(), |i| {
            inputs[i].validate(chain, &block, self.context, self.token)
        })?;
        let contract =
            protocol::ProtocolContract::new(word_address(self.context.protocol_address)?)?;
        let proof = if matches!(self.plan, CreditPlan::Revoke { .. }) {
            Bytes::new()
        } else {
            if self.phase != Phase::Proved {
                return Err("verified Credit proof required".into());
            }
            let bundle = self.proof.as_ref().ok_or("Credit proof required")?;
            let expected = prover::statement(
                &self.operation()?.1,
                "evm",
                self.public_inputs()?.into_iter().map(field_word).collect(),
            )?;
            prover::assert_bundle(bundle, &expected)?;
            <(
                alloy_sol_types::sol_data::Uint<8>,
                alloy_sol_types::sol_data::Bytes,
            ) as alloy_sol_types::SolType>::abi_encode_params(&(
                0u8,
                Bytes::copy_from_slice(&bundle.proof),
            ))
            .into()
        };
        match &self.plan {
            CreditPlan::Create { params: p, .. } => {
                if p.deadline < U256::from(block.timestamp)
                    || chain.credit_allocation(p.owner, p.token, &block)?
                        != (p.revocationShard, p.revocationSlot)
                {
                    return Err("Credit create deadline or allocation changed".into());
                }
                fee_balance(chain, p.owner, p.token, p.feeAmount, &block)?;
                Ok(contract.call(&InvisiProtocol::createCreditCall {
                    _0: proof,
                    p: p.clone(),
                    _2: self.deliveries.clone(),
                }))
            }
            CreditPlan::Update { params: p, .. } => {
                if p.deadline < U256::from(block.timestamp) {
                    return Err("Credit update expired".into());
                }
                fee_balance(chain, p.owner, p.token, p.feeAmount, &block)?;
                Ok(contract.call(&InvisiProtocol::updateCreditCall {
                    _0: proof,
                    p: p.clone(),
                    _2: self.deliveries.clone(),
                }))
            }
            CreditPlan::Draw { params: p, .. } => {
                if p.deadline < U256::from(block.timestamp)
                    || !chain.historical_preparation()
                        && crate::credit::credit_periods(block.timestamp)
                            != crate::credit::credit_periods(self.constructed_at)
                {
                    return Err(
                        "Credit draw crossed deadline or UTC usage period; prepare again".into(),
                    );
                }
                map_preparation(p.payers.len(), |i| {
                    let payer = &p.payers[i];
                    fee_balance(chain, payer.payer, p.token, payer.amount, &block)
                })?;
                Ok(contract.call(&InvisiProtocol::creditDrawCall {
                    _0: proof,
                    p: p.clone(),
                    _2: self.deliveries.clone(),
                }))
            }
            CreditPlan::Revoke {
                owner,
                token,
                shard,
                slot,
                deadline,
                fee,
                signature,
            } => {
                if *deadline < block.timestamp
                    || signature.is_empty() && *owner != caller
                    || (*shard, *slot) >= chain.credit_allocation(*owner, *token, &block)?
                    || chain.credit_revoked(*owner, *token, *shard, *slot, &block)?
                {
                    return Err(
                        "Credit revocation expired, unallocated, already revoked or unauthorized caller".into(),
                    );
                }
                if !signature.is_empty()
                    && !chain.public_signature_valid(
                        *owner,
                        self.revocation_digest()?,
                        signature,
                        &block,
                    )?
                {
                    return Err("public revocation signature is no longer valid".into());
                }
                fee_balance(chain, *owner, *token, fee.amount, &block)?;
                Ok(contract.call(&InvisiProtocol::revokeCreditCall {
                    token: *token,
                    owner: *owner,
                    shard: *shard,
                    slot: *slot,
                    deadline: U256::from(*deadline),
                    feeRecipient: fee.recipient,
                    feeAmount: fee.amount,
                    signature: signature.clone().into(),
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credit::{CreditPolicy, CreditState, CreditUsage};
    fn keys(key: u8) -> ReceivingKeys {
        let viewing = crate::wallet::viewing_key(&[key; 32]).unwrap();
        let public = k256::SecretKey::from_slice(&*viewing).unwrap().public_key();
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        ReceivingKeys {
            viewing_public_key: public.to_encoded_point(true).as_bytes().try_into().unwrap(),
            clue_key: crate::fmd::derive_clue_key(
                &*crate::wallet::detection_key(&[key; 32]).unwrap(),
            )
            .unwrap(),
        }
    }
    fn state(chain: &dyn ChainState, owner: Address, spender: Address) -> CreditDeliveryState {
        CreditDeliveryState {
            note: CreditState {
                context: chain.context(),
                token_address: address_word(Address::repeat_byte(2)),
                spender_wallet_identity: address_word(spender),
                owner_wallet_identity: address_word(owner),
                revocation_shard: 1,
                revocation_slot: 0,
                nonce: U256::from(74),
                expiry: 2100000000,
                credit_shared_key: U256::from(75),
                policy: CreditPolicy::default(),
                usage: CreditUsage::default(),
                available_credit: U256::from(400),
                unlimited: false,
                payload: Vec::new(),
            },
            owner_receiving_keys: keys(1),
            spender_receiving_keys: keys(2),
        }
    }
    #[test]
    fn create_requires_strictly_future_expiry() {
        let (chain, wallet, _, _) = super::super::test_support::note_fixture();
        let mut state = state(&*chain, wallet.owner_address, Address::repeat_byte(7));
        state.note.expiry = chain.snapshot().unwrap().timestamp;
        let deadline = state.note.expiry;
        assert!(Invisi::new(chain)
            .prepare_create_credit_explicit(&wallet, state, deadline, Fee::default())
            .is_err());
    }
}

impl PreparedCredit {
    pub fn needs_authorization(&self) -> bool {
        !matches!(self.plan, CreditPlan::Revoke { .. })
    }
    pub fn deliveries(&self) -> &[abi::Delivery] {
        &self.deliveries
    }
    pub fn proving_request(&self) -> Result<prover::ProvingRequest> {
        let (_, name, _) = self.operation()?;
        prover::request(
            &name,
            "evm",
            self.private_inputs()?,
            self.public_inputs()?.into_iter().map(field_word).collect(),
        )
    }
    pub fn approval_requirements(&self) -> Vec<CreditApprovalRequirement> {
        match &self.plan {
            CreditPlan::Create { params, .. } => {
                if params.feeAmount == U256::ZERO {
                    Vec::new()
                } else {
                    vec![CreditApprovalRequirement {
                        token: params.token,
                        payer: params.owner,
                        amount: params.feeAmount,
                    }]
                }
            }
            CreditPlan::Update { params, .. } => {
                if params.feeAmount == U256::ZERO {
                    Vec::new()
                } else {
                    vec![CreditApprovalRequirement {
                        token: params.token,
                        payer: params.owner,
                        amount: params.feeAmount,
                    }]
                }
            }
            CreditPlan::Draw { params, .. } => params
                .payers
                .iter()
                .map(|payer| CreditApprovalRequirement {
                    token: params.token,
                    payer: payer.payer,
                    amount: payer.amount,
                })
                .collect(),
            CreditPlan::Revoke {
                owner, token, fee, ..
            } => {
                if fee.amount == U256::ZERO {
                    Vec::new()
                } else {
                    vec![CreditApprovalRequirement {
                        token: *token,
                        payer: *owner,
                        amount: fee.amount,
                    }]
                }
            }
        }
    }
    pub fn export_revocation_signing_request(&self) -> Result<EvmSigningRequest> {
        Ok(EvmSigningRequest {
            typed_data: self.export_revocation_authorization()?,
            digest: self.revocation_digest()?,
        })
    }
    pub fn export_revocation_authorization(&self) -> Result<Value> {
        let CreditPlan::Revoke {
            owner,
            token,
            shard,
            slot,
            deadline,
            fee,
            ..
        } = &self.plan
        else {
            return Err("public revocation operation required".into());
        };
        Ok(
            json!({"domain":{"name":"InvisibleProtocol","version":"1","chainId":self.context.chain_id.to_string(),"verifyingContract":hex(&self.context.protocol_address.to_be_bytes::<32>()[12..])},"primaryType":"RevokeCredit","types":{"RevokeCredit":[{"name":"token","type":"address"},{"name":"owner","type":"address"},{"name":"shard","type":"uint64"},{"name":"slot","type":"uint16"},{"name":"deadline","type":"uint256"},{"name":"feeRecipient","type":"address"},{"name":"feeAmount","type":"uint256"}]},"message":{"token":hex(token.as_slice()),"owner":hex(owner.as_slice()),"shard":shard.to_string(),"slot":slot.to_string(),"deadline":deadline.to_string(),"feeRecipient":hex(fee.recipient.as_slice()),"feeAmount":fee.amount.to_string()}}),
        )
    }
    pub fn revocation_digest(&self) -> Result<B256> {
        let CreditPlan::Revoke {
            owner,
            token,
            shard,
            slot,
            deadline,
            fee,
            ..
        } = &self.plan
        else {
            return Err("public revocation operation required".into());
        };
        let domain=keccak256((keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),keccak256("InvisibleProtocol"),keccak256("1"),U256::from(self.context.chain_id),word_address(self.context.protocol_address)?).abi_encode());
        let structure=keccak256((keccak256("RevokeCredit(address token,address owner,uint64 shard,uint16 slot,uint256 deadline,address feeRecipient,uint256 feeAmount)"),*token,*owner,*shard,*slot,U256::from(*deadline),fee.recipient,fee.amount).abi_encode());
        let mut bytes = vec![0x19, 0x01];
        bytes.extend_from_slice(domain.as_slice());
        bytes.extend_from_slice(structure.as_slice());
        Ok(keccak256(bytes))
    }
    pub fn with_revocation_signature(
        mut self,
        chain: &dyn ChainState,
        signature: Vec<u8>,
    ) -> Result<Self> {
        if !matches!(self.phase, Phase::Prepared | Phase::Authorized)
            || signature.is_empty()
            || signature.len() > 4096
        {
            return Err("invalid revocation authorization state or signature length".into());
        }
        let block = chain.snapshot()?;
        if chain.context() != self.context {
            return Err("revocation authorization deployment mismatch".into());
        }
        chain.canonical(&self.anchor)?;
        let CreditPlan::Revoke {
            owner, deadline, ..
        } = &self.plan
        else {
            return Err("public revocation operation required".into());
        };
        if *deadline < block.timestamp
            || !chain.public_signature_valid(
                *owner,
                self.revocation_digest()?,
                &signature,
                &block,
            )?
        {
            return Err("invalid public revocation signature".into());
        }
        let CreditPlan::Revoke {
            signature: stored, ..
        } = &mut self.plan
        else {
            unreachable!()
        };
        *stored = signature;
        self.phase = Phase::Authorized;
        chain.canonical(&block)?;
        Ok(self)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreditApprovalRequirement {
    pub token: Address,
    pub payer: Address,
    pub amount: U256,
}

#[cfg(test)]
mod lifecycle_tests {
    #[test]
    fn request_create_allocates_state_and_preserves_typed_recipient_failures() {
        use super::*;
        let chain = chain();
        let owner = wallet(1);
        let spender = wallet(2);
        let initial = initial(chain.as_ref());
        let request = CreateCreditRequest {
            token: word_address(initial.note.token_address).unwrap(),
            spender: spender.address().unwrap(),
            policy: initial.note.policy.clone(),
            available_credit: initial.note.available_credit,
            unlimited: false,
            expiry: initial.note.expiry,
            payload: vec![7],
            deadline: 2000000100,
            fee: Fee::default(),
        };
        let invisi = Invisi::new(chain);
        let prepared = invisi
            .prepare_create_credit(&owner, request.clone(), None)
            .unwrap();
        let state = prepared.successor_states()[0];
        assert_eq!(
            state.note.spender_wallet_identity,
            address_word(spender.owner_address())
        );
        assert_eq!(state.note.payload, vec![7]);
        assert_ne!(state.note.credit_shared_key, U256::ZERO);
        let mut invalid = request.clone();
        invalid.spender = "broken".into();
        assert_eq!(
            invisi
                .prepare_create_credit(&owner, invalid, None)
                .unwrap_err()
                .code,
            InvisiErrorCode::InvalidRecipient
        );
        let mut unregistered = request;
        unregistered.spender = format!("{}", spender.owner_address());
        assert_eq!(
            invisi
                .prepare_create_credit(&owner, unregistered, None)
                .unwrap_err()
                .code,
            InvisiErrorCode::MissingCapability
        );
    }
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use std::sync::Mutex;
    #[test]
    fn repeated_quotes_retain_the_original_credit_read_set() {
        let chain = chain();
        let mut prepared = Invisi::new(chain.clone())
            .prepare_create_credit_explicit(
                &wallet(1),
                initial(chain.as_ref()),
                2000000100,
                Fee::default(),
            )
            .unwrap();
        let original = prepared.preparation_reads.clone().unwrap();
        for _ in 0..2 {
            prepared = prepared
                .quote_for_broadcaster(
                    chain.clone(),
                    Arc::new(CreditRelay {
                        fees: 0.into(),
                        submits: 0.into(),
                    }),
                    &BroadcasterOptions {
                        max_fee_amount: Some(U256::from(100)),
                        ..Default::default()
                    },
                )
                .unwrap();
            assert!(
                Arc::ptr_eq(&original, prepared.preparation_reads.as_ref().unwrap()),
                "quote replaced the operation read set"
            );
        }
    }
    #[test]
    fn credit_highlevel_relay_preserves_original_on_failure() {
        let chain = chain();
        let invisi = Invisi::new(chain.clone());
        let prepared = invisi
            .prepare_create_credit_explicit(
                &wallet(1),
                initial(chain.as_ref()),
                2000000100,
                Fee::default(),
            )
            .unwrap();
        assert!(prepared
            .quote_for_broadcaster(
                chain,
                std::sync::Arc::new(RejectedRelay),
                &BroadcasterOptions {
                    max_fee_amount: Some(U256::from(100)),
                    ..Default::default()
                }
            )
            .is_err());
        assert_eq!(prepared.phase(), Phase::Prepared);
        assert!(prepared.broadcaster_state().is_none());
    }
    struct RejectedRelay;
    impl PreparedBroadcaster for RejectedRelay {
        fn configuration(&self) -> invisi_sdk_rpc::broadcaster::Configuration {
            invisi_sdk_rpc::broadcaster::Configuration {
                endpoint: "https://relay.example".into(),
                quote_signer: Address::repeat_byte(3),
                fee_recipient: Address::repeat_byte(4),
            }
        }
        fn submission_requirements(
            &self,
            q: &invisi_sdk_rpc::broadcaster::VerifiedQuote,
        ) -> Result<bool> {
            Ok(q.signed().provenance_required == Some(true))
        }
        fn provenance_mode(&self) -> Option<()> {
            None
        }
        fn fee(&self, _: Address, _: Option<&[u8]>) -> Result<invisi_sdk_rpc::broadcaster::Fee> {
            Err("unsupported token".into())
        }
        fn quote(
            &self,
            _: &[u8],
            _: u64,
            _: Address,
            _: u64,
            _: &[crate::provenance::ProofSidecar],
        ) -> Result<invisi_sdk_rpc::broadcaster::VerifiedQuote> {
            panic!("must not quote unsupported token")
        }
        fn submit(
            &self,
            _: &[u8],
            _: &invisi_sdk_rpc::broadcaster::VerifiedQuote,
            _: &[crate::provenance::ProofSidecar],
        ) -> Result<invisi_sdk_rpc::broadcaster::Status> {
            panic!("no submit")
        }
    }
    #[test]
    fn credit_relay_converges_before_consent_and_rebuilds_draw_note() {
        let chain = chain();
        let invisi = Invisi::new(chain.clone());
        let owner = wallet(1);
        let spender = wallet(2);
        let recipient = wallet(91);
        let state = initial(chain.as_ref());
        let member = |state: CreditDeliveryState| CreditInput {
            payload: None,
            root: merkle_root(state.note.commitment().unwrap(), 0, &[U256::ZERO; 16]).unwrap(),
            delivery: state,
            tree_id: 1,
            leaf_index: 0,
            path: [U256::ZERO; 16],
            debit: U256::from(7),
        };
        let plans = [
            invisi
                .prepare_create_credit_explicit(&owner, state.clone(), 2000000100, Fee::default())
                .unwrap(),
            invisi
                .prepare_update_credit_explicit(
                    &owner,
                    member(state.clone()),
                    crate::credit::CreditUpdateChanges {
                        increase_available_credit: U256::from(10),
                        ..Default::default()
                    },
                    2000000100,
                    Fee::default(),
                )
                .unwrap(),
            invisi
                .prepare_draw_credit_explicit(
                    &spender,
                    vec![member(state)],
                    &recipient,
                    2000000100,
                    Fee::default(),
                    b"local-payload".to_vec(),
                )
                .unwrap(),
        ];
        for original in plans {
            let relay = Arc::new(CreditRelay {
                fees: std::sync::atomic::AtomicUsize::new(0),
                submits: std::sync::atomic::AtomicUsize::new(0),
            });
            let old = original.export_wallet_request("old-consent").unwrap();
            let signing_secret = secret(if matches!(original.plan, CreditPlan::Draw { .. }) {
                2
            } else {
                1
            });
            let response: WalletResponse = serde_json::from_value(
                crate::wallet::execute(&signing_secret, &old.as_value()).unwrap(),
            )
            .unwrap();
            let before_quote = journal::ManagedPrepared::Credit(original.clone())
                .snapshot()
                .unwrap();
            let restored = before_quote
                .restore(original.wallet().unwrap(), None)
                .unwrap();
            let restarted = match restored {
                journal::ManagedPrepared::Credit(v) => v,
                _ => panic!("Credit"),
            };
            assert!(restarted.reprice.is_some());
            let prepared = restarted
                .quote_for_broadcaster(
                    chain.clone(),
                    relay.clone(),
                    &BroadcasterOptions {
                        max_fee_amount: Some(U256::from(100)),
                        ..Default::default()
                    },
                )
                .unwrap();
            assert!(original.broadcaster_state().is_none());
            assert_eq!(relay.fees.load(std::sync::atomic::Ordering::SeqCst), 3);
            assert!(prepared
                .clone()
                .with_wallet_response(&old, &response)
                .is_err());
            let saved = prepared.broadcaster_state().unwrap();
            assert!(saved.sidecars.is_empty());
            assert_eq!(saved.quote.quote.fee_amount, "2");
            if let (
                CreditPlan::Draw {
                    params: old_params,
                    output: old_output,
                    successors: old_successors,
                    ..
                },
                CreditPlan::Draw {
                    params,
                    output,
                    successors,
                    ..
                },
            ) = (&original.plan, &prepared.plan)
            {
                assert_eq!(params.totalAmount, old_params.totalAmount);
                assert_eq!(
                    params.payers.iter().map(|p| p.amount).collect::<Vec<_>>(),
                    old_params
                        .payers
                        .iter()
                        .map(|p| p.amount)
                        .collect::<Vec<_>>()
                );
                assert_eq!(output.amount(), U256::from(5));
                assert_ne!(output.commitment(), old_output.commitment());
                assert_ne!(
                    output.delivery().ciphertext,
                    old_output.delivery().ciphertext
                );
                assert_eq!(
                    successors[0].note.available_credit,
                    old_successors[0].note.available_credit
                );
                let context = DeliveryContext {
                    context: chain.context,
                    token_address: address_word(prepared.token),
                    output_commitment: U256::from_be_bytes(output.commitment().0),
                };
                let key = crate::wallet::viewing_key(&secret(91)).unwrap();
                let decoded = crate::delivery::decrypt_note(
                    &*key,
                    &output.delivery().ciphertext,
                    &context,
                    address_word(recipient.owner_address),
                )
                .unwrap();
                assert_eq!(decoded.amount, U256::from(5));
                assert_eq!(decoded.payload, b"local-payload");
            }
            let snapshot = journal::ManagedPrepared::Credit(prepared.clone())
                .snapshot()
                .unwrap();
            let bytes = serde_json::to_vec(&snapshot).unwrap();
            let snapshot: journal::PreparedSnapshot = serde_json::from_slice(&bytes).unwrap();
            let restored = snapshot.restore(prepared.wallet().unwrap(), None).unwrap();
            match restored {
                journal::ManagedPrepared::Credit(v) => {
                    assert_eq!(
                        v.broadcaster_state().unwrap().intent_hash,
                        saved.intent_hash
                    );
                    assert!(v.reprice.is_none());
                }
                _ => panic!("Credit"),
            }
            let request = prepared.export_wallet_request("final-consent").unwrap();
            let response: WalletResponse = serde_json::from_value(
                crate::wallet::execute(&signing_secret, &request.as_value()).unwrap(),
            )
            .unwrap();
            // Synthetic main proof bytes exercise orchestration only; no cryptographic proof claim.
            let proved = prepared
                .with_wallet_response(&request, &response)
                .unwrap()
                .prove(&SyntheticCreditBackend)
                .unwrap();
            let snapshot = journal::ManagedPrepared::Credit(proved.clone())
                .snapshot()
                .unwrap();
            let restored = snapshot
                .restore(proved.wallet().unwrap(), Some(&SyntheticCreditBackend))
                .unwrap();
            match restored {
                journal::ManagedPrepared::Credit(mut v) => {
                    v.submit_broadcaster(chain.as_ref(), relay.as_ref())
                        .unwrap();
                    let saved = journal::ManagedPrepared::Credit(v.clone())
                        .snapshot()
                        .unwrap();
                    let exact = saved.export_broadcaster_submission().unwrap();
                    assert_eq!(exact.data, v.broadcaster_state().unwrap().submitted_data);
                    assert!(exact.member_proof.is_none());
                    v.broadcaster.as_mut().unwrap().submission_id = None;
                    let saved = journal::ManagedPrepared::Credit(v).snapshot().unwrap();
                    let mut restored = match saved.restore(proved.wallet().unwrap(), None).unwrap()
                    {
                        journal::ManagedPrepared::Credit(v) => v,
                        _ => panic!("Credit"),
                    };
                    assert_eq!(restored.phase(), Phase::Prepared);
                    restored
                        .submit_broadcaster(chain.as_ref(), relay.as_ref())
                        .unwrap();
                    assert_eq!(
                        restored.broadcaster_state().unwrap().submitted_data,
                        exact.data
                    );
                }
                _ => panic!("Credit"),
            }
            assert_eq!(relay.submits.load(std::sync::atomic::Ordering::SeqCst), 2);
        }
    }
    #[test]
    fn prepared_credit_estimates_are_local_before_proof_and_stable() {
        for label in ["create_credit", "credit_draw_slots1", "credit_update"] {
            let (_, p) = prepared(label);
            assert!(p.proof().is_none());
            let estimate = p.estimate_gas().unwrap();
            assert!(estimate.available());
            assert_eq!(
                serde_json::to_value(&estimate).unwrap()["source"],
                "benchmark"
            );
            let mut nonstandard = p.clone();
            nonstandard.deliveries[0].clue.clear();
            let unsupported = nonstandard.estimate_gas().unwrap();
            assert_eq!(unsupported, estimate);
            nonstandard.deliveries[0].clue = vec![1; 78].into();
            assert_eq!(
                serde_json::to_value(nonstandard.estimate_gas().unwrap()).unwrap()["statistic"],
                "estimate"
            );
            let proved = p.prove(&SyntheticCreditBackend).unwrap();
            assert_eq!(estimate, proved.estimate_gas().unwrap());
        }
    }
    #[test]
    fn cached_draw_uses_construction_period_and_restores_it_without_changing_anchor() {
        let chain = chain();
        chain.block.lock().unwrap().timestamp = 1;
        let state = initial(chain.as_ref());
        let input = CreditInput {
            payload: None,
            root: merkle_root(state.note.commitment().unwrap(), 0, &[U256::ZERO; 16]).unwrap(),
            delivery: state,
            tree_id: 1,
            leaf_index: 0,
            path: [U256::ZERO; 16],
            debit: U256::from(5),
        };
        let block = chain.snapshot().unwrap();
        let mut facts = PreparationSnapshot::new(chain.context(), block.clone());
        facts.roots.push((1, field_word(input.root), true));
        facts
            .spent
            .push((field_word(input.delivery.note.nullifier().unwrap()), false));
        facts.revocations.push((
            wallet(1).owner_address,
            word_address(input.delivery.note.token_address).unwrap(),
            1,
            0,
            false,
        ));
        let now = facts.construction_timestamp(&block);
        let mut prepared = Invisi::new(Arc::new(facts))
            .prepare_draw_credit_explicit(
                &wallet(2),
                vec![input],
                &wallet(91),
                now + 172800,
                Fee::default(),
                vec![],
            )
            .unwrap();
        assert_eq!(prepared.anchor(), &block);
        assert_eq!(
            crate::credit::credit_periods(prepared.constructed_at),
            crate::credit::credit_periods(now)
        );
        let request = prepared.export_wallet_request("period").unwrap();
        let response: WalletResponse = serde_json::from_value(
            crate::wallet::execute(&secret(2), &request.as_value()).unwrap(),
        )
        .unwrap();
        prepared = prepared
            .with_wallet_response(&request, &response)
            .unwrap()
            .prove(&SyntheticCreditBackend)
            .unwrap();
        let snapshot = journal::ManagedPrepared::Credit(prepared)
            .snapshot()
            .unwrap();
        let restored = snapshot
            .restore(&wallet(2), Some(&SyntheticCreditBackend))
            .unwrap();
        let journal::ManagedPrepared::Credit(restored) = restored else {
            panic!("Credit operation required");
        };
        assert_eq!(restored.anchor(), &block);
        assert_eq!(
            crate::credit::credit_periods(restored.constructed_at),
            crate::credit::credit_periods(now)
        );
        chain.block.lock().unwrap().timestamp = now + 86400;
        // The fixture chain pins only the current block, so preserve the original anchor check separately.
        struct PeriodChain<'a> {
            live: &'a dyn ChainState,
            anchor: CanonicalBlock,
        }
        impl ChainState for PeriodChain<'_> {
            fn context(&self) -> ProtocolContext {
                self.live.context()
            }
            fn snapshot(&self) -> Result<CanonicalBlock> {
                self.live.snapshot()
            }
            fn canonical(&self, b: &CanonicalBlock) -> Result<()> {
                if b == &self.anchor {
                    Ok(())
                } else {
                    self.live.canonical(b)
                }
            }
            fn known_root(&self, t: u64, r: B256, b: &CanonicalBlock) -> Result<bool> {
                self.live.known_root(t, r, b)
            }
            fn nullifier_spent(&self, n: B256, b: &CanonicalBlock) -> Result<bool> {
                self.live.nullifier_spent(n, b)
            }
            fn credit_revoked(
                &self,
                o: Address,
                t: Address,
                s: u64,
                l: u16,
                b: &CanonicalBlock,
            ) -> Result<bool> {
                self.live.credit_revoked(o, t, s, l, b)
            }
            fn token_balance_allowance(
                &self,
                o: Address,
                t: Address,
                b: &CanonicalBlock,
            ) -> Result<(U256, U256)> {
                self.live.token_balance_allowance(o, t, b)
            }
            fn credit_allocation(
                &self,
                o: Address,
                t: Address,
                b: &CanonicalBlock,
            ) -> Result<(u64, u16)> {
                self.live.credit_allocation(o, t, b)
            }
        }
        let live = PeriodChain {
            live: chain.as_ref(),
            anchor: block,
        };
        assert!(restored
            .validate_submission(&live, Address::ZERO)
            .unwrap_err()
            .contains("UTC usage period"));
    }
    struct SyntheticCreditBackend;
    impl Prover for SyntheticCreditBackend {
        fn prove(&self, r: &prover::ProvingRequest) -> Result<ProofBundle> {
            let s = &r.statement;
            let proof = vec![0; 32];
            Ok(ProofBundle {
                format_version: 1,
                circuit_name: s.circuit_name.clone(),
                target: s.target.clone(),
                bb_version: "6.0.0".into(),
                artifact_sha256: s.artifact_sha256.clone(),
                vk_sha256: s.vk_sha256.clone(),
                proof_sha256: prover::sha256(&proof),
                proof,
                public_inputs: s.expected_public_inputs.clone(),
            })
        }
        fn verify(&self, _: &ProofBundle, _: &prover::ProofStatement) -> Result<bool> {
            Ok(true)
        }
    }
    pub(super) struct CreditRelay {
        pub(super) fees: std::sync::atomic::AtomicUsize,
        pub(super) submits: std::sync::atomic::AtomicUsize,
    }
    impl PreparedBroadcaster for CreditRelay {
        fn configuration(&self) -> invisi_sdk_rpc::broadcaster::Configuration {
            let key = k256::ecdsa::SigningKey::from_slice(&secret(7)).unwrap();
            let public = key.verifying_key().to_encoded_point(false);
            invisi_sdk_rpc::broadcaster::Configuration {
                endpoint: "https://relay.example".into(),
                quote_signer: Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]),
                fee_recipient: Address::repeat_byte(4),
            }
        }
        fn submission_requirements(
            &self,
            q: &invisi_sdk_rpc::broadcaster::VerifiedQuote,
        ) -> Result<bool> {
            Ok(q.signed().provenance_required == Some(true))
        }
        fn provenance_mode(&self) -> Option<()> {
            Some(())
        }
        fn fee(&self, _: Address, data: Option<&[u8]>) -> Result<invisi_sdk_rpc::broadcaster::Fee> {
            assert!(data.is_some(), "final Credit calldata required");
            let n = self.fees.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(invisi_sdk_rpc::broadcaster::Fee {
                fee_recipient: self.configuration().fee_recipient,
                fee_amount: if n % 2 == 0 { "1" } else { "2" }.into(),
                max_gas: "100000".into(),
            })
        }
        fn quote(
            &self,
            data: &[u8],
            chain_id: u64,
            protocol: Address,
            now: u64,
            sidecars: &[crate::provenance::ProofSidecar],
        ) -> Result<invisi_sdk_rpc::broadcaster::VerifiedQuote> {
            use invisi_sdk_rpc::broadcaster::*;
            assert!(sidecars.is_empty());
            let i = decode_intent(data).unwrap();
            let trust = Trust {
                chain_id,
                protocol,
                signer: self.configuration().quote_signer,
            };
            let policy = self.provenance_mode().unwrap();
            let quote = Quote {
                schedule: None,
                execution: invisi_sdk_rpc::broadcaster::Execution::Direct,
                token: i.token,
                fee_recipient: i.fee_recipient,
                fee_amount: i.fee_amount.to_string(),
                deadline: i.deadline.to_string(),
                max_gas: "100000".into(),
                request_hash: B256::from(crate::provenance::provenance_intent_hash(
                    request_hash(data).unwrap().0,
                )),
            };
            let (sig, r) = k256::ecdsa::SigningKey::from_slice(&secret(7))
                .unwrap()
                .sign_prehash_recoverable(quote_digest(&quote, &trust).unwrap().as_slice())
                .unwrap();
            let mut bytes = sig.to_bytes().to_vec();
            bytes.push(r.to_byte());
            VerifiedQuote::authenticate(
                SignedQuote {
                    quote,
                    signature: hex(&bytes),

                    request_hash_format: Some(REQUEST_HASH_FORMAT.into()),
                    provenance_required: Some(true),
                },
                trust,
                data,
                now,
                Some(policy),
            )
            .map_err(|e| e.to_string())
        }
        fn submit(
            &self,
            data: &[u8],
            quote: &invisi_sdk_rpc::broadcaster::VerifiedQuote,
            sidecars: &[crate::provenance::ProofSidecar],
        ) -> Result<invisi_sdk_rpc::broadcaster::Status> {
            assert!(sidecars.is_empty());
            invisi_sdk_rpc::broadcaster::verify_quote_for_provenance(
                quote.signed(),
                quote.trust(),
                data,
                0,
                self.provenance_mode(),
            )
            .map_err(|e| e.to_string())?;
            self.submits
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(invisi_sdk_rpc::broadcaster::Status {
                confirmation: None,
                id: "server-owned".into(),
                state: invisi_sdk_rpc::broadcaster::StatusState::Pending,
                transaction_hash: None,
            })
        }
    }
    fn secret(scalar: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[31] = scalar;
        key
    }
    fn wallet(scalar: u8) -> Wallet {
        let key = secret(scalar);
        let public = k256::SecretKey::from_slice(&key)
            .unwrap()
            .public_key()
            .to_encoded_point(false);
        let owner = Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]);
        let viewing = crate::wallet::viewing_key(&key).unwrap();
        let public = k256::SecretKey::from_slice(&*viewing)
            .unwrap()
            .public_key()
            .to_encoded_point(true);
        Wallet::from_keys(
            owner,
            ReceivingKeys {
                viewing_public_key: public.as_bytes().try_into().unwrap(),
                clue_key: crate::fmd::derive_clue_key(
                    &*crate::wallet::detection_key(&key).unwrap(),
                )
                .unwrap(),
            },
        )
        .unwrap()
    }
    fn chain() -> Arc<super::super::test_support::FixtureChain> {
        Arc::new(super::super::test_support::FixtureChain {
            context: ProtocolContext {
                chain_id: 1,
                protocol_address: U256::from_be_slice(&[0x11; 20]),
            },
            block: Mutex::new(CanonicalBlock {
                number: 10,
                hash: B256::repeat_byte(1),
                parent_hash: B256::ZERO,
                timestamp: 2000000000,
            }),
            spent: Mutex::new(BTreeSet::new()),
        })
    }
    fn initial(chain: &dyn ChainState) -> CreditDeliveryState {
        CreditDeliveryState {
            note: crate::credit::CreditState {
                context: chain.context(),
                token_address: U256::from_be_slice(&[0x22; 20]),
                spender_wallet_identity: address_word(wallet(2).owner_address),
                owner_wallet_identity: address_word(wallet(1).owner_address),
                revocation_shard: 1,
                revocation_slot: 0,
                nonce: U256::from(74),
                expiry: 2100000000,
                credit_shared_key: U256::from(75),
                policy: crate::credit::CreditPolicy::default(),
                usage: crate::credit::CreditUsage::default(),
                available_credit: U256::from(400),
                unlimited: false,
                payload: Vec::new(),
            },
            owner_receiving_keys: wallet(1).receiving_keys,
            spender_receiving_keys: wallet(2).receiving_keys,
        }
    }
    fn fixture(label: &str) -> Value {
        let all: Value = serde_json::from_str(include_str!(
            "../../assets/prover/testdata/current-proving.json"
        ))
        .unwrap();
        all["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["label"] == label)
            .unwrap()
            .clone()
    }
    fn delivery_fixture(label: &str) -> Vec<abi::Delivery> {
        let all: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/credit-highlevel.json"))
                .unwrap();
        all[label]["deliveries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| abi::Delivery {
                ciphertext: hex_bytes(d["ciphertext"].as_str().unwrap(), None)
                    .unwrap()
                    .into(),
                clue: hex_bytes(d["clue"].as_str().unwrap(), Some(68))
                    .unwrap()
                    .into(),
            })
            .collect()
    }
    fn input(state: CreditDeliveryState, label: &str) -> CreditInput {
        let f = fixture(label);
        let w = &f["witness"];
        let (path, index, root) = if label == "credit_update" {
            (&w["merkle_path"], &w["leaf_index"], &w["merkle_root"])
        } else {
            (&w["merkle_paths"][0], &w["leaf_indices"][0], &w["roots"][0])
        };
        CreditInput {
            payload: None,
            delivery: state,
            tree_id: 1,
            leaf_index: decimal(index).unwrap().to::<u16>(),
            path: path
                .as_array()
                .unwrap()
                .iter()
                .map(|v| decimal(v).unwrap())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            root: decimal(root).unwrap(),
            debit: U256::from(7),
        }
    }
    fn prepared(
        label: &str,
    ) -> (
        Arc<super::super::test_support::FixtureChain>,
        PreparedCredit,
    ) {
        let chain = chain();
        let invisi = Invisi::new(chain.clone());
        let owner = wallet(1);
        let spender = wallet(2);
        let fee = Fee {
            recipient: Address::repeat_byte(0x44),
            amount: U256::from(1),
        };
        let deadline = 2000000100;
        let state = initial(&*chain);
        let mut prepared = match label {
            "create_credit" => invisi
                .prepare_create_credit_explicit(&owner, state, deadline, fee)
                .unwrap(),
            "credit_draw_slots1" => {
                let mut p = invisi
                    .prepare_draw_credit_explicit(
                        &spender,
                        vec![input(state, label)],
                        &wallet(91),
                        deadline,
                        fee,
                        Vec::new(),
                    )
                    .unwrap();
                let output = NoteOutput::from_note(
                    Note {
                        context: chain.context(),
                        token_address: U256::from_be_slice(&[0x22; 20]),
                        owner_address: address_word(wallet(91).owner_address),
                        amount: U256::from(6),
                        nonce: U256::from(8675309),
                        payload: Vec::new(),
                    },
                    Some(wallet(91).receiving_keys()),
                )
                .unwrap();
                if let CreditPlan::Draw {
                    params,
                    output: stored,
                    ..
                } = &mut p.plan
                {
                    params.noteCommitment = output.commitment;
                    *stored = output;
                }
                p
            }
            "credit_update" => {
                let drawn = model(crate::credit::derive_credit_state(
                    &state.note,
                    U256::from(7),
                    2000000000,
                ))
                .unwrap();
                let state = CreditDeliveryState {
                    note: drawn.state,
                    ..state
                };
                let changes = crate::credit::CreditUpdateChanges {
                    single_limit: Some(U256::from(10)),
                    daily_limit: Some(U256::from(40)),
                    monthly_limit: Some(U256::from(60)),
                    expiry: Some(2050000000),
                    increase_available_credit: U256::from(100),
                    ..Default::default()
                };
                invisi
                    .prepare_update_credit_explicit(
                        &owner,
                        input(state, label),
                        changes,
                        deadline,
                        fee,
                    )
                    .unwrap()
            }
            _ => panic!("unsupported test operation"),
        };
        // Freeze independently generated delivery bytes so public statement parity is deterministic.
        prepared.deliveries = delivery_fixture(label);
        let expected: Vec<B256> =
            serde_json::from_value(fixture(label)["publicInputs"].clone()).unwrap();
        assert_eq!(
            prepared
                .public_inputs()
                .unwrap()
                .into_iter()
                .map(field_word)
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(prepared.phase(), Phase::Prepared);
        let unsigned_estimate = prepared.estimate_gas().unwrap();
        assert!(prepared.proof().is_none());
        let request = prepared.export_wallet_authorization().unwrap();
        let scalar = if label == "credit_draw_slots1" { 2 } else { 1 };
        let key = k256::ecdsa::SigningKey::from_slice(&secret(scalar)).unwrap();
        let (signature, id) = key
            .sign_prehash_recoverable(request.digest.as_slice())
            .unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(id.to_byte() + 27);
        let mut wrong = request.clone();
        wrong.digest = keccak256("different Credit intent");
        assert!(accept_wallet_signature(prepared.owner_address, &wrong, &bytes).is_err());
        let authorized = prepared.with_wallet_signature(&bytes).unwrap();
        assert_eq!(unsigned_estimate, authorized.estimate_gas().unwrap());
        (chain, authorized)
    }
    fn prepared_live(
        label: &str,
    ) -> (
        Arc<super::super::test_support::FixtureChain>,
        PreparedCredit,
    ) {
        let chain = chain();
        let invisi = Invisi::new(chain.clone());
        let state = initial(&*chain);
        let fee = Fee {
            recipient: Address::repeat_byte(0x44),
            amount: U256::from(1),
        };
        let p = match label {
            "create_credit" => invisi
                .prepare_create_credit_explicit(&wallet(1), state, 2000000100, fee)
                .unwrap(),
            "credit_draw_slots1" => invisi
                .prepare_draw_credit_explicit(
                    &wallet(2),
                    vec![input(state, label)],
                    &wallet(91),
                    2000000100,
                    fee,
                    Vec::new(),
                )
                .unwrap(),
            "credit_update" => {
                let next =
                    crate::credit::derive_credit_state(&state.note, U256::from(7), 2000000000)
                        .unwrap();
                let state = CreditDeliveryState {
                    note: next.state,
                    ..state
                };
                invisi
                    .prepare_update_credit_explicit(
                        &wallet(1),
                        input(state, label),
                        crate::credit::CreditUpdateChanges {
                            increase_available_credit: U256::from(100),
                            single_limit: Some(U256::from(10)),
                            daily_limit: Some(U256::from(40)),
                            monthly_limit: Some(U256::from(60)),
                            expiry: Some(2050000000),
                            ..Default::default()
                        },
                        2000000100,
                        fee,
                    )
                    .unwrap()
            }
            _ => unreachable!(),
        };
        let q = p.export_wallet_request(label).unwrap();
        let r: WalletResponse = serde_json::from_value(
            crate::wallet::execute(
                &secret(if label == "credit_draw_slots1" { 2 } else { 1 }),
                &q.as_value(),
            )
            .unwrap(),
        )
        .unwrap();
        (chain, p.with_wallet_response(&q, &r).unwrap())
    }
    #[test]
    fn constructed_create_draw_and_update_witnesses_match_independent_protocol() {
        for label in ["create_credit", "credit_draw_slots1", "credit_update"] {
            let (_, p) = prepared(label);
            let reference = serde_json::to_value(p.estimate_gas().unwrap()).unwrap();
            assert_eq!(reference["available"], true);
            assert_eq!(reference["source"], "benchmark");
            let request = p.proving_request().unwrap();
            request
                .witness
                .with_inputs(|value| {
                    assert_eq!(value, &fixture(label)["witness"]);
                    Ok(())
                })
                .unwrap();
        }
    }
    #[test]
    fn batched_draw_groups_distinct_payers_and_preserves_available_balances() {
        let chain = chain();
        let invisi = Invisi::new(chain.clone());
        let spender = wallet(2);
        let first = initial(&*chain);
        let mut second = first.clone();
        second.note.owner_wallet_identity = address_word(wallet(3).owner_address);
        second.owner_receiving_keys = wallet(3).receiving_keys;
        second.note.nonce = U256::from(76);
        let member = |state: CreditDeliveryState, tree_id, debit| CreditInput {
            payload: None,
            root: merkle_root(state.note.commitment().unwrap(), 0, &[U256::ZERO; 16]).unwrap(),
            delivery: state,
            tree_id,
            leaf_index: 0,
            path: [U256::ZERO; 16],
            debit: U256::from(debit),
        };
        let first = member(first, 1, 7u64);
        let second = member(second, 2, 8u64);
        let prepared = invisi
            .prepare_draw_credit_explicit(
                &spender,
                vec![second, first.clone()],
                &wallet(91),
                2000000100,
                Fee {
                    recipient: Address::repeat_byte(0x44),
                    amount: U256::from(1),
                },
                Vec::new(),
            )
            .unwrap();
        let CreditPlan::Draw {
            params,
            successors,
            output,
            ..
        } = &prepared.plan
        else {
            unreachable!()
        };
        assert_eq!(params.payers.len(), 2);
        assert!(params.payers[0].payer < params.payers[1].payer);
        assert_eq!(params.sources.len(), 2);
        assert_eq!(params.totalAmount, U256::from(15));
        assert_eq!(output.amount(), U256::from(14));
        assert_eq!(prepared.deliveries.len(), 5);
        assert_eq!(prepared.approval_requirements().len(), 2);
        for successor in successors {
            assert!(
                successor.note.available_credit == U256::from(393)
                    || successor.note.available_credit == U256::from(392)
            );
            assert!(!successor.note.unlimited);
        }
        assert!(invisi
            .prepare_draw_credit_explicit(
                &spender,
                vec![first.clone(), first],
                &wallet(91),
                2000000100,
                Fee::default(),
                Vec::new()
            )
            .is_err());
    }
    #[test]
    #[ignore = "requires explicit actual BB6, Noir executor and pinned circuit assets"]
    fn real_constructed_credit_witnesses_prove_and_verify() {
        use crate::prover::{DirectoryAssets, NativeProver, NoirCli};
        use std::{path::PathBuf, time::Duration};
        let backend = NativeProver {
            bb_binary: PathBuf::from(std::env::var_os("INVISI_BB").expect("explicit BB6 binary")),
            timeout: Duration::from_secs(600),
            threads: 4,
            assets: Arc::new(DirectoryAssets {
                directory: PathBuf::from(
                    std::env::var_os("INVISI_PROVER_ASSETS").expect("explicit circuit assets"),
                ),
            }),
            witness_executor: Arc::new(NoirCli {
                binary: PathBuf::from(
                    std::env::var_os("INVISI_NOIR_EXECUTE").expect("explicit real Noir executor"),
                ),
                timeout: Duration::from_secs(120),
            }),
        };
        for label in ["create_credit", "credit_draw_slots1", "credit_update"] {
            let (chain, p) = prepared_live(label);
            let prepared = p.prove(&backend).unwrap();
            let request = prover::statement(
                label,
                "evm",
                prepared
                    .public_inputs()
                    .unwrap()
                    .into_iter()
                    .map(field_word)
                    .collect(),
            )
            .unwrap();
            assert!(backend.verify(prepared.proof().unwrap(), &request).unwrap());
            let call = prepared.calldata(&*chain, prepared.owner_address).unwrap();
            assert_eq!(
                call.to,
                word_address(prepared.context.protocol_address).unwrap()
            );
            assert!(protocol::ProtocolContract::decode_call(&call.data).is_ok());
        }
    }
}

#[cfg(test)]
mod revocation_tests {
    use super::*;
    struct Chain(Arc<super::super::test_support::FixtureChain>);
    impl ChainState for Chain {
        fn context(&self) -> ProtocolContext {
            self.0.context()
        }
        fn snapshot(&self) -> Result<CanonicalBlock> {
            self.0.snapshot()
        }
        fn canonical(&self, b: &CanonicalBlock) -> Result<()> {
            self.0.canonical(b)
        }
        fn known_root(&self, t: u64, r: B256, b: &CanonicalBlock) -> Result<bool> {
            self.0.known_root(t, r, b)
        }
        fn nullifier_spent(&self, n: B256, b: &CanonicalBlock) -> Result<bool> {
            self.0.nullifier_spent(n, b)
        }
        fn credit_revoked(
            &self,
            o: Address,
            t: Address,
            s: u64,
            l: u16,
            b: &CanonicalBlock,
        ) -> Result<bool> {
            self.0.credit_revoked(o, t, s, l, b)
        }
        fn token_balance_allowance(
            &self,
            o: Address,
            t: Address,
            b: &CanonicalBlock,
        ) -> Result<(U256, U256)> {
            self.0.token_balance_allowance(o, t, b)
        }
        fn credit_allocation(
            &self,
            _: Address,
            _: Address,
            _: &CanonicalBlock,
        ) -> Result<(u64, u16)> {
            Ok((1, 1))
        }
    }
    #[test]
    fn highlevel_revocation_freezes_fee_before_evm_consent_and_survives_restore() {
        let (inner, _, _, _) = super::super::test_support::note_fixture();
        let chain = Arc::new(Chain(inner));
        let runtime = Invisi::new(chain.clone());
        let mut key = [0u8; 32];
        key[31] = 1;
        let signing = k256::ecdsa::SigningKey::from_slice(&key).unwrap();
        let public = signing.verifying_key().to_encoded_point(false);
        let owner = Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]);
        let original = runtime
            .prepare_revoke_credit_explicit(
                owner,
                Address::repeat_byte(2),
                1,
                0,
                2000000100,
                Fee::default(),
            )
            .unwrap();
        let relay = Arc::new(super::lifecycle_tests::CreditRelay {
            fees: std::sync::atomic::AtomicUsize::new(0),
            submits: std::sync::atomic::AtomicUsize::new(0),
        });
        let prepared = original
            .quote_for_broadcaster(
                chain.clone(),
                relay.clone(),
                &BroadcasterOptions {
                    max_fee_amount: Some(U256::from(100)),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(original.broadcaster_state().is_none());
        assert_ne!(
            original.revocation_digest().unwrap(),
            prepared.revocation_digest().unwrap()
        );
        let sign = |digest: B256| {
            let (s, r) = signing.sign_prehash_recoverable(digest.as_slice()).unwrap();
            let mut bytes = s.to_bytes().to_vec();
            bytes.push(r.to_byte() + 27);
            bytes
        };
        assert!(prepared
            .clone()
            .with_revocation_signature(chain.as_ref(), sign(original.revocation_digest().unwrap()))
            .is_err());
        let signature = sign(prepared.revocation_digest().unwrap());
        let approved = prepared
            .with_revocation_signature(chain.as_ref(), signature)
            .unwrap();
        let saved = journal::ManagedPrepared::Credit(approved)
            .snapshot()
            .unwrap();
        let restored = saved.restore_for_owner(owner, None).unwrap();
        match restored {
            journal::ManagedPrepared::Credit(mut v) => {
                v.submit_broadcaster(chain.as_ref(), relay.as_ref())
                    .unwrap();
                let saved = journal::ManagedPrepared::Credit(v.clone())
                    .snapshot()
                    .unwrap();
                let exact = saved.export_broadcaster_submission().unwrap();
                assert_eq!(exact.data, v.broadcaster_state().unwrap().submitted_data);
                v.broadcaster.as_mut().unwrap().submission_id = None;
                let saved = journal::ManagedPrepared::Credit(v).snapshot().unwrap();
                let mut restored = match saved.restore_for_owner(owner, None).unwrap() {
                    journal::ManagedPrepared::Credit(v) => v,
                    _ => panic!("Credit"),
                };
                restored
                    .submit_broadcaster(chain.as_ref(), relay.as_ref())
                    .unwrap();
                assert_eq!(
                    restored.broadcaster_state().unwrap().submitted_data,
                    exact.data
                );
            }
            _ => panic!("Credit"),
        }
        assert_eq!(relay.submits.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
    #[test]
    fn public_revocation_is_owner_direct_or_independently_verified_relay() {
        let (inner, wallet, _, _) = super::super::test_support::note_fixture();
        let chain = Arc::new(Chain(inner));
        let invisi = Invisi::new(chain.clone());
        let token = Address::repeat_byte(2);
        let owner = wallet.owner_address;
        let deadline = 2000000100;
        let direct = invisi
            .prepare_revoke_credit_explicit(owner, token, 1, 0, deadline, Fee::default())
            .unwrap();
        let estimate = direct.estimate_gas().unwrap();
        assert!(estimate.available());
        assert!(estimate.gas_units().unwrap() > U256::from(60000));
        assert!(!direct.needs_authorization());
        assert!(direct.calldata(&*chain, owner).is_ok());
        assert!(direct.calldata(&*chain, Address::repeat_byte(9)).is_err());
        let request = direct.export_revocation_authorization().unwrap();
        assert_eq!(request["primaryType"], "RevokeCredit");
        assert_eq!(request["message"]["owner"], hex(owner.as_slice()));
        let mut key = [0u8; 32];
        key[31] = 1;
        let signing = k256::ecdsa::SigningKey::from_slice(&key).unwrap();
        let public = signing.verifying_key().to_encoded_point(false);
        let actual_owner = Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]);
        let prepared = invisi
            .prepare_revoke_credit_explicit(actual_owner, token, 1, 0, deadline, Fee::default())
            .unwrap();
        let (signature, recovery) = signing
            .sign_prehash_recoverable(prepared.revocation_digest().unwrap().as_slice())
            .unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery.to_byte() + 27);
        let relay = prepared.with_revocation_signature(&*chain, bytes).unwrap();
        assert_eq!(relay.phase(), Phase::Authorized);
        let calldata = relay.calldata(&*chain, Address::repeat_byte(9)).unwrap();
        assert!(protocol::ProtocolContract::decode_call(&calldata.data).is_ok());
        let wrong = invisi
            .prepare_revoke_credit_explicit(
                actual_owner,
                token,
                1,
                0,
                deadline,
                Fee {
                    recipient: Address::repeat_byte(3),
                    amount: U256::from(1),
                },
            )
            .unwrap();
        let CreditPlan::Revoke { signature, .. } = &relay.plan else {
            unreachable!()
        };
        assert!(wrong
            .with_revocation_signature(&*chain, signature.clone())
            .is_err());
    }
}

impl PreparedCredit {
    /// Look up a local measured workload before authorization or proving.
    /// Returned medians are conditional benchmarks, not gas limits or monetary fees.
    pub fn estimate_gas(&self) -> Result<crate::gas::GasEstimate> {
        let (mut query, fee, draw) = match &self.plan {
            CreditPlan::Create { params, .. } => (
                json!({"kind":"create-credit","scenario":"first-allocation-empty-tree"}),
                params.feeAmount,
                false,
            ),
            CreditPlan::Update { params, .. } => (
                json!({"kind":"update-credit","scenario":"after-draw-preserve-usage"}),
                params.feeAmount,
                false,
            ),
            CreditPlan::Draw {
                params,
                inputs,
                successors,
                ..
            } => (
                json!({"kind":"draw-credit","capacity":credit_capacity(inputs.len())?,"creditInputs":inputs.len(),"distinctPayers":params.payers.iter().map(|p| p.payer).collect::<std::collections::BTreeSet<_>>().len(),"sourceTrees":params.sources.len(),"noteOutputs":1,"creditOutputs":successors.len(),"creditCiphertextBytes":485,"noteCiphertextBytes":160,"clueBytes":68,"scenario":"distinct-payers"}),
                params.feeAmount,
                true,
            ),
            CreditPlan::Revoke { fee, .. } => (
                json!({"kind":"revoke-credit","authorization":"unknown","bitmapWord":"empty"}),
                fee.amount,
                false,
            ),
        };
        query["feeEnabled"] = json!(fee != U256::ZERO);
        query["feeMechanism"] = json!(if fee == U256::ZERO {
            "none"
        } else if draw {
            "draw-deduction"
        } else {
            "owner-pull"
        });
        let credit_count = match &self.plan {
            CreditPlan::Create { .. } | CreditPlan::Update { .. } => 2,
            CreditPlan::Draw { inputs, .. } => 2 * inputs.len(),
            CreditPlan::Revoke { .. } => 0,
        };
        query["extraDeliveryBytes"] = json!(self
            .deliveries
            .iter()
            .enumerate()
            .map(|(i, d)| d.clue.len().saturating_sub(68)
                + d.ciphertext
                    .len()
                    .saturating_sub(if i < credit_count { 485 } else { 160 }))
            .sum::<usize>());
        if self.broadcaster.as_ref().is_some_and(|s| {
            s.quote.quote.execution == invisi_sdk_rpc::broadcaster::Execution::Aggregate
        }) {
            query = json!({"kind":"aggregate"});
        }
        model(crate::gas::estimate_gas(
            query.as_object().ok_or("invalid gas shape")?,
        ))
    }
}
