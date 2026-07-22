//! Property-based invariant stress test for the fund-moving native operations
//! shipped in Phases 9/13 (tokens, NFTs, agent mandates, application governance,
//! and the native DEX).
//!
//! Purpose: drive long, RANDOM sequences of these operations through the PUBLIC
//! [`ChainState::execute_transaction`] API and assert that the protocol's core
//! accounting invariants NEVER break and nothing panics — across BOTH accepted
//! and rejected operations. It is EXPECTED (and the point) that most randomly
//! generated operations are rejected on a fail-closed path (wrong authority,
//! insufficient funds, frozen/paused state, expired mandate, wrong lifecycle);
//! the invariants must hold identically whether an operation committed or was
//! refused.
//!
//! Invariants asserted after EVERY step:
//! 1. Native supply conservation: `supply_invariant_report().balanced` is always
//!    true (the primary property), and — because this fixture runs with no
//!    validators, so no epoch-reward minting ever occurs — the issued native
//!    supply stays pinned to the genesis total forever.
//! 2. Per-token supply: every created token reconciles issued vs. held units.
//! 3. Per-collection NFT supply: every collection reconciles
//!    `minted - burned == live items`.
//! 4. Fail-closed rollback: a rejected transaction (any `Err`) leaves state
//!    byte-for-byte UNCHANGED (`execute_transaction` commits only on `Ok`).
//!
//! Determinism: every identity comes from a fixed seed and every namespace from
//! fixed bytes; the only source of "time" is explicit epoch advancement through
//! the public API ([`ChainState::distribute_epoch_rewards`], which with no
//! validators simply increments the epoch), so time-gated logic (mandate expiry,
//! governance voting windows and timelocks) actually fires. There is no
//! wall-clock or RNG input beyond proptest's own seeded generation, so a failure
//! shrinks to a minimal, replayable reproducer.
//!
//! Security boundary: none. This is an integration stress test over the public
//! surface; it adds no trust and asserts only accounting the protocol already
//! guarantees.

use proptest::prelude::*;
use webc_chain::{
    Amount, AssetId, ChainConfig, ChainState, Epoch, ExternalChain, FeeBid, GenesisAccount,
    GenesisConfig, GovernanceAction, GovernanceConfig, GovernanceInstanceId,
    MandateCounterpartyPolicy, MandateId, NftCollectionId, NftMetadata, Operation, OrderId,
    OrderSide, Price, ProposalId, TokenId, TokenMetadata, TradingPair, Transaction, VoteChoice,
};
use webc_crypto::{Address, Hash256, Keypair};

// ------------------------------- fixed world --------------------------------

/// Number of distinct signer identities. Small and fixed so ownership/authority
/// paths are exercised (the acting signer frequently is NOT the required
/// authority) and so failures shrink to a minimal reproducer.
const SIGNERS: u8 = 4;
/// Number of fixed application namespaces a token/collection/instance may live
/// under. Tied to the owner index so an id is reconstructable from the seed.
const NAMESPACES: u8 = 2;
/// How many distinct create-nonces (token/collection/instance slots per owner).
const NONCE_MOD: u8 = 3;
/// How many distinct NFT serials an item operation may address.
const SERIAL_MOD: u64 = 6;
/// How many distinct proposal nonces a governance vote/resolve/etc. may address.
const PROPOSAL_MOD: u64 = 3;

/// Per-signer genesis balance: far above any deposit or fee these sequences
/// incur, so most operations fail for protocol reasons (authority, lifecycle,
/// frozen state) rather than trivially running out of native balance.
const GENESIS_BALANCE_WEBC: u64 = 100_000;

/// A deterministic keypair for signer `i` (mod [`SIGNERS`]).
fn signer(i: u8) -> Keypair {
    Keypair::from_seed([0x21u8.wrapping_add(i % SIGNERS); 32])
}

/// A fixed application namespace for index `i` (mod [`NAMESPACES`]).
fn namespace(i: u8) -> Hash256 {
    Hash256::digest_many([b"webc-proptest-namespace", &[i % NAMESPACES]])
}

/// The shared fee bid: `gas_limit` covers every op's `required_units` (max
/// 30_000) and the min base fee is 1, so a well-funded sender's fee never fails
/// for the wrong reason.
fn fee() -> FeeBid {
    FeeBid {
        gas_limit: 100_000,
        max_fee_per_unit: 1,
        priority_fee_per_unit: 0,
    }
}

/// Interprets `amt` as a bounded NATIVE amount in whole WEBC. Zero is reachable
/// (exercising zero-amount rejections); the ceiling keeps a single sequence from
/// draining a signer, and is nowhere near `u128` overflow territory.
fn native(amt: u64) -> Amount {
    Amount::from_webc(amt % 400)
}

/// Interprets `amt` as a bounded FUNGIBLE-TOKEN amount in raw units.
fn units(amt: u64) -> Amount {
    Amount::from_units(u128::from(amt % 50_000))
}

/// Bounded, always-valid token metadata (non-empty name/symbol, in-range decimals).
fn token_metadata() -> TokenMetadata {
    TokenMetadata::new(b"proptok".to_vec(), b"ptk".to_vec(), 6, Hash256::ZERO)
        .expect("static token metadata is valid")
}

/// Bounded, always-valid NFT collection metadata.
fn nft_metadata() -> NftMetadata {
    NftMetadata::new(b"propcol".to_vec(), b"pcl".to_vec(), Hash256::ZERO)
        .expect("static nft metadata is valid")
}

/// Fresh genesis state: [`SIGNERS`] funded accounts, NO validators (so epoch
/// advancement mints nothing and the issued supply stays pinned) and no pinned
/// `expected_total_supply` (a trusted in-crate fixture with a small allocation).
fn genesis_state() -> (ChainConfig, ChainState, Amount) {
    let config = ChainConfig::default();
    let accounts: Vec<GenesisAccount> = (0..SIGNERS)
        .map(|i| GenesisAccount {
            address: signer(i).address(),
            balance: Amount::from_webc(GENESIS_BALANCE_WEBC),
        })
        .collect();
    let genesis = GenesisConfig {
        chain: config.clone(),
        accounts,
        validators: Vec::new(),
    };
    let state = ChainState::from_genesis(&genesis).expect("valid genesis fixture");
    let genesis_total = Amount::from_webc(GENESIS_BALANCE_WEBC * u64::from(SIGNERS));
    (config, state, genesis_total)
}

/// Current replay nonce for `address`, or zero for an account that does not yet
/// exist. Every signer exists from genesis, so a signed transaction always uses
/// its live nonce (a rejected transaction never advances it).
fn nonce_of(state: &ChainState, address: Address) -> u64 {
    state.accounts.get(&address).map(|a| a.nonce).unwrap_or(0)
}

/// A stable, seed-derived DEX order identity, so a later `CancelOrder` can name
/// the same order a `SubmitOrder` created.
fn order_id(owner: u8, actor: u8, sub: u8) -> OrderId {
    OrderId::new(Hash256::digest_many([
        b"webc-proptest-order",
        &[owner, actor, sub],
    ]))
}

// ---------------------------- step construction -----------------------------

/// Builds the signed transaction for a non-epoch step `kind` from the seed.
///
/// The generator emits only integers, so this maps them onto the fixed world:
/// `owner` selects the asset's creator/authority slot (and its namespace),
/// `actor` selects the ACTING signer (frequently not the required authority —
/// that is deliberate), `other` selects a recipient/agent/counterparty, `sub`
/// carries a create-nonce / choice / flags, and `amt` an amount. State-derived
/// inputs the pure access list cannot name (a governance instance's weight token,
/// a treasury payout's recipient) are resolved by reading committed state, exactly
/// as a real caller would; when the referenced record is absent a placeholder is
/// used and the transaction is rejected fail-closed.
fn build_tx(state: &ChainState, seed: (u8, u8, u8, u8, u8, u64)) -> Transaction {
    let (kind, owner, actor, other, sub, amt) = seed;
    let owner_kp = signer(owner);
    let actor_kp = signer(actor);
    let other_kp = signer(other);
    let ns = namespace(owner);
    let create_nonce = u64::from(sub % NONCE_MOD);

    match kind % 26 {
        // --------------------------- fungible tokens ------------------------
        0 => {
            // CreateToken (creator-signed). Authorities are sometimes renounced
            // at creation so later mint/freeze attempts hit the `None`-authority
            // path; an initial supply is minted to `other`.
            let mint_authority = (sub % 3 != 0).then(|| owner_kp.address());
            let freeze_authority = (sub % 4 != 0).then(|| owner_kp.address());
            let op = Operation::CreateToken {
                namespace: ns,
                create_nonce,
                metadata: token_metadata(),
                mint_authority,
                freeze_authority,
                initial_supply: units(amt),
                initial_recipient: other_kp.address(),
            };
            for_op(&owner_kp, nonce_of(state, owner_kp.address()), op)
        }
        1 => {
            let token_id = TokenId::derive(ns, owner_kp.address(), create_nonce);
            let op = Operation::MintToken {
                token_id,
                recipient: other_kp.address(),
                amount: units(amt),
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
        2 => {
            let token_id = TokenId::derive(ns, owner_kp.address(), create_nonce);
            let op = Operation::BurnToken {
                token_id,
                amount: units(amt),
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
        3 => {
            let token_id = TokenId::derive(ns, owner_kp.address(), create_nonce);
            let op = Operation::TransferToken {
                token_id,
                recipient: other_kp.address(),
                amount: units(amt),
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
        4 => {
            let token_id = TokenId::derive(ns, owner_kp.address(), create_nonce);
            let op = Operation::SetTokenPaused {
                token_id,
                paused: sub % 2 == 0,
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
        5 => {
            let token_id = TokenId::derive(ns, owner_kp.address(), create_nonce);
            let op = Operation::FreezeTokenAccount {
                token_id,
                account: other_kp.address(),
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
        6 => {
            let token_id = TokenId::derive(ns, owner_kp.address(), create_nonce);
            let op = Operation::ThawTokenAccount {
                token_id,
                account: other_kp.address(),
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
        // -------------------------------- NFTs ------------------------------
        7 => {
            let max_supply = (sub % 2 == 1).then_some((amt % 8) + 1);
            let op = Operation::CreateNftCollection {
                namespace: ns,
                create_nonce,
                metadata: nft_metadata(),
                mint_authority: (sub % 3 != 0).then(|| owner_kp.address()),
                freeze_authority: (sub % 4 != 0).then(|| owner_kp.address()),
                max_supply,
                royalty_bps: (amt % 1000) as u16,
            };
            for_op(&owner_kp, nonce_of(state, owner_kp.address()), op)
        }
        8 => {
            let collection_id = NftCollectionId::derive(ns, owner_kp.address(), create_nonce);
            let op = Operation::MintNft {
                collection_id,
                recipient: other_kp.address(),
                item_metadata_hash: Hash256::ZERO,
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
        9 => {
            let collection_id = NftCollectionId::derive(ns, owner_kp.address(), create_nonce);
            let op = Operation::TransferNft {
                collection_id,
                serial: amt % SERIAL_MOD,
                recipient: other_kp.address(),
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
        10 => {
            let collection_id = NftCollectionId::derive(ns, owner_kp.address(), create_nonce);
            let op = Operation::BurnNft {
                collection_id,
                serial: amt % SERIAL_MOD,
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
        11 => {
            let collection_id = NftCollectionId::derive(ns, owner_kp.address(), create_nonce);
            let op = Operation::FreezeNftItem {
                collection_id,
                serial: amt % SERIAL_MOD,
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
        12 => {
            let collection_id = NftCollectionId::derive(ns, owner_kp.address(), create_nonce);
            let op = Operation::ThawNftItem {
                collection_id,
                serial: amt % SERIAL_MOD,
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
        // ------------------------------ mandates ----------------------------
        13 => {
            // GrantMandate (principal-signed). `owner` is the principal, `other`
            // the agent key; expiry is near the current epoch so later advances
            // expire it. per_tx_max == budget keeps the grant valid (per-tx cap
            // never above budget) while a zero budget exercises validation.
            let op = Operation::GrantMandate {
                agent_key: other_kp.public_key(),
                grant_nonce: create_nonce,
                budget_total: native(amt),
                expiry_epoch: Epoch::new(state.current_epoch + u64::from(sub % 4)),
                per_tx_max: native(amt),
                rate_limit_per_day: u32::from(sub % 5),
                counterparty_policy: MandateCounterpartyPolicy::Open,
            };
            for_op(&owner_kp, nonce_of(state, owner_kp.address()), op)
        }
        14 => {
            // SpendUnderMandate (agent-signed). The sender is the agent `other`.
            let mandate_id =
                MandateId::derive(owner_kp.address(), &other_kp.public_key(), create_nonce);
            let op = Operation::SpendUnderMandate {
                mandate_id,
                recipient: actor_kp.address(),
                amount: native(amt),
            };
            for_op(&other_kp, nonce_of(state, other_kp.address()), op)
        }
        15 => {
            let mandate_id =
                MandateId::derive(owner_kp.address(), &other_kp.public_key(), create_nonce);
            let op = Operation::TopUpMandate {
                mandate_id,
                amount: native(amt),
            };
            for_op(&owner_kp, nonce_of(state, owner_kp.address()), op)
        }
        16 => {
            let mandate_id =
                MandateId::derive(owner_kp.address(), &other_kp.public_key(), create_nonce);
            let op = Operation::RevokeMandate { mandate_id };
            for_op(&owner_kp, nonce_of(state, owner_kp.address()), op)
        }
        // ----------------------------- governance ---------------------------
        17 => {
            // CreateGovernanceInstance. The weight token is this owner's slot-0
            // token (must already exist, else `TokenNotFound`).
            let weight_token = TokenId::derive(ns, owner_kp.address(), 0);
            let config = GovernanceConfig {
                voting_period_epochs: 1 + u64::from(sub % 3),
                timelock_epochs: u64::from(sub % 2),
                quorum_bps: (amt % 5000) as u16,
                proposal_threshold: Amount::from_units(u128::from(amt % 1000)),
                approval_threshold_bps: (amt % 8000) as u16,
            };
            let op = Operation::CreateGovernanceInstance {
                namespace: ns,
                create_nonce,
                weight_token,
                config,
            };
            for_op(&owner_kp, nonce_of(state, owner_kp.address()), op)
        }
        18 => {
            let instance_id = GovernanceInstanceId::derive(ns, owner_kp.address(), create_nonce);
            let op = Operation::FundGovernanceTreasury {
                instance_id,
                amount: native(amt),
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
        19 => {
            // OpenProposal. The proposer's weight-token balance key is
            // state-derived, so resolve the instance's weight token from state.
            let instance_id = GovernanceInstanceId::derive(ns, owner_kp.address(), create_nonce);
            let weight_token = state
                .governance_instances
                .get(&instance_id)
                .map(|instance| instance.weight_token)
                .unwrap_or_else(|| TokenId::derive(ns, owner_kp.address(), 0));
            let action = if sub % 2 == 0 {
                GovernanceAction::Signaling
            } else {
                GovernanceAction::TreasuryTransfer {
                    recipient: other_kp.address(),
                    amount: native(amt),
                }
            };
            Transaction::for_open_proposal(
                &actor_kp,
                nonce_of(state, actor_kp.address()),
                instance_id,
                action,
                weight_token,
                fee(),
            )
            .expect("open-proposal transaction builds and signs")
        }
        20 => {
            // CastVote. Resolve the weight token from the proposal snapshot.
            let instance_id = GovernanceInstanceId::derive(ns, owner_kp.address(), create_nonce);
            let proposal_id = ProposalId::derive(instance_id, u64::from(other) % PROPOSAL_MOD);
            let weight_token = proposal_weight_token(state, proposal_id, ns, owner_kp.address());
            let choice = match sub % 3 {
                0 => VoteChoice::Yes,
                1 => VoteChoice::No,
                _ => VoteChoice::Abstain,
            };
            Transaction::for_cast_vote(
                &actor_kp,
                nonce_of(state, actor_kp.address()),
                proposal_id,
                choice,
                units(amt),
                weight_token,
                fee(),
            )
            .expect("cast-vote transaction builds and signs")
        }
        21 => {
            let instance_id = GovernanceInstanceId::derive(ns, owner_kp.address(), create_nonce);
            let proposal_id = ProposalId::derive(instance_id, u64::from(other) % PROPOSAL_MOD);
            let weight_token = proposal_weight_token(state, proposal_id, ns, owner_kp.address());
            Transaction::for_resolve_proposal(
                &actor_kp,
                nonce_of(state, actor_kp.address()),
                proposal_id,
                weight_token,
                fee(),
            )
            .expect("resolve-proposal transaction builds and signs")
        }
        22 => {
            // ExecuteProposal. A treasury-transfer payout names the instance and
            // recipient (state-derived from the stored proposal); a signaling
            // proposal needs no extra keys.
            let instance_id = GovernanceInstanceId::derive(ns, owner_kp.address(), create_nonce);
            let proposal_id = ProposalId::derive(instance_id, u64::from(other) % PROPOSAL_MOD);
            let payout =
                state
                    .governance_proposals
                    .get(&proposal_id)
                    .and_then(|p| match &p.action {
                        GovernanceAction::TreasuryTransfer { recipient, .. } => {
                            Some((p.instance_id, *recipient))
                        }
                        GovernanceAction::Signaling => None,
                    });
            Transaction::for_execute_proposal(
                &actor_kp,
                nonce_of(state, actor_kp.address()),
                proposal_id,
                payout,
                fee(),
            )
            .expect("execute-proposal transaction builds and signs")
        }
        23 => {
            let instance_id = GovernanceInstanceId::derive(ns, owner_kp.address(), create_nonce);
            let proposal_id = ProposalId::derive(instance_id, u64::from(other) % PROPOSAL_MOD);
            let weight_token = proposal_weight_token(state, proposal_id, ns, owner_kp.address());
            Transaction::for_reclaim_vote(
                &actor_kp,
                nonce_of(state, actor_kp.address()),
                proposal_id,
                weight_token,
                fee(),
            )
            .expect("reclaim-vote transaction builds and signs")
        }
        // -------------------------------- DEX -------------------------------
        24 => {
            // SubmitOrder with a native-WEBC base leg: a Sell locks `amount`
            // native into `dex_escrow` (liquid -> escrow, supply-neutral).
            let pair = TradingPair::new(
                AssetId::NativeWebc,
                AssetId::WrappedWebc {
                    origin_chain: ExternalChain::Ethereum,
                },
            );
            let op = Operation::SubmitOrder {
                order_id: order_id(owner, actor, sub),
                pair,
                side: OrderSide::Sell,
                amount: native(amt),
                limit_price: Price::new(u128::from(amt % 1000) + 1),
                deadline_height: 0,
                fill_or_cancel: sub % 2 == 0,
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
        _ => {
            let op = Operation::CancelOrder {
                order_id: order_id(owner, actor, sub),
            };
            for_op(&actor_kp, nonce_of(state, actor_kp.address()), op)
        }
    }
}

/// Resolves a proposal's snapshotted weight token from state, falling back to a
/// placeholder (the referenced proposal does not exist, so the transaction is
/// rejected fail-closed regardless of which token id is named).
fn proposal_weight_token(
    state: &ChainState,
    proposal_id: ProposalId,
    ns: Hash256,
    owner: Address,
) -> TokenId {
    state
        .governance_proposals
        .get(&proposal_id)
        .map(|proposal| proposal.weight_token)
        .unwrap_or_else(|| TokenId::derive(ns, owner, 0))
}

/// Signs a default-lane transaction carrying `operation` for `signer`.
fn for_op(signer: &Keypair, nonce: u64, operation: Operation) -> Transaction {
    Transaction::for_operation(signer, nonce, operation, fee())
        .expect("proptest transaction builds and signs")
}

// ------------------------------- invariants ---------------------------------

/// Executes `tx` and enforces the fail-closed rollback invariant: a rejected
/// transaction (any `Err`) must leave state byte-for-byte unchanged. Never
/// `.unwrap()`s the result — the whole point is that many transactions are
/// rejected.
fn execute_checked(
    state: &mut ChainState,
    config: &ChainConfig,
    tx: &Transaction,
) -> Result<(), TestCaseError> {
    let before = state.clone();
    if state.execute_transaction(tx, config).is_err() {
        prop_assert!(
            *state == before,
            "a rejected transaction mutated chain state (rollback invariant broken)"
        );
    }
    Ok(())
}

/// Asserts every accounting invariant that must hold after every applied or
/// rejected operation.
fn assert_invariants(state: &ChainState, genesis_total: Amount) -> Result<(), TestCaseError> {
    // 1. Native supply conservation (primary property).
    let report = state
        .supply_invariant_report()
        .expect("supply invariant report");
    prop_assert!(
        report.balanced,
        "native supply invariant does not reconcile: {report:?}"
    );
    // With no validators there is no epoch-reward minting, so issued native
    // supply is pinned to the genesis total for the whole sequence.
    prop_assert_eq!(
        report.issued,
        genesis_total,
        "issued native supply drifted from the genesis total"
    );

    // 2. The aggregate storage bucket must equal the deposits authenticated by
    // live object leaves. Native supply can remain numerically balanced even if
    // these two drift together with a liquid-account bug, so check the stronger
    // object-level ownership invariant explicitly.
    let live_object_deposits = state
        .objects
        .values()
        .try_fold(Amount::ZERO, |total, object| {
            total.checked_add(object.deposit)
        })
        .expect("bounded object deposits sum without overflow");
    prop_assert_eq!(
        state.storage_deposits,
        live_object_deposits,
        "aggregate storage deposits drifted from live object deposits"
    );

    // 3. Per-token supply: issued == sum of held balances, for every token.
    for token_id in state.tokens.keys() {
        let token_report = state
            .token_supply_report(*token_id)
            .expect("token supply report for a live token");
        prop_assert!(
            token_report.balanced,
            "per-token supply invariant broke for {token_id:?}: {token_report:?}"
        );
    }

    // 4. Per-collection NFT supply: minted - burned == live items.
    for collection_id in state.nft_collections.keys() {
        let collection_report = state
            .nft_collection_supply_report(*collection_id)
            .expect("nft collection supply report for a live collection");
        prop_assert!(
            collection_report.balanced,
            "per-collection NFT invariant broke for {collection_id:?}: {collection_report:?}"
        );
    }

    Ok(())
}

// --------------------------------- driver -----------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Drives a random sequence of the fund-moving native operations through the
    /// public API and asserts the accounting invariants after every step. A
    /// step whose `kind` selects an epoch advance drives chain "time" forward
    /// (the only time source), letting mandate expiry and governance
    /// voting/timelock windows fire; all other steps build, sign, and submit one
    /// native operation and enforce the fail-closed rollback rule on rejection.
    #[test]
    fn native_ops_preserve_all_supply_invariants(
        seeds in prop::collection::vec(
            (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>(), 0u64..2_000_000u64),
            1..48,
        )
    ) {
        let (config, mut state, genesis_total) = genesis_state();
        assert_invariants(&state, genesis_total)?;

        for seed in seeds {
            // Two of the 28 selector classes advance the epoch (the rest submit
            // a native operation), so ~1 in 14 steps moves chain time forward —
            // enough for mandate expiry and governance windows to fire, without
            // starving the value-moving operations.
            match seed.0 % 28 {
                26 | 27 => {
                    let before = state.clone();
                    if state.distribute_epoch_rewards(&config).is_err() {
                        prop_assert!(
                            state == before,
                            "a failed epoch advance mutated chain state"
                        );
                    }
                }
                _ => {
                    let tx = build_tx(&state, seed);
                    execute_checked(&mut state, &config, &tx)?;
                }
            }

            assert_invariants(&state, genesis_total)?;
        }
    }
}
