//! Native APPLICATION GOVERNANCE: token-weighted, lock-to-vote governance
//! instances that control their own native-WEBC treasury (WEBC-DEFINITION §15;
//! `docs/development-plan.md` "Phase 13" — "governance instances: snapshots,
//! quorum, timelocks, delegation, execution policy").
//!
//! Purpose: let an APPLICATION stand up a self-contained, token-weighted
//! governance instance bound to ONE fungible token (a [`crate::TokenId`], already
//! shipped in [`crate::token`]) and let holders of that token open proposals,
//! vote on them, and — after a timelock — execute the ONE bounded on-chain effect
//! a proposal may carry: a payout from the instance's OWN native-WEBC treasury.
//! This is deliberately APPLICATION-scoped: an instance controls only its own
//! treasury and can never touch chain parameters, validators, slashing, protocol
//! config, or any other application's state (those are owner-gated and out of
//! scope). A governance instance is the configurable-rules counterpart of the
//! native token: a namespace-scoped record an application creates for a
//! spam-priced native deposit, then funds and governs.
//!
//! Lock-to-vote (the key to the Phase 13 acceptance criterion "governance
//! snapshots prevent double voting and after-snapshot manipulation" WITHOUT
//! storing historical balances): a vote LOCKS the voter's weight by MOVING that
//! many weight-token units from the voter into a deterministic per-proposal escrow
//! address ([`gov_vote_escrow_address`]) inside the shared `token_balances` map.
//! The moved units are the voter's immutable voting WEIGHT for that proposal:
//! - double voting is impossible — a second [`crate::Operation::CastVote`] from the
//!   same voter is rejected because a lock already exists, and the locked units are
//!   no longer in the voter's balance to lock again;
//! - after-snapshot manipulation is impossible — weight is the amount locked at
//!   vote time, not a mutable balance a later transfer/mint could inflate;
//! - the per-token supply invariant `sum(token_balances) == issued_supply` is
//!   preserved automatically, because a lock is a MOVE within `token_balances`
//!   (voter -> escrow) and a reclaim is the reverse MOVE (escrow -> voter), never a
//!   mint or burn.
//!
//! Responsibilities: define the instance identity ([`GovernanceInstanceId`]) and
//! proposal identity ([`ProposalId`]) and their deterministic derivations, the
//! per-instance rule set ([`GovernanceConfig`]) with every threshold RANGE-BOUNDED,
//! the instance record ([`GovernanceInstance`]), the bounded typed action enum
//! ([`GovernanceAction`]), the proposal record ([`Proposal`]) with its lifecycle
//! ([`GovProposalStatus`]) and running tallies, the per-voter lock record
//! ([`VoteRecord`]) and choice ([`VoteChoice`]), the deterministic escrow-address
//! derivation ([`gov_vote_escrow_address`]), and the three Merkle sub-root domains
//! that commit the instance map, the proposal map, and the vote-lock map to the
//! state root ([`GOVERNANCE_INSTANCE_LEAF_DOMAIN`],
//! [`GOVERNANCE_PROPOSAL_LEAF_DOMAIN`], [`GOVERNANCE_VOTE_LEAF_DOMAIN`]).
//!
//! Non-responsibilities: this module never moves native WEBC or token supply,
//! never touches accounts, and never reads a wall clock, network, files, or
//! randomness. The `state` module owns the committed `governance_instances` /
//! `governance_proposals` / `governance_votes` collections, the
//! `governance_deposits` and `governance_treasury` locked buckets, every
//! create / fund / open / vote / resolve / execute / reclaim state transition, and
//! the state-commitment / access-list wiring; it consumes the pure identifiers,
//! records, and validation here. All timing is measured in `current_epoch`
//! (never a wall clock); all threshold math is integer `checked_mul`/compare over
//! basis points (never floating point).
//!
//! Security boundary: every field of a [`GovernanceConfig`] and [`Proposal`] is
//! untrusted — thresholds are range-bounded on decode *and* re-checked by
//! [`GovernanceConfig::validate`], and [`GovernanceAction`] is a small typed enum
//! whose only executable effect is a payout from THIS instance's own treasury, so
//! a hostile record can neither smuggle an out-of-range threshold past a state load
//! nor name an out-of-scope effect. A voter can lock only what they hold (the move
//! fails closed on an insufficient balance), and the escrow address is a synthetic
//! [`Address`] no keypair can produce (it is a domain-separated hash, not the hash
//! of any public key), so locked units can be moved only by the reclaim path. This
//! path is a devnet prototype and is disabled for real funds.

use crate::{Amount, ChainError, TokenId};
use serde::{Deserialize, Serialize};
use webc_crypto::{Address, Hash256};

/// Domain tag hashed into a governance instance's opaque, namespace-scoped
/// identity.
///
/// Domain separation keeps an instance id from colliding with an address, a token
/// id, a service id, a proposal id, or any other 32-byte WEBC artifact derived
/// from the same inputs. Changing it is a consensus-format break.
const GOVERNANCE_INSTANCE_ID_DOMAIN: &[u8] = b"WEBC_GOV_INSTANCE_ID_V1";

/// Domain tag hashed into a proposal's opaque identity within one instance.
///
/// A proposal id commits to `(instance_id, proposal_nonce)`, so two instances (or
/// two proposals in one instance) can never derive the same id. Changing it is a
/// consensus-format break.
const GOVERNANCE_PROPOSAL_ID_DOMAIN: &[u8] = b"WEBC_GOV_PROPOSAL_ID_V1";

/// Domain tag hashed into a proposal's deterministic vote-lock ESCROW address.
///
/// The escrow that holds every voter's locked weight for one proposal is a
/// synthetic [`Address`] = `SHA-256(domain || proposal_id)`. Because it is a hash
/// of a domain plus the proposal id (never the hash of a public key, which is how
/// [`Address::from_public_key`] derives real accounts), no keypair can ever sign
/// as the escrow, so the locked units can be moved only by the reclaim path.
/// Changing it is a consensus-format break.
const GOVERNANCE_VOTE_ESCROW_DOMAIN: &[u8] = b"WEBC_GOV_VOTE_ESCROW_V1";

/// Domain tag for the governance-instance Merkle sub-root committed by the state
/// root.
///
/// Each `(GovernanceInstanceId, GovernanceInstance)` entry is a leaf under this
/// domain, so a create, a treasury fund, or (via the bumped proposal nonce) a
/// proposal open moves the state root. Bumping this constant is a consensus-format
/// change.
pub const GOVERNANCE_INSTANCE_LEAF_DOMAIN: &[u8] = b"WEBC_GOV_INSTANCE_LEAF_V1";

/// Domain tag for the governance-proposal Merkle sub-root committed by the state
/// root.
///
/// Each `(ProposalId, Proposal)` entry is a leaf under this domain, so an open, a
/// vote (tally update), a resolve, or an execute moves the state root. Bumping this
/// constant is a consensus-format change.
pub const GOVERNANCE_PROPOSAL_LEAF_DOMAIN: &[u8] = b"WEBC_GOV_PROPOSAL_LEAF_V1";

/// Domain tag for the governance vote-lock Merkle sub-root committed by the state
/// root.
///
/// Each `((ProposalId, voter), VoteRecord)` entry is a leaf under this domain, so
/// casting a vote (which records a lock) or reclaiming it (which clears the lock)
/// moves the state root. Only currently-locked votes are present, so the committed
/// set stays bounded — a reclaim removes the entry. Bumping this constant is a
/// consensus-format change.
pub const GOVERNANCE_VOTE_LEAF_DOMAIN: &[u8] = b"WEBC_GOV_VOTE_LEAF_V1";

/// The largest basis-point value any governance threshold may take (100%).
///
/// `quorum_bps` and `approval_threshold_bps` are checked against this on decode
/// and by [`GovernanceConfig::validate`]; a value above it is rejected as an
/// invalid config, so all quorum/approval math stays a well-defined ratio of at
/// most one.
pub const MAX_GOVERNANCE_BPS: u16 = 10_000;

/// Opaque, non-secret, namespace-scoped identity of one governance instance.
///
/// Derived as `SHA-256("WEBC_GOV_INSTANCE_ID_V1" || namespace || creator ||
/// create_nonce_be)`. Binding the `namespace` keeps governance activity isolated
/// by application (§8) and lets two applications create instances under distinct
/// namespaces without contention; binding the `creator` and a creator-chosen
/// `create_nonce` makes creation permissionless and collision-safe — one creator
/// may create many instances under one namespace by varying the nonce, while a
/// repeated `(namespace, creator, create_nonce)` derives the same id and the
/// second creation is rejected as a duplicate. A distinct wrapper type keeps an
/// instance id from being mixed with a token id, a service id, a proposal id, or a
/// raw hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GovernanceInstanceId(Hash256);

impl GovernanceInstanceId {
    /// Constructs an instance id from a raw 32-byte hash (wire/decoding path).
    pub const fn new(value: Hash256) -> Self {
        Self(value)
    }

    /// Returns the underlying fixed-size identifier used by versioned state keys
    /// and leaf hashing.
    pub const fn hash(self) -> Hash256 {
        self.0
    }

    /// Derives the deterministic id committing to a `(namespace, creator,
    /// create_nonce)` creation.
    ///
    /// Identical inputs derive an identical id on every node; changing any input
    /// (including the `create_nonce`) derives a different id. This is the only way
    /// an id is minted, so a fund / open / vote / resolve / execute / reclaim that
    /// names an id can never address an instance a different creator created.
    pub fn derive(namespace: Hash256, creator: Address, create_nonce: u64) -> Self {
        let nonce = create_nonce.to_be_bytes();
        let parts: [&[u8]; 4] = [
            GOVERNANCE_INSTANCE_ID_DOMAIN,
            namespace.as_bytes().as_slice(),
            creator.as_bytes().as_slice(),
            nonce.as_slice(),
        ];
        Self(Hash256::digest_many(parts))
    }
}

/// Opaque, non-secret identity of one proposal within one instance.
///
/// Derived as `SHA-256("WEBC_GOV_PROPOSAL_ID_V1" || instance_id ||
/// proposal_nonce_be)`, where `proposal_nonce` is the instance's monotonic
/// [`GovernanceInstance::next_proposal_nonce`] at open time. Binding the
/// `instance_id` keeps proposals isolated per instance; binding the monotonic
/// nonce makes each open collision-safe and lets a proposal be found in one map
/// probe. A distinct wrapper type keeps a proposal id from being mixed with an
/// instance id, a token id, or a raw hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProposalId(Hash256);

impl ProposalId {
    /// Constructs a proposal id from a raw 32-byte hash (wire/decoding path).
    pub const fn new(value: Hash256) -> Self {
        Self(value)
    }

    /// Returns the underlying fixed-size identifier used by versioned state keys
    /// and leaf hashing.
    pub const fn hash(self) -> Hash256 {
        self.0
    }

    /// Derives the deterministic id committing to `(instance_id, proposal_nonce)`.
    ///
    /// Identical inputs derive an identical id on every node; a different instance
    /// or nonce derives a different id. Because the nonce is the instance's
    /// monotonic counter (never reused), a proposal id is unique for the instance's
    /// life.
    pub fn derive(instance_id: GovernanceInstanceId, proposal_nonce: u64) -> Self {
        let nonce = proposal_nonce.to_be_bytes();
        let instance_hash = instance_id.hash();
        let parts: [&[u8]; 3] = [
            GOVERNANCE_PROPOSAL_ID_DOMAIN,
            instance_hash.as_bytes().as_slice(),
            nonce.as_slice(),
        ];
        Self(Hash256::digest_many(parts))
    }
}

/// Derives the deterministic per-proposal vote-lock ESCROW address.
///
/// Returned as `Address(SHA-256("WEBC_GOV_VOTE_ESCROW_V1" || proposal_id))`. Every
/// voter on one proposal locks their weight by moving weight-token units into this
/// single synthetic holder inside `token_balances`; a reclaim moves them back. The
/// address is a hash of a domain plus the proposal id — NOT the hash of any public
/// key, which is how real accounts are derived ([`Address::from_public_key`]) — so
/// no keypair maps to it and the locked units can be moved only by the reclaim
/// state transition. Distinct proposals derive distinct escrows, so locks never
/// commingle across proposals.
pub fn gov_vote_escrow_address(proposal_id: ProposalId) -> Address {
    let proposal_hash = proposal_id.hash();
    let parts: [&[u8]; 2] = [
        GOVERNANCE_VOTE_ESCROW_DOMAIN,
        proposal_hash.as_bytes().as_slice(),
    ];
    Address::from_bytes(Hash256::digest_many(parts).0)
}

/// Per-instance governance rule set (Phase 13c, §15).
///
/// Fixed at instance creation and SNAPSHOT onto every [`Proposal`] at open time, so
/// a proposal is judged by the rules in force when it opened. Every threshold is
/// range-bounded; timing is in epochs (never wall clock).
///
/// Invariants (checked by [`GovernanceConfig::validate`], re-checked on any state
/// load or create in `state`):
/// - `voting_period_epochs` is non-zero (a proposal must have a positive voting
///   window, or voting could never be open);
/// - `quorum_bps` is at most [`MAX_GOVERNANCE_BPS`];
/// - `approval_threshold_bps` is at most [`MAX_GOVERNANCE_BPS`].
///
/// `timelock_epochs` may be zero (execution available immediately once passed);
/// `proposal_threshold` may be zero (anyone holding the weight token — or none, if
/// zero — may open a proposal).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceConfig {
    /// Epochs a proposal accepts votes after it opens; the proposal's
    /// `voting_ends_epoch` is `created_epoch + voting_period_epochs`. Must be > 0.
    pub voting_period_epochs: u64,
    /// Epochs that must pass AFTER voting ends before a passed proposal may
    /// execute; the proposal's `eta_epoch` is `voting_ends_epoch + timelock_epochs`.
    /// May be zero (no timelock).
    pub timelock_epochs: u64,
    /// Minimum participation, in basis points of the weight token's issued supply,
    /// for a proposal to reach quorum: `(yes+no+abstain) * 10_000 >= issued_supply
    /// * quorum_bps`. At most [`MAX_GOVERNANCE_BPS`].
    pub quorum_bps: u16,
    /// Minimum weight-token balance a proposer must currently hold to open a
    /// proposal. May be zero.
    pub proposal_threshold: Amount,
    /// Approval ratio, in basis points of the decisive vote, required to pass:
    /// `yes * 10_000 >= (yes + no) * approval_threshold_bps` (abstain does not count
    /// toward the ratio, only toward quorum). At most [`MAX_GOVERNANCE_BPS`].
    pub approval_threshold_bps: u16,
}

impl GovernanceConfig {
    /// Re-validates the range/non-zero invariants.
    ///
    /// Returns [`ChainError::InvalidGovernanceConfig`] on a zero voting period or a
    /// quorum/approval threshold above [`MAX_GOVERNANCE_BPS`]. A hostile decode or a
    /// state load could otherwise smuggle an out-of-range config in, so this is
    /// called on every create and (defensively) on load.
    pub fn validate(&self) -> Result<(), ChainError> {
        if self.voting_period_epochs == 0 {
            return Err(ChainError::InvalidGovernanceConfig);
        }
        if self.quorum_bps > MAX_GOVERNANCE_BPS
            || self.approval_threshold_bps > MAX_GOVERNANCE_BPS
        {
            return Err(ChainError::InvalidGovernanceConfig);
        }
        Ok(())
    }
}

/// Per-instance authority and treasury record (Phase 13c, §15).
///
/// Keyed in [`crate::ChainState::governance_instances`] by
/// [`GovernanceInstanceId`]. Holds the instance's creator, the fungible token that
/// denominates voting weight, its immutable rule set, the native-WEBC `treasury`
/// the instance controls, and the monotonic proposal-nonce counter.
///
/// The `treasury` is native WEBC an instance holds: [`crate::Operation::FundGovernanceTreasury`]
/// moves units in from a funder's liquid balance (tracked by the aggregate
/// `governance_treasury` bucket), and a passed [`GovernanceAction::TreasuryTransfer`]
/// pays units out to a recipient's liquid balance on execution. The treasury never
/// mints or burns native WEBC; it only relocates it between the funder/recipient
/// liquid balance and the locked treasury bucket, so the native supply invariant
/// stays balanced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceInstance {
    /// Account that created the instance (immutable; recorded for provenance).
    pub creator: Address,
    /// Fungible token whose per-account balance denominates voting weight. Bound
    /// for the instance's life; every proposal snapshots it.
    pub weight_token: TokenId,
    /// Immutable rule set (voting period, timelock, quorum, proposal threshold,
    /// approval threshold).
    pub config: GovernanceConfig,
    /// Native WEBC the instance controls, in base units. Funded by
    /// [`crate::Operation::FundGovernanceTreasury`]; paid out by a passed
    /// [`GovernanceAction::TreasuryTransfer`] on execution.
    pub treasury: Amount,
    /// Monotonic counter assigning the next proposal its nonce (and, with the
    /// instance id, its [`ProposalId`]). Only grows, so a proposal id is never
    /// reused.
    pub next_proposal_nonce: u64,
}

impl GovernanceInstance {
    /// Creates a freshly created, validated instance with a zero treasury and a
    /// zero proposal nonce.
    ///
    /// Validates the embedded config; id derivation, duplicate rejection, and the
    /// deposit lock are the caller's (`state`'s) concern. Returns
    /// [`ChainError::InvalidGovernanceConfig`] on a malformed config.
    pub fn new(
        creator: Address,
        weight_token: TokenId,
        config: GovernanceConfig,
    ) -> Result<Self, ChainError> {
        config.validate()?;
        Ok(Self {
            creator,
            weight_token,
            config,
            treasury: Amount::ZERO,
            next_proposal_nonce: 0,
        })
    }
}

/// The single BOUNDED, TYPED on-chain effect a proposal may carry (Phase 13c,
/// §15).
///
/// A proposal's ONLY executable effect is APPLICATION-scoped: a payout from THIS
/// instance's own treasury, or nothing at all. This enum is deliberately small and
/// closed — it has NO variant that could touch chain parameters, validators,
/// slashing, protocol config, or another application's state — so the hard scope
/// boundary is enforced by construction, not by a runtime check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum GovernanceAction {
    /// Pay `amount` native WEBC from the instance treasury to `recipient` on
    /// execution. Re-checked against the live treasury at execute time and fails
    /// closed if the treasury cannot cover it.
    TreasuryTransfer {
        /// Account credited the paid-out native WEBC.
        recipient: Address,
        /// Native base units paid from the treasury.
        amount: Amount,
    },
    /// A signaling-only proposal with no on-chain effect. It still passes/fails by
    /// the same quorum/approval rules and locks/reclaims votes identically; its
    /// "execution" simply marks it done without moving any value.
    Signaling,
}

/// Lifecycle status of one proposal (Phase 13c, §15).
///
/// Transitions (each driven by an explicit operation, never a wall clock):
/// - `Active` -> `Passed` or `Defeated` by [`crate::Operation::ResolveProposal`]
///   after voting ends;
/// - `Passed` -> `Executed` by [`crate::Operation::ExecuteProposal`] within the
///   execution window after the timelock;
/// - `Passed` -> `Expired` by [`crate::Operation::ExecuteProposal`] once the
///   execution window has lapsed (a stale approval can no longer drain the
///   treasury; this mirrors the canonical governance "expired" state).
///
/// `Defeated`, `Executed`, and `Expired` are terminal; `Passed` is terminal except
/// for the single execute transition. Every terminal status (and `Passed`) lets a
/// voter reclaim their locked weight.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovProposalStatus {
    /// Accepting votes (until `voting_ends_epoch`).
    Active,
    /// Voting ended without meeting quorum, or without meeting the approval ratio.
    Defeated,
    /// Voting ended having met both quorum and approval; awaiting/allowing
    /// execution after the timelock.
    Passed,
    /// A passed proposal's action was carried out (or a signaling proposal was
    /// finalized).
    Executed,
    /// A passed proposal was not executed before its execution window lapsed; its
    /// action can no longer run.
    Expired,
}

impl GovProposalStatus {
    /// Whether the proposal has reached a resolved state (voting concluded), so a
    /// voter may reclaim their locked weight. `Active` is the only non-resolved
    /// status.
    pub fn is_resolved(self) -> bool {
        !matches!(self, Self::Active)
    }
}

/// One voter's choice on a proposal (Phase 13c, §15).
///
/// `Yes` and `No` are the decisive votes that determine the approval ratio;
/// `Abstain` counts toward quorum (participation) but not toward the ratio, so a
/// holder can signal presence without pushing the outcome either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteChoice {
    /// Support the proposal.
    Yes,
    /// Oppose the proposal.
    No,
    /// Participate (count toward quorum) without supporting or opposing.
    Abstain,
}

/// Canonical proposal record (Phase 13c, §15).
///
/// Keyed in [`crate::ChainState::governance_proposals`] by [`ProposalId`]. Holds
/// the owning instance, the proposer, the SNAPSHOT of the weight token and rule
/// set captured at open time (so vote/resolve never re-read the instance and a
/// proposal is judged by the rules in force when it opened), the bounded typed
/// action, the epoch bounds, the execution-availability epoch (set on pass), the
/// lifecycle status, and the running weight tallies.
///
/// Invariant: `yes`, `no`, and `abstain` each equal the sum of every locked
/// [`VoteRecord::weight`] for this proposal with the matching [`VoteChoice`]; each
/// tally only grows while `Active` and is frozen once resolved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    /// Instance this proposal belongs to (its treasury is the payout source).
    pub instance_id: GovernanceInstanceId,
    /// Account that opened the proposal (met the proposal threshold at open).
    pub proposer: Address,
    /// Weight token snapshot: the token whose locked units are this proposal's
    /// votes (copied from the instance at open; immutable).
    pub weight_token: TokenId,
    /// Rule-set snapshot captured at open (quorum, approval, timelock, voting
    /// period). Immutable for the proposal's life.
    pub config: GovernanceConfig,
    /// The single bounded typed effect this proposal carries.
    pub action: GovernanceAction,
    /// Epoch the proposal opened.
    pub created_epoch: u64,
    /// Last epoch votes are accepted (`created_epoch + config.voting_period_epochs`).
    pub voting_ends_epoch: u64,
    /// Execution-available epoch, set to `voting_ends_epoch + config.timelock_epochs`
    /// when the proposal passes; `None` while `Active` or once `Defeated`.
    pub eta_epoch: Option<u64>,
    /// Current lifecycle status.
    pub status: GovProposalStatus,
    /// Total weight locked for `Yes`.
    pub yes: Amount,
    /// Total weight locked for `No`.
    pub no: Amount,
    /// Total weight locked for `Abstain`.
    pub abstain: Amount,
}

impl Proposal {
    /// Total decisive-and-participating weight cast (`yes + no + abstain`), used as
    /// the quorum numerator. Checked addition; overflow returns
    /// [`ChainError::ArithmeticOverflow`].
    pub fn total_weight(&self) -> Result<Amount, ChainError> {
        self.yes
            .checked_add(self.no)
            .and_then(|partial| partial.checked_add(self.abstain))
            .ok_or(ChainError::ArithmeticOverflow)
    }

    /// Whether the running tallies meet quorum against `issued_supply`.
    ///
    /// Exact integer test `(yes+no+abstain) * 10_000 >= issued_supply * quorum_bps`,
    /// computed with `checked_mul` on both sides (never floating point). Overflow of
    /// either product returns [`ChainError::ArithmeticOverflow`] (only reachable for
    /// an absurdly large supply). A `quorum_bps` of 0 makes quorum trivially met.
    pub fn quorum_met(&self, issued_supply: Amount) -> Result<bool, ChainError> {
        let numerator = self
            .total_weight()?
            .0
            .checked_mul(u128::from(MAX_GOVERNANCE_BPS))
            .ok_or(ChainError::ArithmeticOverflow)?;
        let threshold = issued_supply
            .0
            .checked_mul(u128::from(self.config.quorum_bps))
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(numerator >= threshold)
    }

    /// Whether the running tallies meet the approval ratio.
    ///
    /// Exact integer test `yes * 10_000 >= (yes + no) * approval_threshold_bps`,
    /// computed with `checked_mul` on both sides (never floating point). Abstentions
    /// are excluded from the ratio. Overflow of either product returns
    /// [`ChainError::ArithmeticOverflow`].
    pub fn approval_met(&self) -> Result<bool, ChainError> {
        let numerator = self
            .yes
            .0
            .checked_mul(u128::from(MAX_GOVERNANCE_BPS))
            .ok_or(ChainError::ArithmeticOverflow)?;
        let decisive = self
            .yes
            .checked_add(self.no)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let threshold = decisive
            .0
            .checked_mul(u128::from(self.config.approval_threshold_bps))
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(numerator >= threshold)
    }
}

/// One voter's locked weight on one proposal (Phase 13c, §15).
///
/// Keyed in [`crate::ChainState::governance_votes`] by `(ProposalId, voter)`.
/// Records the voter's `choice` and the `weight` (weight-token units) they LOCKED
/// into the proposal's escrow. The presence of this record is what prevents a
/// second vote from the same voter (double-vote protection); its `weight` is the
/// immutable amount returned on reclaim. A reclaim removes the record, so the map
/// holds exactly the currently-locked votes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VoteRecord {
    /// The voter's choice (fixed at vote time).
    pub choice: VoteChoice,
    /// Weight-token units locked into the proposal escrow for this vote.
    pub weight: Amount,
}

// deferred: standing (per-account) vote DELEGATION is intentionally NOT built in
// this pass. Under lock-to-vote, weight is proven by MOVING tokens into a
// per-proposal escrow; a delegate can only lock tokens it actually holds. A clean
// standing delegation would therefore require either (a) letting a delegate move a
// delegator's tokens without a per-proposal signature, which breaks custody and
// the "weight == self-locked amount" model, or (b) tracking delegated weight
// separately from locked balances, which reintroduces exactly the mutable,
// snapshot-manipulable weight that lock-to-vote exists to eliminate. Neither stays
// clean, so delegation is deferred rather than shipped broken; a future pass may
// add it as an explicit, separately-escrowed primitive.

#[cfg(test)]
mod tests {
    use super::*;
    use webc_crypto::Keypair;

    fn creator() -> Address {
        Keypair::from_seed([61u8; 32]).address()
    }

    fn sample_config() -> GovernanceConfig {
        GovernanceConfig {
            voting_period_epochs: 10,
            timelock_epochs: 3,
            quorum_bps: 2_000,
            proposal_threshold: Amount::from_units(100),
            approval_threshold_bps: 5_000,
        }
    }

    fn sample_token() -> TokenId {
        TokenId::new(Hash256([0x2a; 32]))
    }

    #[test]
    fn instance_id_derivation_is_deterministic_and_input_separated() {
        let ns = Hash256([0x55; 32]);
        let c = creator();
        assert_eq!(
            GovernanceInstanceId::derive(ns, c, 0),
            GovernanceInstanceId::derive(ns, c, 0)
        );
        assert_ne!(
            GovernanceInstanceId::derive(ns, c, 0),
            GovernanceInstanceId::derive(ns, c, 1)
        );
        assert_ne!(
            GovernanceInstanceId::derive(ns, c, 0),
            GovernanceInstanceId::derive(Hash256([0x56; 32]), c, 0)
        );
        let other = Keypair::from_seed([62u8; 32]).address();
        assert_ne!(
            GovernanceInstanceId::derive(ns, c, 0),
            GovernanceInstanceId::derive(ns, other, 0)
        );
        // Domain-separated from the bare creator bytes.
        assert_ne!(GovernanceInstanceId::derive(ns, c, 0).hash().0, c.0);
    }

    #[test]
    fn proposal_id_derivation_is_deterministic_and_nonce_separated() {
        let instance = GovernanceInstanceId::new(Hash256([0x11; 32]));
        assert_eq!(ProposalId::derive(instance, 0), ProposalId::derive(instance, 0));
        assert_ne!(ProposalId::derive(instance, 0), ProposalId::derive(instance, 1));
        let other = GovernanceInstanceId::new(Hash256([0x12; 32]));
        assert_ne!(ProposalId::derive(instance, 0), ProposalId::derive(other, 0));
    }

    #[test]
    fn escrow_address_is_deterministic_per_proposal_and_not_a_keypair_address() {
        let a = ProposalId::new(Hash256([0x01; 32]));
        let b = ProposalId::new(Hash256([0x02; 32]));
        assert_eq!(gov_vote_escrow_address(a), gov_vote_escrow_address(a));
        assert_ne!(gov_vote_escrow_address(a), gov_vote_escrow_address(b));
        // The escrow is domain-separated from the raw proposal id bytes and from
        // any real (public-key-derived) account address.
        assert_ne!(gov_vote_escrow_address(a).0, a.hash().0);
    }

    #[test]
    fn config_validation_bounds_are_enforced() {
        sample_config().validate().expect("sample config is valid");
        // Zero voting period rejected.
        let mut cfg = sample_config();
        cfg.voting_period_epochs = 0;
        assert!(matches!(
            cfg.validate(),
            Err(ChainError::InvalidGovernanceConfig)
        ));
        // Over-range quorum rejected.
        let mut cfg = sample_config();
        cfg.quorum_bps = MAX_GOVERNANCE_BPS + 1;
        assert!(matches!(
            cfg.validate(),
            Err(ChainError::InvalidGovernanceConfig)
        ));
        // Over-range approval rejected.
        let mut cfg = sample_config();
        cfg.approval_threshold_bps = MAX_GOVERNANCE_BPS + 1;
        assert!(matches!(
            cfg.validate(),
            Err(ChainError::InvalidGovernanceConfig)
        ));
    }

    #[test]
    fn quorum_and_approval_are_exact_integer_ratios() {
        let mut proposal = Proposal {
            instance_id: GovernanceInstanceId::new(Hash256([0x11; 32])),
            proposer: creator(),
            weight_token: sample_token(),
            config: sample_config(),
            action: GovernanceAction::Signaling,
            created_epoch: 1,
            voting_ends_epoch: 11,
            eta_epoch: None,
            status: GovProposalStatus::Active,
            yes: Amount::from_units(150),
            no: Amount::from_units(50),
            abstain: Amount::ZERO,
        };
        // quorum_bps = 2000 (20%). Supply 1000 -> need >= 200 participation.
        // 200 participation exactly meets it.
        assert!(proposal.quorum_met(Amount::from_units(1_000)).unwrap());
        // One less participant fails quorum.
        proposal.no = Amount::from_units(49);
        assert!(!proposal.quorum_met(Amount::from_units(1_000)).unwrap());
        // approval_threshold_bps = 5000 (50%). yes/(yes+no) = 150/199 > 50%.
        assert!(proposal.approval_met().unwrap());
        // A tie is exactly the 50% boundary and passes (>=).
        proposal.yes = Amount::from_units(50);
        proposal.no = Amount::from_units(50);
        assert!(proposal.approval_met().unwrap());
        // Just below 50% fails.
        proposal.yes = Amount::from_units(49);
        assert!(!proposal.approval_met().unwrap());
    }

    #[test]
    fn instance_round_trips_and_rejects_unknown_fields() {
        let instance =
            GovernanceInstance::new(creator(), sample_token(), sample_config()).expect("valid");
        assert_eq!(instance.treasury, Amount::ZERO);
        assert_eq!(instance.next_proposal_nonce, 0);
        let text = serde_json::to_string(&instance).expect("serializes");
        let decoded: GovernanceInstance = serde_json::from_str(&text).expect("decodes");
        assert_eq!(decoded, instance);
        let mut value = serde_json::to_value(&instance).expect("to value");
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<GovernanceInstance>(value).is_err());
    }

    #[test]
    fn action_round_trips_and_rejects_unknown_fields() {
        let action = GovernanceAction::TreasuryTransfer {
            recipient: creator(),
            amount: Amount::from_units(42),
        };
        let text = serde_json::to_string(&action).expect("serializes");
        let decoded: GovernanceAction = serde_json::from_str(&text).expect("decodes");
        assert_eq!(decoded, action);
        let mut value = serde_json::to_value(&action).expect("to value");
        value["TreasuryTransfer"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<GovernanceAction>(value).is_err());
    }
}
