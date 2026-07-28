//! Bounded durable state for protocol-2 sponsor grants.
//!
//! Purpose: keep sponsor replay, budget, revocation, and expiry records behind
//! one invariant-preserving boundary. Responsibilities: validate every stored
//! record, maintain a deterministic derived expiry index, bound cleanup work per
//! block, and prune expired records in consensus order. It does not
//! verify transaction signatures, authorize revocations, debit fees, or choose
//! a block height; those remain transaction/execution responsibilities.
//!
//! Data flows from a fully validated execution effect into `set`, is serialized
//! as the primary ordered record map, and rebuilds the derived index on load.
//! Security boundary: callers cannot mutate the map or index independently,
//! invalid counters/digests fail closed, and cleanup never performs more than
//! the fixed consensus work limit in one block.

use crate::{
    Amount, BlockHeight, SponsorGrantId, SponsorUseCount, SponsorUseNonce,
    REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS, SPONSOR_GRANT_USE_V1_REQUIRED_UNITS,
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use webc_crypto::{Address, Hash256};

/// Maximum expired grant records removed at one consensus block boundary.
///
/// Admission deliberately has no shared per-expiry capacity: such a capacity
/// would let an attacker reserve all slots at a height and would create a hidden
/// conflict between otherwise independent grant keys. Materialization units
/// bound ingress while this value bounds deterministic cleanup work. It is a
/// protocol-2 activation parameter and must be benchmarked before activation.
pub const MAX_SPONSOR_GRANT_PRUNES_PER_BLOCK_V1: usize = 256;

/// Required cleanup headroom over maximum per-block grant materialization.
///
/// A value of four means one block's worst-case new records must be removable
/// within at most one quarter of the fixed pruning capacity. Protocol-2 genesis
/// rejects a block-unit policy that violates this relationship, preventing a
/// configuration change from turning bounded cleanup into permanent growth.
pub const SPONSOR_GRANT_PRUNE_HEADROOM_V1: u64 = 4;

/// Returns whether one protocol-2 block-unit policy preserves cleanup headroom.
pub(crate) fn pruning_capacity_covers_maximum_ingress(max_block_units: u64) -> bool {
    let minimum_materialization_units =
        REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS.min(SPONSOR_GRANT_USE_V1_REQUIRED_UNITS);
    let maximum_materializations = max_block_units / minimum_materialization_units;
    let Some(required_prunes) =
        maximum_materializations.checked_mul(SPONSOR_GRANT_PRUNE_HEADROOM_V1)
    else {
        return false;
    };
    u64::try_from(MAX_SPONSOR_GRANT_PRUNES_PER_BLOCK_V1)
        .is_ok_and(|available_prunes| required_prunes <= available_prunes)
}

/// Durable replay, fee-budget, use-count, revocation, and lifetime state.
///
/// Invariants: `grant_digest` is non-zero, `next_use_nonce == uses`, and
/// `valid_until_height` is the authenticated inclusive expiry from the complete
/// signed grant. Absence is represented by no map entry, never by an incomplete
/// tombstone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorGrantStateV1 {
    /// Domain-separated digest of the complete signed immutable grant.
    pub grant_digest: Hash256,
    /// Inclusive last consensus height at which the grant can authorize a use.
    pub valid_until_height: BlockHeight,
    /// Exact use nonce required by the next includable sponsored transaction.
    pub next_use_nonce: SponsorUseNonce,
    /// Actual native base units charged across all included uses.
    pub total_charged: Amount,
    /// Number of included uses, including chargeable action failures.
    pub uses: SponsorUseCount,
    /// Owner-authorized revocation marker retained only through grant expiry.
    pub revoked: bool,
}

impl SponsorGrantStateV1 {
    /// Constructs an unused record from authenticated signed-grant identity.
    pub const fn unused(grant_digest: Hash256, valid_until_height: BlockHeight) -> Self {
        Self {
            grant_digest,
            valid_until_height,
            next_use_nonce: SponsorUseNonce::new(0),
            total_charged: Amount::ZERO,
            uses: SponsorUseCount::new(0),
            revoked: false,
        }
    }

    fn validate(self) -> Result<(), SponsorGrantBookError> {
        if self.grant_digest == Hash256::ZERO || self.next_use_nonce.get() != self.uses.get() {
            return Err(SponsorGrantBookError::InvalidRecord);
        }
        Ok(())
    }
}

type SponsorGrantKey = (Address, SponsorGrantId);
type SponsorGrantExpiryKey = (BlockHeight, Address, SponsorGrantId);

struct SponsorGrantChangePlan {
    changes: Vec<(
        SponsorGrantKey,
        Option<SponsorGrantStateV1>,
        Option<SponsorGrantStateV1>,
    )>,
}

/// Invariant-preserving primary sponsor records plus a derived expiry index.
///
/// Serialization intentionally emits only `records`. Deserialization rebuilds
/// and validates the index, so restart behavior cannot depend on stale cached
/// tuples and state commitment needs to hash only one canonical copy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SponsorGrantBookV1 {
    records: BTreeMap<SponsorGrantKey, SponsorGrantStateV1>,
    expirations: BTreeSet<SponsorGrantExpiryKey>,
}

impl SponsorGrantBookV1 {
    /// Returns one immutable durable record.
    pub fn get(&self, key: &SponsorGrantKey) -> Option<&SponsorGrantStateV1> {
        self.records.get(key)
    }

    /// Returns whether one grant identity currently has durable state.
    pub fn contains_key(&self, key: &SponsorGrantKey) -> bool {
        self.records.contains_key(key)
    }

    /// Returns the number of currently retained grant records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether no grant state is retained.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Iterates primary records in canonical `(sponsor, grant_id)` order.
    pub fn iter(&self) -> impl Iterator<Item = (&SponsorGrantKey, &SponsorGrantStateV1)> {
        self.records.iter()
    }

    /// Validates all grant identities materialized by one atomic transaction.
    ///
    /// Checking entries separately is unsafe because two actions can name
    /// different immutable grants under one replay key. This method deduplicates
    /// exact repeats and rejects conflicting digest/expiry pairs.
    pub(crate) fn ensure_can_set_batch<I>(&self, entries: I) -> Result<(), SponsorGrantBookError>
    where
        I: IntoIterator<Item = (SponsorGrantKey, SponsorGrantStateV1)>,
    {
        let mut changes: BTreeMap<SponsorGrantKey, Option<SponsorGrantStateV1>> = BTreeMap::new();
        for (key, state) in entries {
            state.validate()?;
            match changes.get(&key).copied().flatten() {
                Some(previous)
                    if previous.grant_digest != state.grant_digest
                        || previous.valid_until_height != state.valid_until_height =>
                {
                    return Err(SponsorGrantBookError::ConflictingBatchIdentity);
                }
                Some(_) => {}
                None => {
                    changes.insert(key, Some(state));
                }
            }
        }
        self.plan_changes(changes)?;
        Ok(())
    }

    /// Atomically inserts or replaces one validated primary/index record.
    pub(crate) fn set(
        &mut self,
        key: SponsorGrantKey,
        state: SponsorGrantStateV1,
    ) -> Result<(), SponsorGrantBookError> {
        self.commit_changes(BTreeMap::from([(key, Some(state))]))
    }

    /// Copies exactly one declared record into a sparse execution book.
    pub(crate) fn capture_from(
        &mut self,
        source: &Self,
        key: SponsorGrantKey,
    ) -> Result<(), SponsorGrantBookError> {
        if let Some(state) = source.records.get(&key).copied() {
            self.set(key, state)?;
        }
        Ok(())
    }

    /// Atomically commits all named sparse records (or deletions) into the base.
    pub(crate) fn commit_entries_from<I>(
        &mut self,
        source: &Self,
        keys: I,
    ) -> Result<(), SponsorGrantBookError>
    where
        I: IntoIterator<Item = SponsorGrantKey>,
    {
        let mut changes = BTreeMap::new();
        for key in keys {
            changes.insert(key, source.records.get(&key).copied());
        }
        self.commit_changes(changes)
    }

    /// Removes expired entries in canonical expiry/sponsor/id order.
    ///
    /// A grant remains valid through `valid_until_height`, so only records with
    /// an expiry strictly below `current_height` are removed. The global
    /// per-block limit bounds cleanup even when one expiry has a large backlog.
    pub(crate) fn prune_expired(
        &mut self,
        current_height: BlockHeight,
    ) -> Result<usize, SponsorGrantBookError> {
        let changes = self
            .expirations
            .iter()
            .take_while(|(expiry, _, _)| *expiry < current_height)
            .take(MAX_SPONSOR_GRANT_PRUNES_PER_BLOCK_V1)
            .map(|(_, sponsor, grant_id)| ((*sponsor, *grant_id), None))
            .collect::<BTreeMap<_, _>>();
        let removed = changes.len();
        if removed != 0 {
            self.commit_changes(changes)?;
        }
        Ok(removed)
    }

    fn commit_changes(
        &mut self,
        changes: BTreeMap<SponsorGrantKey, Option<SponsorGrantStateV1>>,
    ) -> Result<(), SponsorGrantBookError> {
        let plan = self.plan_changes(changes)?;
        for (key, previous, next) in plan.changes {
            let previous_expiry = previous.map(|state| state.valid_until_height);
            let next_expiry = next.map(|state| state.valid_until_height);
            if previous_expiry != next_expiry {
                if let Some(expiry) = previous_expiry {
                    self.expirations.remove(&(expiry, key.0, key.1));
                }
                if let Some(expiry) = next_expiry {
                    self.expirations.insert((expiry, key.0, key.1));
                }
            }
            match next {
                Some(state) => {
                    self.records.insert(key, state);
                }
                None => {
                    self.records.remove(&key);
                }
            }
        }
        Ok(())
    }

    fn plan_changes(
        &self,
        changes: BTreeMap<SponsorGrantKey, Option<SponsorGrantStateV1>>,
    ) -> Result<SponsorGrantChangePlan, SponsorGrantBookError> {
        let mut planned = Vec::with_capacity(changes.len());
        for (key, next) in changes {
            if let Some(state) = next {
                state.validate()?;
            }
            let previous = self.records.get(&key).copied();
            if let Some(state) = previous {
                state.validate()?;
                let expiry_key = (state.valid_until_height, key.0, key.1);
                if !self.expirations.contains(&expiry_key) {
                    return Err(SponsorGrantBookError::InvalidIndex);
                }
            }
            let previous_expiry = previous.map(|state| state.valid_until_height);
            let next_expiry = next.map(|state| state.valid_until_height);
            if previous_expiry != next_expiry {
                if let Some(expiry) = next_expiry {
                    if self.expirations.contains(&(expiry, key.0, key.1)) {
                        return Err(SponsorGrantBookError::InvalidIndex);
                    }
                }
            }
            planned.push((key, previous, next));
        }
        Ok(SponsorGrantChangePlan { changes: planned })
    }
}

impl Serialize for SponsorGrantBookV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.records.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SponsorGrantBookV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let records = BTreeMap::<SponsorGrantKey, SponsorGrantStateV1>::deserialize(deserializer)?;
        let mut book = Self::default();
        for (key, state) in records {
            book.set(key, state).map_err(D::Error::custom)?;
        }
        Ok(book)
    }
}

/// Internal failure proving primary/index state or one atomic batch is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SponsorGrantBookError {
    /// A primary record violates digest or replay-counter invariants.
    #[error("sponsor grant state record is invalid")]
    InvalidRecord,
    /// A derived expiry tuple disagrees with its primary record.
    #[error("sponsor grant expiry index is inconsistent")]
    InvalidIndex,
    /// One transaction assigned different immutable grants to one replay key.
    #[error("sponsor grant batch contains conflicting identities")]
    ConflictingBatchIdentity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hint::black_box;
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    };
    use std::time::{Duration, Instant};
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    use webc_crypto::Keypair;

    use crate::{
        build_block_v4, BlockBuildInputV1, ChainConfig, ChainState, Epoch, FinalityAuthoritySetV1,
        GenesisAccount, GenesisConfig, GenesisValidator, ValidatorSet,
        TRANSACTION_V5_PROTOCOL_VERSION,
    };

    fn key(seed: u8, id: u8) -> SponsorGrantKey {
        (
            Keypair::from_seed([seed; 32]).address(),
            SponsorGrantId::new(Hash256([id; 32])),
        )
    }

    fn record(digest: u8, expiry: u64) -> SponsorGrantStateV1 {
        SponsorGrantStateV1::unused(Hash256([digest; 32]), BlockHeight::new(expiry))
    }

    /// Polls the current process's resident set while the ignored capacity gate
    /// runs. RSS is allocator- and operating-system-dependent, so it is recorded
    /// as reproducible comparison evidence and never enters consensus or a
    /// public throughput claim.
    struct ResidentSetSampler {
        stop: Arc<AtomicBool>,
        peak_bytes: Arc<AtomicU64>,
        thread: std::thread::JoinHandle<()>,
    }

    impl ResidentSetSampler {
        fn start() -> Result<(Self, u64), &'static str> {
            let pid = sysinfo::get_current_pid()?;
            let mut system = System::new();
            refresh_process_memory(&mut system, pid);
            let baseline_bytes = system
                .process(pid)
                .map(sysinfo::Process::memory)
                .ok_or("current process is unavailable to the RSS sampler")?;
            let stop = Arc::new(AtomicBool::new(false));
            let peak_bytes = Arc::new(AtomicU64::new(baseline_bytes));
            let thread_stop = Arc::clone(&stop);
            let thread_peak = Arc::clone(&peak_bytes);
            let thread = std::thread::spawn(move || {
                let mut system = System::new();
                while !thread_stop.load(Ordering::Acquire) {
                    refresh_process_memory(&mut system, pid);
                    if let Some(process) = system.process(pid) {
                        thread_peak.fetch_max(process.memory(), Ordering::Relaxed);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                refresh_process_memory(&mut system, pid);
                if let Some(process) = system.process(pid) {
                    thread_peak.fetch_max(process.memory(), Ordering::Relaxed);
                }
            });
            Ok((
                Self {
                    stop,
                    peak_bytes,
                    thread,
                },
                baseline_bytes,
            ))
        }

        fn finish(self) -> Result<u64, &'static str> {
            self.stop.store(true, Ordering::Release);
            self.thread
                .join()
                .map_err(|_| "resident-set sampler thread panicked")?;
            Ok(self.peak_bytes.load(Ordering::Relaxed))
        }
    }

    fn refresh_process_memory(system: &mut System, pid: sysinfo::Pid) {
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            false,
            ProcessRefreshKind::nothing().with_memory(),
        );
    }

    fn mebibytes_with_three_decimals(bytes: u64) -> String {
        const BYTES_PER_MEBIBYTE: u128 = 1024 * 1024;
        let thousandths = u128::from(bytes) * 1_000 / BYTES_PER_MEBIBYTE;
        format!("{}.{:03}", thousandths / 1_000, thousandths % 1_000)
    }

    /// Runs the protocol-2 activation capacity gate on an optimized build.
    ///
    /// This is deliberately ignored by ordinary tests because it constructs the
    /// complete default live-set ceiling. Run with:
    /// `cargo test --release -p webc-chain sponsor_grant_capacity_benchmark -- --ignored --nocapture --test-threads=1`.
    #[test]
    #[ignore = "release-only 163,840-record capacity benchmark"]
    fn sponsor_grant_capacity_benchmark() {
        const LIVE_GRANTS: usize = 163_840;
        const EXPIRY_HEIGHT: u64 = 4_096;

        let (memory_sampler, baseline_resident_bytes) =
            ResidentSetSampler::start().expect("capacity benchmark can sample process RSS");

        let validator = Keypair::from_seed([0x71; 32]);
        let sponsor = Keypair::from_seed([0x72; 32]).address();
        let config = ChainConfig {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            ..ChainConfig::default()
        };
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: validator.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: vec![GenesisValidator {
                operator: validator.address(),
                consensus_key: validator.public_key(),
                self_stake: Amount::from_webc(100),
                commission_bps: 500,
                bootstrap: false,
            }],
        };
        let mut state = ChainState::from_genesis_v1(&genesis)
            .expect("capacity benchmark protocol-2 genesis builds");

        let populate_started = Instant::now();
        for index in 0..LIVE_GRANTS {
            let mut identity = [0u8; 32];
            identity[..8].copy_from_slice(
                &u64::try_from(index)
                    .expect("benchmark grant index fits u64")
                    .to_be_bytes(),
            );
            identity[31] = 1;
            let grant_id = SponsorGrantId::new(Hash256(identity));
            let grant_digest = Hash256::digest_many([
                b"WEBC_SPONSOR_GRANT_CAPACITY_BENCH_V1".as_slice(),
                identity.as_slice(),
            ]);
            state
                .sponsor_grants
                .set(
                    (sponsor, grant_id),
                    SponsorGrantStateV1::unused(grant_digest, BlockHeight::new(EXPIRY_HEIGHT)),
                )
                .expect("generated benchmark grant is valid");
        }
        let populate_elapsed = populate_started.elapsed();
        assert_eq!(state.sponsor_grants.len(), LIVE_GRANTS);

        let clone_started = Instant::now();
        let cloned = black_box(state.clone());
        let clone_elapsed = clone_started.elapsed();
        assert_eq!(cloned.sponsor_grants.len(), LIVE_GRANTS);
        drop(cloned);

        let root_started = Instant::now();
        let root = black_box(
            state
                .state_root()
                .expect("capacity benchmark state root computes"),
        );
        let root_elapsed = root_started.elapsed();

        let validator_set =
            ValidatorSet::from_state(&state).expect("capacity benchmark validator set derives");
        let authority_set = FinalityAuthoritySetV1::from_validator_set(
            TRANSACTION_V5_PROTOCOL_VERSION,
            state.chain_id.clone(),
            Epoch::new(0),
            &validator_set,
        )
        .expect("capacity benchmark authority set derives");
        let input = BlockBuildInputV1 {
            chain_id: state.chain_id.clone(),
            height: BlockHeight::new(1),
            epoch: Epoch::new(0),
            previous_hash: Hash256::ZERO,
            proposer: validator.address(),
            timestamp_ms: 1,
        };
        let block_started = Instant::now();
        let block = black_box(
            build_block_v4(
                &mut state,
                &config,
                input,
                Vec::new(),
                Vec::new(),
                &authority_set,
                &authority_set,
            )
            .expect("capacity benchmark V4 block executes"),
        );
        let block_elapsed = block_started.elapsed();
        assert_eq!(state.sponsor_grants.len(), LIVE_GRANTS);
        assert_eq!(
            block.header.state_root,
            state.state_root().expect("post-root")
        );
        let peak_resident_bytes = memory_sampler
            .finish()
            .expect("capacity benchmark RSS sampler stops");
        let resident_growth_bytes = peak_resident_bytes.saturating_sub(baseline_resident_bytes);

        println!("sponsor_grants={LIVE_GRANTS}");
        println!(
            "populate_ms={:.3}",
            populate_elapsed.as_secs_f64() * 1_000.0
        );
        println!("clone_ms={:.3}", clone_elapsed.as_secs_f64() * 1_000.0);
        println!("state_root_ms={:.3}", root_elapsed.as_secs_f64() * 1_000.0);
        println!(
            "block_execute_ms={:.3}",
            block_elapsed.as_secs_f64() * 1_000.0
        );
        println!(
            "baseline_resident_set_mib={}",
            mebibytes_with_three_decimals(baseline_resident_bytes)
        );
        println!(
            "peak_resident_set_mib={}",
            mebibytes_with_three_decimals(peak_resident_bytes)
        );
        println!(
            "resident_set_growth_mib={}",
            mebibytes_with_three_decimals(resident_growth_bytes)
        );
        println!("state_root={root}");
    }

    #[test]
    fn expiry_is_inclusive_and_pruning_order_is_deterministic() {
        let mut book = SponsorGrantBookV1::default();
        book.set(key(2, 2), record(2, 10)).expect("valid record");
        book.set(key(1, 1), record(1, 9)).expect("valid record");

        assert_eq!(book.prune_expired(BlockHeight::new(9)), Ok(0));
        assert_eq!(book.prune_expired(BlockHeight::new(10)), Ok(1));
        assert!(book.contains_key(&key(2, 2)));
        assert_eq!(book.prune_expired(BlockHeight::new(11)), Ok(1));
        assert!(book.is_empty());
    }

    #[test]
    fn serialization_rebuilds_the_derived_expiry_index() {
        let mut book = SponsorGrantBookV1::default();
        book.set(key(1, 1), record(1, 10)).expect("valid record");
        book.set(key(2, 2), record(2, 11)).expect("valid record");

        let bytes = bincode::serialize(&book).expect("book serializes");
        let mut restored: SponsorGrantBookV1 =
            bincode::deserialize(&bytes).expect("book deserializes");
        assert_eq!(restored, book);
        assert_eq!(restored.prune_expired(BlockHeight::new(11)), Ok(1));
        assert_eq!(restored.len(), 1);
    }

    #[test]
    fn invalid_records_fail_before_mutating_primary_or_index_state() {
        let mut book = SponsorGrantBookV1::default();
        let invalid = SponsorGrantStateV1 {
            grant_digest: Hash256::ZERO,
            ..record(1, 10)
        };
        assert_eq!(
            book.set(key(1, 1), invalid),
            Err(SponsorGrantBookError::InvalidRecord)
        );
        assert!(book.is_empty());
    }

    #[test]
    fn one_large_expiry_bucket_is_drained_in_bounded_block_steps() {
        let sponsor = Keypair::from_seed([1; 32]).address();
        let expiry = BlockHeight::new(50);
        let mut book = SponsorGrantBookV1::default();
        let record_count_beyond_removed_cap = 1_025;
        for ordinal in 0..record_count_beyond_removed_cap {
            let mut id = [0_u8; 32];
            let ordinal = u64::try_from(ordinal).expect("test cap fits u64");
            id[..8].copy_from_slice(&ordinal.to_le_bytes());
            id[8] = 1;
            book.set(
                (sponsor, SponsorGrantId::new(Hash256(id))),
                SponsorGrantStateV1::unused(Hash256([0x51; 32]), expiry),
            )
            .expect("same-expiry admission has no shared capacity");
        }

        assert_eq!(
            book.prune_expired(BlockHeight::new(51)),
            Ok(MAX_SPONSOR_GRANT_PRUNES_PER_BLOCK_V1)
        );
        assert_eq!(
            book.len(),
            record_count_beyond_removed_cap - MAX_SPONSOR_GRANT_PRUNES_PER_BLOCK_V1
        );
        let mut removed = MAX_SPONSOR_GRANT_PRUNES_PER_BLOCK_V1;
        while removed < record_count_beyond_removed_cap {
            removed += book
                .prune_expired(BlockHeight::new(52))
                .expect("bounded follow-up prune");
        }
        assert_eq!(removed, record_count_beyond_removed_cap);
        assert!(book.is_empty());
    }

    #[test]
    fn conflicting_batch_identity_fails_without_mutating_the_book() {
        let book = SponsorGrantBookV1::default();
        let shared = key(1, 1);
        let before = book.clone();

        assert_eq!(
            book.ensure_can_set_batch([(shared, record(1, 10)), (shared, record(2, 11)),]),
            Err(SponsorGrantBookError::ConflictingBatchIdentity)
        );
        assert_eq!(book, before);
    }

    #[test]
    fn sparse_batch_commit_preflights_every_record_before_mutation() {
        let mut base = SponsorGrantBookV1::default();
        base.set(key(1, 1), record(1, 10)).expect("base record");
        let before = base.clone();
        let mut source = SponsorGrantBookV1::default();
        source.records.insert(
            key(2, 2),
            SponsorGrantStateV1::unused(Hash256::ZERO, BlockHeight::new(11)),
        );

        assert_eq!(
            base.commit_entries_from(&source, [key(2, 2)]),
            Err(SponsorGrantBookError::InvalidRecord)
        );
        assert_eq!(base, before);
    }
}
