//! WEBC Phase 6 sharded examples: parallel execution and namespace isolation.
//!
//! Purpose: demonstrate and ASSERT the core WEBC scheduling property —
//! "unrelated sites and applications do not block each other at the state
//! scheduler" (AGENTS.md "Parallelism and application isolation"). Independent
//! activity is grouped into ONE parallel batch by
//! [`parallel_batches`](webc_chain::parallel_batches); genuinely-conflicting
//! activity is forced into separate, correctly-ordered batches.
//!
//! Responsibilities: exercise the public `webc-chain` API only (no `src/`
//! edits), across the four application classes the Phase 6 plan names —
//! tokens, games, swaps, and site sessions — each built from the CURRENT
//! primitives:
//!
//! * tokens: native [`Operation::Transfer`] between accounts.
//! * games: owned objects in distinct application namespaces via
//!   `CreateObject` / `MutateObject`.
//! * swaps: declared access lists over objects/namespaces (modeled at the
//!   scheduler level; see the swaps note).
//! * site sessions: owned per-user session objects in per-user namespaces.
//!
//! Non-responsibilities: this file does NOT implement sponsors, a DEX/AMM,
//! token contracts, or shared-object mutation — those are later phases. It
//! never asserts a concrete state-root/hash value (only behavior), and it is
//! fully deterministic: every key comes from a fixed seed and every namespace
//! from fixed bytes, so there is no wall-clock or RNG input.
//!
//! Data flow: build funded [`ChainState`] via the public `accounts` map ->
//! sign transactions with fixed-seed keypairs -> assert the batch structure
//! from `parallel_batches` -> where the primitive supports it, apply the batch
//! through [`ChainState::execute_transaction`] and assert the result is
//! order-independent (running a non-conflicting batch forwards and backwards
//! lands on byte-identical state) and that conflicting work refuses to reorder.
//!
//! Security boundary: none. These are integration examples over the public API;
//! they add no trust and assert scheduling/execution behavior the protocol
//! already guarantees.

use webc_chain::{
    parallel_batches, AccessList, Account, Amount, ChainConfig, ChainError, ChainState, FeeBid,
    ObjectId, ObjectVersion, Operation, StateKey, Transaction,
};
use webc_crypto::{Hash256, Keypair};

// ------------------------------- shared helpers ------------------------------

/// A deterministic keypair from a single seed byte, so every actor in these
/// examples has a stable, readable identity.
fn actor(seed: u8) -> Keypair {
    Keypair::from_seed([seed; 32])
}

/// Fresh empty state plus its config. The base fee is the config minimum, so
/// fee accounting is deterministic across every example.
fn empty_state() -> (ChainConfig, ChainState) {
    let config = ChainConfig::default();
    let state = ChainState::new(&config).expect("empty state for supported config");
    (config, state)
}

/// Funds `who` with `amount` liquid native balance in the public account map.
///
/// The `accounts` map is part of the crate's public surface, so an example can
/// seed balances without a full genesis. Each account starts at nonce zero.
fn fund(state: &mut ChainState, who: &Keypair, amount: Amount) {
    state
        .accounts
        .insert(who.address(), Account::with_balance(amount));
}

/// A generous per-actor balance: far above any fee or storage deposit these
/// examples incur, so nothing fails for lack of funds and the scheduling
/// property is what is under test.
fn generous() -> Amount {
    Amount::from_webc(1)
}

/// The transaction fee bid used for native transfers (a `Transfer` costs 500
/// execution units; this bid covers it at the minimum base fee).
fn transfer_fee() -> FeeBid {
    FeeBid {
        gas_limit: 1_000,
        max_fee_per_unit: 1,
        priority_fee_per_unit: 0,
    }
}

/// The transaction fee bid used for object operations (`CreateObject` /
/// `MutateObject` each cost 20,000 execution units).
fn object_fee() -> FeeBid {
    FeeBid {
        gas_limit: 30_000,
        max_fee_per_unit: 1,
        priority_fee_per_unit: 0,
    }
}

/// Returns the batch index that `tx_index` was scheduled into.
fn batch_of(batches: &[Vec<usize>], tx_index: usize) -> usize {
    batches
        .iter()
        .position(|batch| batch.contains(&tx_index))
        .expect("every transaction is scheduled into exactly one batch")
}

/// Applies every transaction in order and returns the resulting state, so two
/// orderings of a non-conflicting batch can be compared for equality.
fn apply_in_order(base: &ChainState, config: &ChainConfig, txs: &[&Transaction]) -> ChainState {
    let mut state = base.clone();
    for tx in txs {
        state
            .execute_transaction(tx, config)
            .expect("independent transaction applies cleanly");
    }
    state
}

/// Signs a `CreateObject` for `owner` and applies it, so later examples can
/// mutate an object that already exists.
fn create_object(
    state: &mut ChainState,
    config: &ChainConfig,
    owner: &Keypair,
    nonce: u64,
    object_id: ObjectId,
    namespace: Hash256,
    data: &[u8],
) {
    let tx = Transaction::for_operation(
        owner,
        nonce,
        Operation::CreateObject {
            object_id,
            namespace,
            data: data.to_vec(),
        },
        object_fee(),
    )
    .expect("create-object signs");
    state
        .execute_transaction(&tx, config)
        .expect("object is created");
}

// =============================================================================
// Scenario 1 — TOKENS: independent native transfers run in parallel; two
// transfers from the SAME sender serialize on that sender's account/nonce lane.
// =============================================================================

#[test]
fn tokens_disjoint_transfers_share_one_parallel_batch_and_are_order_independent() {
    // Four unrelated payments between four disjoint sender/recipient pairs — the
    // everyday "unrelated sites paying each other" case. No two transactions
    // write a common account, so the scheduler must place all four in a single
    // parallel batch.
    let (config, mut state) = empty_state();
    let senders: Vec<Keypair> = [10u8, 11, 12, 13].iter().map(|s| actor(*s)).collect();
    let recipients: Vec<Keypair> = [20u8, 21, 22, 23].iter().map(|s| actor(*s)).collect();
    let amount = generous(); // each sender moves exactly 1 WEBC to a fresh account
    for sender in &senders {
        // Fund each sender with enough for the amount plus the small fee.
        fund(&mut state, sender, amount.checked_add(generous()).unwrap());
    }

    let txs: Vec<Transaction> = senders
        .iter()
        .zip(&recipients)
        .map(|(sender, recipient)| {
            Transaction::for_operation(
                sender,
                0,
                Operation::Transfer {
                    to: recipient.address(),
                    amount,
                },
                transfer_fee(),
            )
            .expect("transfer signs")
        })
        .collect();

    // Independent ⇒ one batch holding every index.
    let batches = parallel_batches(&txs);
    assert_eq!(
        batches,
        vec![vec![0, 1, 2, 3]],
        "four disjoint transfers must all schedule into a single parallel batch"
    );

    // Deterministic execution: because the batch has no conflicts, applying it
    // forwards and in reverse must reach byte-identical state — the concrete
    // proof that these transactions are safe to run in any order / in parallel.
    let forward_refs: Vec<&Transaction> = txs.iter().collect();
    let reverse_refs: Vec<&Transaction> = txs.iter().rev().collect();
    let forward = apply_in_order(&state, &config, &forward_refs);
    let reverse = apply_in_order(&state, &config, &reverse_refs);
    assert_eq!(
        forward, reverse,
        "a conflict-free batch reaches the same state regardless of order"
    );

    // Each fresh recipient ends holding exactly the transferred amount.
    for recipient in &recipients {
        assert_eq!(
            forward
                .accounts
                .get(&recipient.address())
                .expect("recipient account was created")
                .balance,
            amount,
        );
    }
}

#[test]
fn tokens_same_sender_transfers_serialize_in_nonce_order() {
    // Two payments from ONE sender genuinely conflict: both write that sender's
    // account and fee lane, and they are nonce-ordered. The scheduler must split
    // them into separate, ordered batches, and execution must refuse to reorder
    // them.
    let (config, mut state) = empty_state();
    let sender = actor(30);
    let first_to = actor(31);
    let second_to = actor(32);
    fund(&mut state, &sender, Amount::from_webc(4));

    let amount = generous();
    let first = Transaction::for_operation(
        &sender,
        0,
        Operation::Transfer {
            to: first_to.address(),
            amount,
        },
        transfer_fee(),
    )
    .expect("first transfer signs");
    let second = Transaction::for_operation(
        &sender,
        1,
        Operation::Transfer {
            to: second_to.address(),
            amount,
        },
        transfer_fee(),
    )
    .expect("second transfer signs");

    // Conflicting ⇒ two batches, and the earlier nonce commits first.
    let batches = parallel_batches(&[first.clone(), second.clone()]);
    assert_eq!(batches, vec![vec![0], vec![1]]);
    assert!(
        batch_of(&batches, 0) < batch_of(&batches, 1),
        "the nonce-0 transfer must be ordered before the nonce-1 transfer"
    );

    // Executing the later nonce first is rejected: the serialization the
    // scheduler enforces is a real ordering requirement, not a hint.
    let mut out_of_order = state.clone();
    assert!(
        matches!(
            out_of_order.execute_transaction(&second, &config),
            Err(ChainError::NonceMismatch { .. })
        ),
        "the second transfer cannot commit before the first"
    );

    // In nonce order both commit and both recipients are paid.
    state.execute_transaction(&first, &config).expect("first");
    state.execute_transaction(&second, &config).expect("second");
    assert_eq!(
        state.accounts.get(&first_to.address()).unwrap().balance,
        amount
    );
    assert_eq!(
        state.accounts.get(&second_to.address()).unwrap().balance,
        amount
    );
    assert_eq!(state.accounts.get(&sender.address()).unwrap().nonce, 2);
}

// =============================================================================
// Scenario 2 — GAMES: each game owns an object in its own namespace, played by
// its own account. Moves in DIFFERENT games run in parallel; two moves in the
// SAME game serialize on that game's object.
// =============================================================================

/// Three games, each owned by a distinct player in a distinct namespace with a
/// distinct object. Returns (config, post-setup state, players, per-game ids).
#[allow(clippy::type_complexity)]
fn three_games() -> (
    ChainConfig,
    ChainState,
    Vec<Keypair>,
    Vec<(ObjectId, Hash256)>,
) {
    let (config, mut state) = empty_state();
    let players: Vec<Keypair> = [40u8, 41, 42].iter().map(|s| actor(*s)).collect();
    let games: Vec<(ObjectId, Hash256)> = (0..players.len())
        .map(|i| {
            (
                ObjectId::new(Hash256::digest_many([b"game-object", &[i as u8]])),
                Hash256::digest_many([b"game-namespace", &[i as u8]]),
            )
        })
        .collect();
    for (player, (object_id, namespace)) in players.iter().zip(&games) {
        fund(&mut state, player, generous());
        // Each game's opening position is created at nonce 0 (version 1).
        create_object(
            &mut state, &config, player, 0, *object_id, *namespace, b"p1",
        );
    }
    (config, state, players, games)
}

#[test]
fn games_moves_in_distinct_games_share_one_parallel_batch() {
    // One move per game: player i advances game i's object. The games share no
    // account, object, or namespace, so all three moves schedule in parallel and
    // execute order-independently.
    let (config, state, players, games) = three_games();

    let moves: Vec<Transaction> = players
        .iter()
        .zip(&games)
        .map(|(player, (object_id, namespace))| {
            Transaction::for_operation(
                player,
                1, // nonce 1: nonce 0 created the object
                Operation::MutateObject {
                    object_id: *object_id,
                    namespace: *namespace,
                    expected_version: ObjectVersion::INITIAL,
                    data: b"p2".to_vec(),
                },
                object_fee(),
            )
            .expect("game move signs")
        })
        .collect();

    let batches = parallel_batches(&moves);
    assert_eq!(
        batches,
        vec![vec![0, 1, 2]],
        "moves across distinct games must all land in one parallel batch"
    );

    // Order-independent: forwards and backwards reach identical state.
    let forward_refs: Vec<&Transaction> = moves.iter().collect();
    let reverse_refs: Vec<&Transaction> = moves.iter().rev().collect();
    let forward = apply_in_order(&state, &config, &forward_refs);
    let reverse = apply_in_order(&state, &config, &reverse_refs);
    assert_eq!(forward, reverse);

    // Every game advanced to revision two.
    for (object_id, _) in &games {
        assert_eq!(
            forward.objects.get(object_id).expect("game object").version,
            ObjectVersion::new(2),
        );
    }
}

#[test]
fn games_two_moves_in_the_same_game_serialize_on_its_object() {
    // Two moves in ONE game by its owner both write the same object (and the same
    // account), and each expects the revision the previous move produced. The
    // scheduler serializes them and execution refuses to apply them out of order.
    let (config, mut state, players, games) = three_games();
    let player = &players[0];
    let (object_id, namespace) = games[0];

    let move_one = Transaction::for_operation(
        player,
        1,
        Operation::MutateObject {
            object_id,
            namespace,
            expected_version: ObjectVersion::INITIAL, // v1 -> v2
            data: b"p2".to_vec(),
        },
        object_fee(),
    )
    .expect("first move signs");
    let move_two = Transaction::for_operation(
        player,
        2,
        Operation::MutateObject {
            object_id,
            namespace,
            expected_version: ObjectVersion::new(2), // v2 -> v3
            data: b"p3".to_vec(),
        },
        object_fee(),
    )
    .expect("second move signs");

    let batches = parallel_batches(&[move_one.clone(), move_two.clone()]);
    assert_eq!(batches, vec![vec![0], vec![1]]);
    assert!(batch_of(&batches, 0) < batch_of(&batches, 1));

    // Applying the second move first is rejected (its nonce is not yet due),
    // confirming the ordering is mandatory.
    let mut wrong = state.clone();
    assert!(matches!(
        wrong.execute_transaction(&move_two, &config),
        Err(ChainError::NonceMismatch { .. })
    ));

    // In order, the game advances v1 -> v2 -> v3.
    state
        .execute_transaction(&move_one, &config)
        .expect("first move");
    state
        .execute_transaction(&move_two, &config)
        .expect("second move");
    assert_eq!(
        state.objects.get(&object_id).unwrap().version,
        ObjectVersion::new(3),
    );
}

// =============================================================================
// Scenario 3 — SWAPS: a swap touches two objects in two namespaces. Swaps over
// disjoint objects run in parallel; two swaps sharing one object serialize.
//
// SIMPLIFICATION (noted per the Phase 6 scope): the current protocol has no
// native swap / atomic two-sided settlement operation — a real DEX with
// shared-pool mutation is a later phase. So a "swap" is modeled here at the
// SCHEDULER level: a transaction whose DECLARED access list names the two
// objects/namespaces the swap would touch. This asserts exactly the property
// the parallel executor consumes — `parallel_batches` groups purely on declared
// access — without inventing an execution path the primitives do not yet
// support. (Single-object activity is executed end-to-end in the other three
// scenarios.)
// =============================================================================

/// Builds a swap-shaped transaction: a carrier operation whose declared write
/// set is the swapper's account plus the two namespace "sides" of the swap.
fn swap_tx(swapper: &Keypair, side_a: Hash256, side_b: Hash256) -> Transaction {
    // A fixed local slot within each application namespace stands in for the
    // pool/ledger entry the swap would touch on that side.
    let slot = Hash256::digest(b"swap-slot");
    let access = AccessList::new(
        Vec::new(),
        vec![
            StateKey::account(swapper.address()),
            StateKey::application(side_a, slot),
            StateKey::application(side_b, slot),
        ],
    );
    // The carrier operation is irrelevant to scheduling (only the access list is
    // read by `parallel_batches`); a self-transfer keeps it inert.
    Transaction::new_unsigned(
        swapper.address(),
        swapper.public_key(),
        0,
        Operation::Transfer {
            to: swapper.address(),
            amount: Amount::from_units(1),
        },
        access,
        transfer_fee(),
    )
}

#[test]
fn swaps_over_disjoint_objects_share_one_parallel_batch() {
    // Two unrelated swaps: one between the GOLD and USD namespaces, one between
    // the ETH and DAI namespaces, by two different parties. No side is shared, so
    // both swaps schedule in parallel — unrelated markets do not block each other.
    let gold = Hash256::digest(b"ns-gold");
    let usd = Hash256::digest(b"ns-usd");
    let eth = Hash256::digest(b"ns-eth");
    let dai = Hash256::digest(b"ns-dai");

    let swap_one = swap_tx(&actor(50), gold, usd);
    let swap_two = swap_tx(&actor(51), eth, dai);

    assert_eq!(
        parallel_batches(&[swap_one, swap_two]),
        vec![vec![0, 1]],
        "swaps over disjoint namespaces must run in parallel"
    );
}

#[test]
fn swaps_sharing_one_object_serialize() {
    // Two swaps that both touch the GOLD namespace's shared slot genuinely
    // conflict on that object and must be serialized into separate, ordered
    // batches — a genuinely shared market serializes even though the two swaps
    // are otherwise unrelated.
    let gold = Hash256::digest(b"ns-gold");
    let usd = Hash256::digest(b"ns-usd");
    let eur = Hash256::digest(b"ns-eur");

    let swap_one = swap_tx(&actor(52), gold, usd); // GOLD <-> USD
    let swap_two = swap_tx(&actor(53), gold, eur); // GOLD <-> EUR  (shares GOLD)

    let batches = parallel_batches(&[swap_one, swap_two]);
    assert_eq!(batches, vec![vec![0], vec![1]]);
    assert!(
        batch_of(&batches, 0) < batch_of(&batches, 1),
        "the swap that touches the shared object first is ordered first"
    );
}

// =============================================================================
// Scenario 4 — SITE SESSIONS: each user owns a private session object in their
// own namespace. Many users' sessions run fully in parallel; contention on one
// SHARED session object serializes.
// =============================================================================

#[test]
fn site_sessions_private_per_user_sessions_run_fully_in_parallel() {
    // Four users each own a private session object in their own namespace and
    // each advance their own session once. Nothing is shared, so all four session
    // updates schedule in one parallel batch and execute order-independently —
    // "many users each with their own session" never block one another.
    let (config, mut state) = empty_state();
    let users: Vec<Keypair> = [60u8, 61, 62, 63].iter().map(|s| actor(*s)).collect();
    let sessions: Vec<(ObjectId, Hash256)> = (0..users.len())
        .map(|i| {
            (
                ObjectId::new(Hash256::digest_many([b"session-object", &[i as u8]])),
                Hash256::digest_many([b"session-namespace", &[i as u8]]),
            )
        })
        .collect();
    for (user, (object_id, namespace)) in users.iter().zip(&sessions) {
        fund(&mut state, user, generous());
        create_object(&mut state, &config, user, 0, *object_id, *namespace, b"s1");
    }

    let updates: Vec<Transaction> = users
        .iter()
        .zip(&sessions)
        .map(|(user, (object_id, namespace))| {
            Transaction::for_operation(
                user,
                1,
                Operation::MutateObject {
                    object_id: *object_id,
                    namespace: *namespace,
                    expected_version: ObjectVersion::INITIAL,
                    data: b"s2".to_vec(),
                },
                object_fee(),
            )
            .expect("session update signs")
        })
        .collect();

    let batches = parallel_batches(&updates);
    assert_eq!(
        batches,
        vec![vec![0, 1, 2, 3]],
        "distinct users' private sessions must all schedule in parallel"
    );

    let forward_refs: Vec<&Transaction> = updates.iter().collect();
    let reverse_refs: Vec<&Transaction> = updates.iter().rev().collect();
    let forward = apply_in_order(&state, &config, &forward_refs);
    let reverse = apply_in_order(&state, &config, &reverse_refs);
    assert_eq!(
        forward, reverse,
        "independent session updates are order-independent"
    );
    for (object_id, _) in &sessions {
        assert_eq!(
            forward.objects.get(object_id).unwrap().version,
            ObjectVersion::new(2),
        );
    }
}

#[test]
fn site_sessions_contention_on_one_shared_session_serializes() {
    // A single SHARED session object (for example a shared room) that two
    // different users both try to update. Both declare a write to the same object
    // and namespace, so the scheduler forces them into separate, ordered batches
    // — contention on shared session state serializes.
    //
    // SIMPLIFICATION: under the current owned-object rules only the object's
    // owner may successfully mutate it, so two DIFFERENT users cannot both apply
    // a write end-to-end (shared-object mutation is a later phase). The conflict
    // and its ordering are therefore asserted at the scheduler level — exactly
    // the isolation guarantee the parallel executor relies on.
    let shared_object = ObjectId::new(Hash256::digest(b"shared-session-object"));
    let shared_namespace = Hash256::digest(b"shared-session-namespace");

    let update = |seed: u8, expected: ObjectVersion| {
        Transaction::for_operation(
            &actor(seed),
            0,
            Operation::MutateObject {
                object_id: shared_object,
                namespace: shared_namespace,
                expected_version: expected,
                data: b"shared".to_vec(),
            },
            object_fee(),
        )
        .expect("shared session update signs")
    };
    let user_x = update(70, ObjectVersion::INITIAL);
    let user_y = update(71, ObjectVersion::INITIAL);

    let batches = parallel_batches(&[user_x, user_y]);
    assert_eq!(batches, vec![vec![0], vec![1]]);
    assert!(
        batch_of(&batches, 0) < batch_of(&batches, 1),
        "two updates to one shared session object cannot share a batch"
    );
}
