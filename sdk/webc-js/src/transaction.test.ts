/** Cross-language transaction and state-key signing fixtures. */

import { describe, expect, it } from "vitest";
import { addressToBytes } from "./address";
import { canonicalJson, canonicalJsonHashHex } from "./canonical";
import { bytesToHex } from "./hex";
import { createWalletFromSeed } from "./wallet";
import {
  bridgeBurn,
  bridgeLock,
  bridgeMint,
  bridgeRelease,
  claimDelegatorRewards,
  claimUnbonded,
  claimValidatorRewards,
  createObject,
  delegate,
  defaultAccessList,
  defaultAccessListAsync,
  deriveSessionKeyIdHex,
  fundAuthorizationLane,
  installAuthorizationPolicy,
  installSessionKey,
  openAuthorizationLane,
  mutateObject,
  registerValidator,
  revokeSessionKey,
  rotateActiveTransactionKey,
  rotatePostQuantumRoot,
  sessionKeyKey,
  signTransaction,
  sponsorStateKey,
  sponsorStateKeyHashHex,
  sponsoredAccessListAsync,
  submitSlashingEvidence,
  transactionHashHex,
  transactionSigningPayload,
  transfer,
  transferObject,
  undelegate,
  unstakeValidator,
  validateSponsor,
  verifySignedTransaction,
} from "./transaction";
import type {
  AssetIdJson,
  BridgeMessageJson,
  OperationJson,
  PostQuantumRootRevealJson,
  SessionKeyConstraintsJson,
  SignedTransactionJson,
  SlashingEvidenceJson,
} from "./types";

describe("transaction signing schema", () => {
  const defaultLane = "00".repeat(32);
  it("matches the Rust versioned transfer access-list fixture byte-for-byte", () => {
    const sender =
      "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
    const recipient =
      "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";
    const publicKey =
      "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
    const operation = transfer(recipient, "123456");
    const accessList = defaultAccessList(sender, operation);
    const payload = transactionSigningPayload(
      1,
      "webc-devnet-1",
      sender,
      publicKey,
      7,
      operation,
      accessList,
      {
        gasLimit: 1_000,
        maxFeePerUnit: 5,
        priorityFeePerUnit: 1,
      },
    );

    expect(canonicalJson(payload)).toBe(
      `{"access_list":{"read_only":[{"kind":{"Protocol":{"field":"BaseFee"}},"version":1},{"kind":{"AuthorizationPolicy":{"owner":"${sender}"}},"version":1}],"read_write":[{"kind":{"Account":{"address":"${sender}"}},"version":1},{"kind":{"Account":{"address":"${recipient}"}},"version":1},{"kind":{"FeeAccumulator":{"lane":"${defaultLane}","payer":"${sender}"}},"version":1}]},"authorization_lane":"${defaultLane}","authorization_policy_revision":0,"chain_id":"webc-devnet-1","domain":"WEBC_SIGNED_TRANSACTION_V4","fee":{"gas_limit":1000,"max_fee_per_unit":5,"priority_fee_per_unit":1},"nonce":7,"operation":{"Transfer":{"amount":"123456","to":"${recipient}"}},"protocol_version":1,"public_key":"${publicKey}","sender":"${sender}"}`,
    );
  });

  it("declares position and validator-scoped queue keys for an exit request", () => {
    const owner = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
    const validator = "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";
    const access = defaultAccessList(owner, undelegate(validator, "1000000000000"));

    expect(access.read_write).toEqual([
      { version: 1, kind: { Account: { address: owner } } },
      {
        version: 1,
        kind: { Delegation: { delegator: owner, validator } },
      },
      { version: 1, kind: { UnbondingQueue: { validator } } },
      { version: 1, kind: { FeeAccumulator: { payer: owner, lane: defaultLane } } },
    ]);
  });

  it("makes first policy installation exclusive and rejects an empty root", () => {
    const owner = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
    const operation = installAuthorizationPolicy({
      scheme: "MlDsa65",
      public_key_hash: "44".repeat(32),
    });
    expect(defaultAccessList(owner, operation)).toEqual({
      read_only: [{ version: 1, kind: { Protocol: { field: "BaseFee" } } }],
      read_write: [
        { version: 1, kind: { Account: { address: owner } } },
        { version: 1, kind: { AuthorizationPolicy: { owner } } },
        {
          version: 1,
          kind: { FeeAccumulator: { payer: owner, lane: defaultLane } },
        },
      ],
    });
    expect(() =>
      installAuthorizationPolicy({
        scheme: "MlDsa65",
        public_key_hash: "00".repeat(32),
      }),
    ).toThrow("post-quantum root");
  });

  it("binds new delegation to pending operator exits", () => {
    const owner = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
    const validator = "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";
    const access = defaultAccessList(owner, delegate(validator, "1000000000000"));

    expect(access.read_write).toEqual([
      { version: 1, kind: { Account: { address: owner } } },
      { version: 1, kind: { Validator: { operator: validator } } },
      {
        version: 1,
        kind: { Delegation: { delegator: owner, validator } },
      },
      { version: 1, kind: { UnbondingQueue: { validator } } },
      { version: 1, kind: { FeeAccumulator: { payer: owner, lane: defaultLane } } },
    ]);
  });

  it("binds operator exits to the operator pool and queue", () => {
    const operator = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
    const access = defaultAccessList(operator, unstakeValidator("1000000000000"));
    expect(access.read_write).toEqual([
      { version: 1, kind: { Account: { address: operator } } },
      { version: 1, kind: { Validator: { operator } } },
      { version: 1, kind: { UnbondingQueue: { validator: operator } } },
      { version: 1, kind: { FeeAccumulator: { payer: operator, lane: defaultLane } } },
    ]);
  });

  it("isolates a non-default lane from the account nonce and fee key", () => {
    const owner = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
    const validator = "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";
    const lane = "99".repeat(32);
    const access = defaultAccessList(owner, undelegate(validator, "1"), lane);

    expect(access.read_write).toEqual([
      { version: 1, kind: { AuthorizationLane: { owner, lane } } },
      {
        version: 1,
        kind: { Delegation: { delegator: owner, validator } },
      },
      { version: 1, kind: { UnbondingQueue: { validator } } },
      { version: 1, kind: { FeeAccumulator: { payer: owner, lane } } },
    ]);
  });

  it("isolates object mutation by lane, object, and application namespace", () => {
    const owner = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
    const lane = "99".repeat(32);
    const objectId = "33".repeat(32);
    const namespace = "55".repeat(32);
    const access = defaultAccessList(
      owner,
      mutateObject({
        objectId,
        namespace,
        expectedVersion: 1,
        data: "abcd",
      }),
      lane,
    );

    expect(access.read_write).toEqual([
      { version: 1, kind: { AuthorizationLane: { owner, lane } } },
      { version: 1, kind: { Object: { object_id: objectId } } },
      {
        version: 1,
        kind: { Application: { namespace, key_hash: objectId } },
      },
      { version: 1, kind: { FeeAccumulator: { payer: owner, lane } } },
    ]);
  });

  it("matches every Rust native-operation wire variant", async () => {
    const validator = "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";
    const externalAsset: AssetIdJson = {
      External: {
        origin_chain: "Ethereum",
        symbol: "USDC",
        contract_or_mint: "0x1234",
      },
    };
    const evidence: SlashingEvidenceJson = {
      DoubleVote: {
        first: {
          payload: {
            protocol_version: 1,
            chain_id: "webc-devnet-1",
            height: 9,
            round: 1,
            vote_type: "Precommit",
            block_hash: "10".repeat(32),
            validator,
          },
          signature: "55".repeat(64),
        },
        second: {
          payload: {
            protocol_version: 1,
            chain_id: "webc-devnet-1",
            height: 9,
            round: 1,
            vote_type: "Precommit",
            block_hash: "20".repeat(32),
            validator,
          },
          signature: "66".repeat(64),
        },
      },
    };
    const message: BridgeMessageJson = {
      source_chain: "Ethereum",
      destination_chain: "Webc",
      nonce: 9,
      asset: externalAsset,
      sender: "abcd",
      recipient: bytesToHex(addressToBytes(validator)),
      amount: "77",
      source_tx: "77".repeat(32),
    };
    const operations: OperationJson[] = [
      installAuthorizationPolicy({
        scheme: "MlDsa65",
        public_key_hash: "44".repeat(32),
      }),
      transfer(validator, "1"),
      openAuthorizationLane("99".repeat(32), "6"),
      fundAuthorizationLane("99".repeat(32), "7"),
      createObject({
        objectId: "33".repeat(32),
        namespace: "55".repeat(32),
        data: "ab",
      }),
      mutateObject({
        objectId: "33".repeat(32),
        namespace: "55".repeat(32),
        expectedVersion: 1,
        data: "cd",
      }),
      transferObject({
        objectId: "33".repeat(32),
        namespace: "55".repeat(32),
        expectedVersion: 2,
        newOwner:
          "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3",
      }),
      registerValidator({
        consensusKey: "aa".repeat(32),
        selfStake: "100",
        commissionBps: 500,
        bootstrap: false,
      }),
      delegate(validator, "2"),
      undelegate(validator, "1"),
      unstakeValidator("3"),
      claimUnbonded(validator, 7),
      claimValidatorRewards(),
      claimDelegatorRewards(validator),
      submitSlashingEvidence(evidence),
      bridgeLock({
        asset: "NativeWebc",
        destinationChain: "Ethereum",
        recipient: "abcd",
        amount: "4",
      }),
      bridgeBurn({
        asset: externalAsset,
        destinationChain: "Solana",
        recipient: "dcba",
        amount: "5",
      }),
      bridgeMint(message),
      bridgeRelease(message),
    ];

    expect(await canonicalJsonHashHex(operations)).toBe(
      "2d417a59882276e5908593eae97e323e4db4fceb324e5ff9d27ae895a0bbd1f5",
    );
    expect(claimValidatorRewards()).toBe("ClaimValidatorRewards");
  });

  const sessionReveal: PostQuantumRootRevealJson = {
    scheme: "MlDsa65",
    public_key: "33".repeat(1952),
    signature: "44".repeat(3309),
  };
  const sessionConstraints: SessionKeyConstraintsJson = {
    authorization_lane: "00".repeat(32),
    allowed_operations: { transfer: true },
    max_amount_per_use: "5",
    total_amount_budget: "20",
    max_fee_per_use: "1",
    total_fee_budget: "5",
    lifetime_epochs: 60,
  };

  it("matches the Rust session-key and rotation wire variants", async () => {
    const operations: OperationJson[] = [
      installSessionKey({
        sessionPublicKey: "11".repeat(32),
        constraints: sessionConstraints,
        postQuantumRootReveal: sessionReveal,
      }),
      revokeSessionKey({
        sessionKey: "55".repeat(32),
        postQuantumRootReveal: sessionReveal,
      }),
      rotateActiveTransactionKey({
        newActiveTransactionKey: "66".repeat(32),
        postQuantumRootReveal: sessionReveal,
      }),
      rotatePostQuantumRoot({
        newPostQuantumRoot: { scheme: "MlDsa65", public_key_hash: "22".repeat(32) },
        postQuantumRootReveal: sessionReveal,
      }),
    ];
    // Must equal the Rust vector in
    // `session_and_rotation_operations_have_a_stable_cross_language_wire_vector`.
    expect(await canonicalJsonHashHex(operations)).toBe(
      "272f10267381f778bb9dc0d2d81c3aba143081facb9f677216e0e7bb538dbf1d",
    );
  });

  it("rejects non-canonical amount strings to keep Rust u128 parity (X4)", () => {
    // Rust's Amount serializes as a canonical unsigned decimal (no leading zero,
    // no sign, within u128). A value Rust would never re-produce must not be
    // signable, or the signed bytes silently diverge from verification.
    const validator = "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";
    const overU128 = (2n ** 128n).toString(10);
    for (const bad of ["01", "-5", "abc", "", " 5", "5 ", "1_000", overU128]) {
      expect(() => transfer(validator, bad)).toThrow(/amount/u);
      expect(() => delegate(validator, bad)).toThrow(/amount/u);
      expect(() => undelegate(validator, bad)).toThrow(/amount/u);
      expect(() => unstakeValidator(bad)).toThrow(/amount/u);
      expect(() => registerValidator({
        consensusKey: "aa".repeat(32),
        selfStake: bad,
        commissionBps: 500,
        bootstrap: false,
      })).toThrow(/amount/u);
      expect(() =>
        bridgeLock({
          asset: "NativeWebc",
          destinationChain: "Ethereum",
          recipient: "abcd",
          amount: bad,
        }),
      ).toThrow(/amount/u);
      expect(() => openAuthorizationLane("99".repeat(32), bad)).toThrow(/amount/u);
    }
    // Session-key constraint amounts are validated too (same parity class).
    expect(() =>
      installSessionKey({
        sessionPublicKey: "11".repeat(32),
        constraints: { ...sessionConstraints, max_amount_per_use: "05" },
        postQuantumRootReveal: sessionReveal,
      }),
    ).toThrow(/amount/u);
    // Canonical values still construct.
    expect(transfer(validator, "0")).toEqual({
      Transfer: { to: validator, amount: "0" },
    });
    expect(transfer(validator, "123456")).toEqual({
      Transfer: { to: validator, amount: "123456" },
    });
  });

  it("rejects non-lowercase object id/namespace/data hex to keep Rust parity (X2)", () => {
    // object_id and namespace are Hash256 and data is bounded lowercase hex in
    // Rust; a mixed-case field re-serializes lowercase there, so signing it here
    // produces a silent mismatch. Validate each hex field in the constructor.
    const id = "ab".repeat(32);
    const namespace = "cd".repeat(32);
    expect(() =>
      createObject({ objectId: id.toUpperCase(), namespace, data: "ab" }),
    ).toThrow(/lowercase hex/u);
    expect(() =>
      createObject({ objectId: id, namespace: namespace.toUpperCase(), data: "ab" }),
    ).toThrow(/lowercase hex/u);
    expect(() =>
      createObject({ objectId: id, namespace, data: "AB" }),
    ).toThrow(/lowercase hex/u);
    expect(() =>
      mutateObject({ objectId: id, namespace, expectedVersion: 1, data: "Cd" }),
    ).toThrow(/lowercase hex/u);
    expect(() =>
      transferObject({
        objectId: id.toUpperCase(),
        namespace,
        expectedVersion: 2,
        newOwner: "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3",
      }),
    ).toThrow(/lowercase hex/u);
    // Odd-length (non-byte-aligned) hex is also rejected before signing.
    expect(() =>
      createObject({ objectId: id, namespace, data: "abc" }),
    ).toThrow(/lowercase hex/u);
    // Well-formed lowercase fields still construct.
    expect(
      createObject({ objectId: id, namespace, data: "ab" }),
    ).toEqual({ CreateObject: { object_id: id, namespace, data: "ab" } });
  });

  it("rejects non-lowercase bridge recipient hex to keep Rust parity (X1)", () => {
    // Rust emits and re-serializes the recipient as lowercase hex, so an
    // upper/mixed-case recipient here would sign bytes Rust never re-produces,
    // yielding a silent signing/verification mismatch. Fail closed instead.
    expect(() =>
      bridgeLock({
        asset: "NativeWebc",
        destinationChain: "Ethereum",
        recipient: "ABCD",
        amount: "4",
      }),
    ).toThrow(/lowercase hex/u);
    expect(() =>
      bridgeBurn({
        asset: "NativeWebc",
        destinationChain: "Solana",
        recipient: "AbCd",
        amount: "5",
      }),
    ).toThrow(/lowercase hex/u);
    // An odd-length or non-hex recipient is likewise rejected before signing.
    expect(() =>
      bridgeLock({
        asset: "NativeWebc",
        destinationChain: "Ethereum",
        recipient: "abc",
        amount: "4",
      }),
    ).toThrow(/lowercase hex/u);
    // A well-formed lowercase recipient still constructs successfully.
    expect(
      bridgeLock({
        asset: "NativeWebc",
        destinationChain: "Ethereum",
        recipient: "abcd",
        amount: "4",
      }),
    ).toEqual({
      BridgeLock: {
        asset: "NativeWebc",
        destination_chain: "Ethereum",
        recipient: "abcd",
        amount: "4",
      },
    });
  });

  it("derives the Rust session-key id for a public key", async () => {
    // Must equal Rust `SessionKeyId::derive(PublicKeyBytes([0x11; 32]))`.
    expect(await deriveSessionKeyIdHex("11".repeat(32))).toBe(
      "0ccf7ce5d50b1e08cb4b7d2f7c5b7af9eb094dce0c9d1668a2e270de7fb40c74",
    );
  });

  it("builds session-key and rotation access lists matching Rust", async () => {
    const owner = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
    const account = { version: 1, kind: { Account: { address: owner } } };
    const policy = { version: 1, kind: { AuthorizationPolicy: { owner } } };
    const baseFee = { version: 1, kind: { Protocol: { field: "BaseFee" } } };
    const feeAcc = {
      version: 1,
      kind: { FeeAccumulator: { payer: owner, lane: "00".repeat(32) } },
    };

    // Revoke reads the policy and writes the account and the named session key.
    const revoke = defaultAccessList(
      owner,
      revokeSessionKey({
        sessionKey: "55".repeat(32),
        postQuantumRootReveal: sessionReveal,
      }),
    );
    expect(revoke).toEqual({
      read_only: [baseFee, policy],
      read_write: [account, sessionKeyKey(owner, "55".repeat(32)), feeAcc],
    });

    // Both rotations write the policy, so it must not appear in read_only.
    const rotate = defaultAccessList(
      owner,
      rotateActiveTransactionKey({
        newActiveTransactionKey: "66".repeat(32),
        postQuantumRootReveal: sessionReveal,
      }),
    );
    expect(rotate).toEqual({
      read_only: [baseFee],
      read_write: [account, policy, feeAcc],
    });

    const rotateRoot = defaultAccessList(
      owner,
      rotatePostQuantumRoot({
        newPostQuantumRoot: { scheme: "MlDsa65", public_key_hash: "22".repeat(32) },
        postQuantumRootReveal: sessionReveal,
      }),
    );
    expect(rotateRoot).toEqual({
      read_only: [baseFee],
      read_write: [account, policy, feeAcc],
    });

    // Install derives the session-key id, so the synchronous builder refuses it
    // and the async builder writes the derived key.
    const install = installSessionKey({
      sessionPublicKey: "11".repeat(32),
      constraints: sessionConstraints,
      postQuantumRootReveal: sessionReveal,
    });
    expect(() => defaultAccessList(owner, install)).toThrow(
      /defaultAccessListAsync/u,
    );
    const derivedId = await deriveSessionKeyIdHex("11".repeat(32));
    expect(await defaultAccessListAsync(owner, install)).toEqual({
      read_only: [baseFee, policy],
      read_write: [account, sessionKeyKey(owner, derivedId), feeAcc],
    });
  });

  it("decodes, verifies, and hashes the complete Rust signed transaction wire", async () => {
    const sender = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
    const recipient = "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";
    const transaction: SignedTransactionJson = {
      protocol_version: 1,
      chain_id: "webc-devnet-1",
      sender,
      public_key:
        "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
      authorization_lane: defaultLane,
      authorization_policy_revision: 0,
      nonce: 7,
      operation: transfer(recipient, "123456"),
      access_list: {
        read_only: [
          { version: 1, kind: { Protocol: { field: "BaseFee" } } },
          { version: 1, kind: { AuthorizationPolicy: { owner: sender } } },
        ],
        read_write: [
          { version: 1, kind: { Account: { address: sender } } },
          { version: 1, kind: { Account: { address: recipient } } },
          { version: 1, kind: { FeeAccumulator: { payer: sender, lane: defaultLane } } },
        ],
      },
      fee: {
        gas_limit: 1_000,
        max_fee_per_unit: 5,
        priority_fee_per_unit: 1,
      },
      signature:
        "2c7c52e849d29b96605c8e936d1380d8a241b18ba8b1d2fef72bfbc06af4ce9a83ce3e58151ece30a91108a0dbba502788addfdf66a2c6ae48409d9557a1f305",
    };

    expect(await verifySignedTransaction(transaction)).toBe(true);
    expect(await transactionHashHex(transaction)).toBe(
      "f96ee7384499aa9670ddb2829aca699d97a88c610cb6c0e56662e9ba8e5092a1",
    );
    expect(
      await verifySignedTransaction({
        ...transaction,
        chain_id: "webc-other-1",
      }),
    ).toBe(false);
    await expect(
      verifySignedTransaction({ ...transaction, chain_id: "INVALID" }),
    ).rejects.toThrow("chain ID");
    await expect(
      verifySignedTransaction({
        ...transaction,
        authorization_policy_revision: Number.MAX_SAFE_INTEGER + 1,
      }),
    ).rejects.toThrow("policy revision");
  });
});

describe("fee sponsorship signing (§15.35)", () => {
  const defaultLane = "00".repeat(32);
  const sender = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
  const recipient = "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";
  const publicKey =
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
  const sponsor = "ab".repeat(32);
  const fee = { gasLimit: 1_000, maxFeePerUnit: 5, priorityFeePerUnit: 1 };

  // The exact canonical signing payload for the shared transfer fixture, WITHOUT
  // a sponsor. Byte-identical to the frozen `WEBC_SIGNED_TRANSACTION_V4` vector
  // asserted above and in the Rust `transfer_canonical_signing_payload_is_stable`.
  const baseSigningJson =
    `{"access_list":{"read_only":[{"kind":{"Protocol":{"field":"BaseFee"}},"version":1},{"kind":{"AuthorizationPolicy":{"owner":"${sender}"}},"version":1}],"read_write":[{"kind":{"Account":{"address":"${sender}"}},"version":1},{"kind":{"Account":{"address":"${recipient}"}},"version":1},{"kind":{"FeeAccumulator":{"lane":"${defaultLane}","payer":"${sender}"}},"version":1}]},"authorization_lane":"${defaultLane}","authorization_policy_revision":0,"chain_id":"webc-devnet-1","domain":"WEBC_SIGNED_TRANSACTION_V4","fee":{"gas_limit":1000,"max_fee_per_unit":5,"priority_fee_per_unit":1},"nonce":7,"operation":{"Transfer":{"amount":"123456","to":"${recipient}"}},"protocol_version":1,"public_key":"${publicKey}","sender":"${sender}"}`;

  function payloadFor(sponsorArg?: string) {
    const operation = transfer(recipient, "123456");
    return transactionSigningPayload(
      1,
      "webc-devnet-1",
      sender,
      publicKey,
      7,
      operation,
      defaultAccessList(sender, operation),
      fee,
      defaultLane,
      0,
      sponsorArg,
    );
  }

  it("omits sponsor when absent, byte-identical to the frozen V4 payload", () => {
    // Regression: with no sponsor the signing bytes must not change at all, so
    // every existing hash/signature/vector stays valid.
    const json = canonicalJson(payloadFor(undefined));
    expect(json).toBe(baseSigningJson);
    expect(json).not.toContain("sponsor");
  });

  it("appends the sponsor field last, matching the Rust canonical form", () => {
    // Canonical JSON sorts keys, so `sponsor` lands after `sender` — exactly
    // where Rust's `Option<Hash256>` sponsor field sorts. The only difference
    // from the frozen payload is the single appended key.
    const expected = baseSigningJson.replace(
      `"sender":"${sender}"}`,
      `"sender":"${sender}","sponsor":"${sponsor}"}`,
    );
    expect(canonicalJson(payloadFor(sponsor))).toBe(expected);
    // And this equals the Rust test's `"sponsor":"abab…ab"` (namespace [0xab;32]).
    expect(canonicalJson(payloadFor(sponsor))).toContain(
      `"sponsor":"${"ab".repeat(32)}"`,
    );
  });

  it("derives the Rust sponsor state-key hash for an application namespace", async () => {
    // Cross-language vector: SHA-256("WEBC_SPONSOR_STATE_KEY_V1"), matching Rust
    // `sponsorship::sponsor_state_key_hash()`.
    expect(await sponsorStateKeyHashHex()).toBe(
      "dc9618d08738c7e00d00fb7393c53d8323b90a9ad8a88e578e4608dbb3b4ee9c",
    );
    expect(await sponsorStateKey(sponsor)).toEqual({
      version: 1,
      kind: {
        Application: {
          namespace: sponsor,
          key_hash:
            "dc9618d08738c7e00d00fb7393c53d8323b90a9ad8a88e578e4608dbb3b4ee9c",
        },
      },
    });
  });

  it("builds a sponsored access list that appends the sponsor state key", async () => {
    const operation = transfer(recipient, "123456");
    const list = await sponsoredAccessListAsync(sender, operation, sponsor);
    const base = await defaultAccessListAsync(sender, operation);
    const sponsorKey = await sponsorStateKey(sponsor);
    // Superset of the default list: same read_only, and read_write with the
    // sponsor state key appended last (mirrors Rust `for_sponsored_operation`).
    expect(list.read_only).toEqual(base.read_only);
    expect(list.read_write).toEqual([...base.read_write, sponsorKey]);
  });

  it("signs, verifies, and hashes a full sponsored transaction end to end", async () => {
    const wallet = await createWalletFromSeed(new Uint8Array(32).fill(9));
    const operation = transfer(recipient, "123456");
    const sponsored = await signTransaction(
      wallet,
      "webc-devnet-1",
      7,
      operation,
      fee,
      undefined,
      defaultLane,
      1,
      0,
      sponsor,
    );
    // The sponsor is carried on the wire and its state key is declared.
    expect(sponsored.sponsor).toBe(sponsor);
    expect(sponsored.access_list.read_write).toContainEqual(
      await sponsorStateKey(sponsor),
    );
    expect(await verifySignedTransaction(sponsored)).toBe(true);

    // The identical transaction WITHOUT a sponsor produces a different hash and
    // omits the field entirely — proving the signature binds the sponsor choice.
    const plain = await signTransaction(
      wallet,
      "webc-devnet-1",
      7,
      operation,
      fee,
    );
    expect(plain.sponsor).toBeUndefined();
    expect(await transactionHashHex(plain)).not.toBe(
      await transactionHashHex(sponsored),
    );

    // Tampering the sponsor after signing breaks verification.
    expect(
      await verifySignedTransaction({ ...sponsored, sponsor: "cd".repeat(32) }),
    ).toBe(false);
    // Stripping the signed sponsor likewise fails to verify.
    const stripped = { ...sponsored };
    delete stripped.sponsor;
    expect(await verifySignedTransaction(stripped)).toBe(false);
  });

  it("rejects a non-canonical sponsor namespace to keep Rust Hash256 parity", () => {
    // Rust serializes the sponsor as a lowercase 64-char hex Hash256; a value it
    // would never re-produce must not be signable or the bytes silently diverge.
    for (const bad of [
      "ab".repeat(31), // too short
      "ab".repeat(33), // too long
      "AB".repeat(32), // upper-case
      `${"ab".repeat(31)}gg`, // non-hex
      "",
    ]) {
      expect(() => validateSponsor(bad)).toThrow(/sponsor/u);
      expect(() => payloadFor(bad)).toThrow(/sponsor/u);
    }
    // A well-formed lowercase 32-byte hex namespace is accepted.
    expect(() => validateSponsor(sponsor)).not.toThrow();
  });
});
