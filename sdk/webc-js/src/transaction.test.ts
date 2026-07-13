/** Cross-language transaction and state-key signing fixtures. */

import { describe, expect, it } from "vitest";
import { addressToBytes } from "./address";
import { canonicalJson, canonicalJsonHashHex } from "./canonical";
import { bytesToHex } from "./hex";
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
  fundAuthorizationLane,
  installAuthorizationPolicy,
  openAuthorizationLane,
  mutateObject,
  registerValidator,
  submitSlashingEvidence,
  transactionHashHex,
  transactionSigningPayload,
  transfer,
  transferObject,
  undelegate,
  unstakeValidator,
  verifySignedTransaction,
} from "./transaction";
import type {
  AssetIdJson,
  BridgeMessageJson,
  OperationJson,
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
