/** Rust-shared replay-hash and hash-derived access-list fixtures. */

import { describe, expect, it } from "vitest";
import { addressToBytes } from "./address";
import { bytesToHex } from "./hex";
import {
  bridgeMessageHashHex,
  slashingEvidenceHashHex,
} from "./protocol-hash";
import {
  bridgeBurn,
  bridgeLock,
  bridgeMint,
  bridgeRelease,
  defaultAccessList,
  defaultAccessListAsync,
} from "./transaction";
import type {
  AssetIdJson,
  BridgeMessageJson,
  SlashingEvidenceJson,
} from "./types";

const owner = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
const defaultLane = "00".repeat(32);
const recipient = "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";
const externalAsset: AssetIdJson = {
  External: {
    origin_chain: "Ethereum",
    symbol: "USDC",
    contract_or_mint: "0x1234",
  },
};
const message: BridgeMessageJson = {
  source_chain: "Ethereum",
  destination_chain: "Webc",
  nonce: 9,
  asset: externalAsset,
  sender: "abcd",
  recipient: bytesToHex(addressToBytes(recipient)),
  amount: "77",
  source_tx: "77".repeat(32),
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
        validator: recipient,
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
        validator: recipient,
      },
      signature: "66".repeat(64),
    },
  },
};

describe("protocol replay hashes", () => {
  it("matches Rust bridge and order-independent evidence hashes", async () => {
    expect(await bridgeMessageHashHex(message)).toBe(
      "4c984acec3e91d74db4d81ccce74b6cd8214ff56626747ced5f24b673b83ce85",
    );
    expect(await slashingEvidenceHashHex(evidence)).toBe(
      "4e38c4f195837efcb43185bb5237c15ccccd1f1e372e9df834b654bcec6be3ac",
    );
    const reversed: SlashingEvidenceJson = {
      DoubleVote: {
        first: evidence.DoubleVote.second,
        second: evidence.DoubleVote.first,
      },
    };
    expect(await slashingEvidenceHashHex(reversed)).toBe(
      await slashingEvidenceHashHex(evidence),
    );
  });

  it("derives exact outgoing and incoming bridge access keys", async () => {
    expect(
      defaultAccessList(
        owner,
        bridgeLock({
          asset: "NativeWebc",
          destinationChain: "Ethereum",
          recipient: "abcd",
          amount: "4",
        }),
      ).read_write,
    ).toEqual([
      { version: 1, kind: { Account: { address: owner } } },
      { version: 1, kind: { BridgeEscrow: { domain: "Ethereum" } } },
      { version: 1, kind: { Protocol: { field: "BridgeNonce" } } },
      { version: 1, kind: { FeeAccumulator: { payer: owner, lane: defaultLane } } },
    ]);

    expect(
      defaultAccessList(
        owner,
        bridgeBurn({
          asset: externalAsset,
          destinationChain: "Solana",
          recipient: "dcba",
          amount: "5",
        }),
      ).read_write,
    ).toEqual([
      { version: 1, kind: { Account: { address: owner } } },
      { version: 1, kind: { AssetBalance: { asset: externalAsset, owner } } },
      { version: 1, kind: { Protocol: { field: "BridgeNonce" } } },
      { version: 1, kind: { FeeAccumulator: { payer: owner, lane: defaultLane } } },
    ]);

    expect(
      (await defaultAccessListAsync(owner, bridgeMint(message))).read_write,
    ).toEqual([
      { version: 1, kind: { Account: { address: owner } } },
      {
        version: 1,
        kind: { AssetBalance: { asset: externalAsset, owner: recipient } },
      },
      {
        version: 1,
        kind: {
          BridgeMessage: {
            message_hash:
              "4c984acec3e91d74db4d81ccce74b6cd8214ff56626747ced5f24b673b83ce85",
          },
        },
      },
      { version: 1, kind: { FeeAccumulator: { payer: owner, lane: defaultLane } } },
    ]);

    const releaseMessage: BridgeMessageJson = {
      ...message,
      asset: "NativeWebc",
      source_tx: "88".repeat(32),
    };
    const releaseHash = await bridgeMessageHashHex(releaseMessage);
    expect(
      (await defaultAccessListAsync(owner, bridgeRelease(releaseMessage))).read_write,
    ).toEqual([
      { version: 1, kind: { Account: { address: owner } } },
      { version: 1, kind: { Account: { address: recipient } } },
      {
        version: 1,
        kind: { BridgeMessage: { message_hash: releaseHash } },
      },
      { version: 1, kind: { BridgeEscrow: { domain: "Ethereum" } } },
      { version: 1, kind: { FeeAccumulator: { payer: owner, lane: defaultLane } } },
    ]);
  });
});
