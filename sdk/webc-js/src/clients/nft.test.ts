/**
 * Tests for `NftClient` (`clients/nft.ts`).
 *
 * The `WebcNodeClient` is MOCKED (its read + submit methods) — no network is
 * touched — while a real `WebcWallet` signs. Each write is pinned against the EXACT
 * operation JSON AND the EXACT default access list the low-level `transaction.ts`
 * builders produce (none of these ops is state-derived), so any drift from the
 * composed primitives fails the test. Reads are asserted against mocked responses,
 * and a fail-closed case (an out-of-range royalty) is rejected before any submit.
 */

import { describe, expect, it } from "vitest";

import { bytesToHex } from "../hex.js";
import { canonicalJson } from "../canonical.js";
import { createWalletFromSeed } from "../wallet.js";
import type { WebcWallet } from "../wallet.js";
import type { AccountView, SubmitReceipt, WebcNodeClient } from "../node-client.js";
import type {
  NftCollection,
  NftItem,
  NftMetadataJson,
  SignedTransactionJson,
} from "../types.js";
import {
  DEFAULT_AUTHORIZATION_LANE,
  burnNft,
  createNftCollection,
  defaultAccessListAsync,
  deriveNftCollectionIdHex,
  freezeNftItem,
  mintNft,
  thawNftItem,
  transferNft,
  transactionHashHex,
  verifySignedTransaction,
} from "../transaction.js";
import { NftClient } from "./nft.js";

const COLLECTION_ID = "aa".repeat(32);
const ITEM_HASH = "22".repeat(32);
const NAMESPACE = "dd".repeat(32);
const CHAIN_ID = "webc-devnet-1";
const FEE = { gasLimit: 1000, maxFeePerUnit: 1, priorityFeePerUnit: 0 };

function hexOfText(text: string): string {
  return bytesToHex(new TextEncoder().encode(text));
}

const METADATA: NftMetadataJson = {
  name: hexOfText("Art"),
  symbol: hexOfText("ART"),
  metadata_hash: "11".repeat(32),
};

function walletFromSeedByte(byte: number): Promise<WebcWallet> {
  return createWalletFromSeed(new Uint8Array(32).fill(byte));
}

function mkCollection(creator: string): NftCollection {
  return {
    creator,
    metadata: METADATA,
    mint_authority: creator,
    freeze_authority: creator,
    paused: false,
    next_serial: 3,
    minted_count: 3,
    burned_count: 0,
    max_supply: null,
    royalty_bps: 500,
  };
}

function mkItem(owner: string): NftItem {
  return { owner, item_metadata_hash: ITEM_HASH, frozen: false };
}

interface MockHandlers {
  collections?: Record<string, NftCollection>;
  item?: NftItem;
  itemPage?: { items: readonly unknown[]; nextCursor: string | null };
  chainId?: string;
  accountNonce?: number;
}

interface MockNode {
  node: WebcNodeClient;
  submitted: SignedTransactionJson[];
  listCalls: unknown[];
}

function makeNode(handlers: MockHandlers = {}): MockNode {
  const submitted: SignedTransactionJson[] = [];
  const listCalls: unknown[] = [];
  const node = {
    async submitTransaction(tx: unknown): Promise<SubmitReceipt> {
      submitted.push(tx as SignedTransactionJson);
      return {
        txHash: await transactionHashHex(tx as SignedTransactionJson),
        accepted: true,
        mempoolSize: 1,
      };
    },
    async getNftCollection(id: string): Promise<NftCollection> {
      const collection = handlers.collections?.[id];
      if (!collection) throw new Error(`no mocked collection ${id}`);
      return collection;
    },
    async getNftItem(_id: string, _serial: number): Promise<NftItem> {
      if (!handlers.item) throw new Error("no mocked item");
      return handlers.item;
    },
    async listNftCollectionItems(id: string, options: unknown) {
      listCalls.push({ id, options });
      return handlers.itemPage ?? { items: [], nextCursor: null };
    },
    async health() {
      return {
        apiVersion: "v1",
        chainId: handlers.chainId ?? CHAIN_ID,
        height: 1,
        tipHash: null,
        stateRoot: null,
        mempoolSize: 0,
        faucetEnabled: false,
      };
    },
    async account(address: string): Promise<AccountView> {
      return { address, balance: 0n, nonce: handlers.accountNonce ?? 0 };
    },
  };
  return { node: node as unknown as WebcNodeClient, submitted, listCalls };
}

async function expectDefaultAccessList(
  signer: string,
  tx: SignedTransactionJson,
  operation: Parameters<typeof defaultAccessListAsync>[1],
): Promise<void> {
  expect(tx.access_list).toEqual(
    await defaultAccessListAsync(signer, operation, DEFAULT_AUTHORIZATION_LANE),
  );
}

describe("NftClient writes", () => {
  it("createCollection pins the op + default access list, signs, submits, derives the id", async () => {
    const creator = await walletFromSeedByte(1);
    const { node, submitted } = makeNode();
    const client = new NftClient({ node, signer: creator, chainId: CHAIN_ID, fee: FEE });

    const args = {
      namespace: NAMESPACE,
      createNonce: 4,
      metadata: METADATA,
      mintAuthority: creator.address,
      freezeAuthority: creator.address,
      maxSupply: null,
      royaltyBps: 500,
    };
    const result = await client.createCollection(args, { nonce: 0 });

    expect(canonicalJson(result.transaction.operation)).toBe(canonicalJson(createNftCollection(args)));
    await expectDefaultAccessList(creator.address, result.transaction, createNftCollection(args));
    expect(result.collectionId).toBe(await deriveNftCollectionIdHex(NAMESPACE, creator.address, 4));
    expect(await verifySignedTransaction(result.transaction)).toBe(true);
    expect(submitted).toHaveLength(1);
    expect(submitted[0]).toBe(result.transaction);
    expect(result.txHash).toBe(await transactionHashHex(result.transaction));
  });

  it("mintItem pins the op + default access list and returns the collection id", async () => {
    const signer = await walletFromSeedByte(1);
    const recipient = (await walletFromSeedByte(2)).address;
    const { node, submitted } = makeNode();
    const client = new NftClient({ node, signer, chainId: CHAIN_ID, fee: FEE });

    const result = await client.mintItem(COLLECTION_ID, recipient, ITEM_HASH, { nonce: 1 });
    expect(canonicalJson(result.transaction.operation)).toBe(
      canonicalJson(mintNft(COLLECTION_ID, recipient, ITEM_HASH)),
    );
    await expectDefaultAccessList(signer.address, result.transaction, mintNft(COLLECTION_ID, recipient, ITEM_HASH));
    expect(result.collectionId).toBe(COLLECTION_ID);
    expect(submitted[0]).toBe(result.transaction);
    expect(await verifySignedTransaction(result.transaction)).toBe(true);
  });

  it("transfer pins the op + default access list", async () => {
    const signer = await walletFromSeedByte(1);
    const recipient = (await walletFromSeedByte(3)).address;
    const { node, submitted } = makeNode();
    const client = new NftClient({ node, signer, chainId: CHAIN_ID, fee: FEE });

    const result = await client.transfer(COLLECTION_ID, 2, recipient, { nonce: 2 });
    expect(canonicalJson(result.transaction.operation)).toBe(
      canonicalJson(transferNft(COLLECTION_ID, 2, recipient)),
    );
    await expectDefaultAccessList(signer.address, result.transaction, transferNft(COLLECTION_ID, 2, recipient));
    expect(result.collectionId).toBe(COLLECTION_ID);
    expect(submitted[0]).toBe(result.transaction);
  });

  it("burn pins the op + default access list", async () => {
    const signer = await walletFromSeedByte(1);
    const { node, submitted } = makeNode();
    const client = new NftClient({ node, signer, chainId: CHAIN_ID, fee: FEE });

    const result = await client.burn(COLLECTION_ID, 2, { nonce: 3 });
    expect(canonicalJson(result.transaction.operation)).toBe(canonicalJson(burnNft(COLLECTION_ID, 2)));
    await expectDefaultAccessList(signer.address, result.transaction, burnNft(COLLECTION_ID, 2));
    expect(result.collectionId).toBe(COLLECTION_ID);
    expect(submitted[0]).toBe(result.transaction);
  });

  it("freeze / thaw pin their op + default access list", async () => {
    const signer = await walletFromSeedByte(1);
    const { node, submitted } = makeNode();
    const client = new NftClient({ node, signer, chainId: CHAIN_ID, fee: FEE });

    const frozen = await client.freeze(COLLECTION_ID, 1, { nonce: 4 });
    expect(canonicalJson(frozen.transaction.operation)).toBe(canonicalJson(freezeNftItem(COLLECTION_ID, 1)));
    await expectDefaultAccessList(signer.address, frozen.transaction, freezeNftItem(COLLECTION_ID, 1));

    const thawed = await client.thaw(COLLECTION_ID, 1, { nonce: 5 });
    expect(canonicalJson(thawed.transaction.operation)).toBe(canonicalJson(thawNftItem(COLLECTION_ID, 1)));
    await expectDefaultAccessList(signer.address, thawed.transaction, thawNftItem(COLLECTION_ID, 1));
    expect(submitted).toHaveLength(2);
  });

  it("throws (and never submits) an out-of-range royalty before signing (fail-closed)", async () => {
    const creator = await walletFromSeedByte(1);
    const { node, submitted } = makeNode();
    const client = new NftClient({ node, signer: creator, chainId: CHAIN_ID, fee: FEE });

    await expect(
      client.createCollection(
        {
          namespace: NAMESPACE,
          createNonce: 0,
          metadata: METADATA,
          mintAuthority: creator.address,
          freezeAuthority: creator.address,
          maxSupply: null,
          royaltyBps: 10_001,
        },
        { nonce: 0 },
      ),
    ).rejects.toThrow(/royalty/u);
    expect(submitted).toHaveLength(0);
  });
});

describe("NftClient reads", () => {
  it("getCollection / getItem wrap the node reads", async () => {
    const creator = await walletFromSeedByte(1);
    const collection = mkCollection(creator.address);
    const item = mkItem(creator.address);
    const { node } = makeNode({ collections: { [COLLECTION_ID]: collection }, item });
    const client = new NftClient({ node, signer: creator, chainId: CHAIN_ID, fee: FEE });

    expect(await client.getCollection(COLLECTION_ID)).toEqual(collection);
    expect(await client.getItem(COLLECTION_ID, 0)).toEqual(item);
  });

  it("listItems threads the id + options through to the collection-items endpoint", async () => {
    const creator = await walletFromSeedByte(1);
    const page = {
      items: [{ serial: 0, owner: creator.address, item_metadata_hash: ITEM_HASH, frozen: false }],
      nextCursor: "cursor-2" as string | null,
    };
    const { node, listCalls } = makeNode({ itemPage: page });
    const client = new NftClient({ node, signer: creator, chainId: CHAIN_ID, fee: FEE });

    const result = await client.listItems(COLLECTION_ID, { limit: 5 });
    expect(result).toEqual(page);
    expect(listCalls).toEqual([{ id: COLLECTION_ID, options: { limit: 5 } }]);
  });
});
