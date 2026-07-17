/**
 * Cross-language wire-vector fixtures for the native operations added in Phase 7
 * onward (tokens, NFTs, governance, mandate, service registry, oracle, DEX).
 *
 * Each assertion pins the EXACT canonical JSON string (or state-key hash) that the
 * corresponding Rust wire-vector test asserts in
 * `crates/webc-chain/src/transaction.rs` and `state_key.rs`. Addresses are derived
 * from the SAME `Keypair::from_seed` seeds the Rust tests use, so a byte for byte
 * match confirms field names, sorted-key order, and scalar encodings agree across
 * languages. If the SDK output drifts from Rust, these fail.
 */

import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import { bytesToHex } from "./hex";
import { createWalletFromSeed } from "./wallet";
import {
  accountKey,
  authorizationPolicyKey,
  burnNft,
  burnToken,
  createNftCollection,
  createToken,
  defaultAccessList,
  defaultAccessListAsync,
  deriveNftCollectionIdHex,
  deriveTokenIdHex,
  feeAccumulatorKey,
  freezeNftItem,
  freezeTokenAccount,
  mintNft,
  mintToken,
  nftCollectionKey,
  nftItemKey,
  protocolKey,
  setNftAuthority,
  setNftCollectionPaused,
  setTokenAuthority,
  setTokenPaused,
  thawNftItem,
  thawTokenAccount,
  tokenBalanceKey,
  tokenFreezeKey,
  tokenKey,
  transferNft,
  transferToken,
} from "./transaction";
import type { NftMetadataJson, TokenMetadataJson } from "./types";

const DEFAULT_LANE = "00".repeat(32);

/** Reproduces `Keypair::from_seed([byte; 32]).address()` from the Rust fixtures. */
async function addressFromSeedByte(byte: number): Promise<string> {
  const wallet = await createWalletFromSeed(new Uint8Array(32).fill(byte));
  return wallet.address;
}

/** Lowercase hex of a UTF-8 string, matching Rust `hex::encode(text)`. */
function hexOfText(text: string): string {
  return bytesToHex(new TextEncoder().encode(text));
}

const ID_88 = "88".repeat(32);

describe("native token operation wire vectors", () => {
  it("pins CreateToken canonical JSON (nested metadata, Some/None authorities)", async () => {
    const recipient = await addressFromSeedByte(9);
    const metadata: TokenMetadataJson = {
      name: hexOfText("Acme Dollar"),
      symbol: hexOfText("ACME"),
      decimals: 6,
      metadata_hash: "1f".repeat(32),
    };
    const op = createToken({
      namespace: "55".repeat(32),
      createNonce: 7,
      metadata,
      mintAuthority: recipient,
      freezeAuthority: null,
      initialSupply: "1000",
      initialRecipient: recipient,
    });
    expect(canonicalJson(op)).toBe(
      `{"CreateToken":{"create_nonce":7,"freeze_authority":null,"initial_recipient":"${recipient}",` +
        `"initial_supply":"1000","metadata":{"decimals":6,"metadata_hash":"${"1f".repeat(32)}",` +
        `"name":"${hexOfText("Acme Dollar")}","symbol":"${hexOfText("ACME")}"},` +
        `"mint_authority":"${recipient}","namespace":"${"55".repeat(32)}"}}`,
    );
  });

  it("pins MintToken / BurnToken / TransferToken canonical JSON", async () => {
    const recipient = await addressFromSeedByte(9);
    expect(canonicalJson(mintToken(ID_88, recipient, "7"))).toBe(
      `{"MintToken":{"amount":"7","recipient":"${recipient}","token_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(burnToken(ID_88, "3"))).toBe(
      `{"BurnToken":{"amount":"3","token_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(transferToken(ID_88, recipient, "5"))).toBe(
      `{"TransferToken":{"amount":"5","recipient":"${recipient}","token_id":"${ID_88}"}}`,
    );
  });

  it("pins SetTokenPaused / Freeze / Thaw canonical JSON", async () => {
    const account = await addressFromSeedByte(10);
    expect(canonicalJson(setTokenPaused(ID_88, true))).toBe(
      `{"SetTokenPaused":{"paused":true,"token_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(freezeTokenAccount(ID_88, account))).toBe(
      `{"FreezeTokenAccount":{"account":"${account}","token_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(thawTokenAccount(ID_88, account))).toBe(
      `{"ThawTokenAccount":{"account":"${account}","token_id":"${ID_88}"}}`,
    );
  });

  it("pins SetTokenAuthority for both transfer (Some) and renounce (null)", async () => {
    const recipient = await addressFromSeedByte(9);
    expect(canonicalJson(setTokenAuthority(ID_88, "Mint", recipient))).toBe(
      `{"SetTokenAuthority":{"authority_kind":"Mint","new_authority":"${recipient}","token_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(setTokenAuthority(ID_88, "Freeze", null))).toBe(
      `{"SetTokenAuthority":{"authority_kind":"Freeze","new_authority":null,"token_id":"${ID_88}"}}`,
    );
  });

  it("rejects a non-canonical amount and non-lowercase-hex token id", () => {
    const recipient = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
    expect(() => mintToken(ID_88, recipient, "01")).toThrow();
    expect(() => mintToken(ID_88, recipient, "-5")).toThrow();
    expect(() => mintToken("AB".repeat(32), recipient, "7")).toThrow();
    expect(() => burnToken("88", "3")).toThrow(); // not 32 bytes
  });
});

describe("native token access lists", () => {
  it("declares BOTH parties' freeze markers as reads on TransferToken", async () => {
    const sender = await addressFromSeedByte(1);
    const recipient = await addressFromSeedByte(9);
    const list = defaultAccessList(sender, transferToken(ID_88, recipient, "5"));
    // Exact order mirrors Rust `default_access_list_for_lane` insertion order.
    expect(list.read_only).toEqual([
      protocolKey("BaseFee"),
      tokenKey(ID_88),
      tokenFreezeKey(ID_88, sender),
      tokenFreezeKey(ID_88, recipient),
      authorizationPolicyKey(sender),
    ]);
    expect(list.read_write).toEqual([
      accountKey(sender),
      tokenBalanceKey(ID_88, sender),
      tokenBalanceKey(ID_88, recipient),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });

  it("names the derived token record (and initial balance) on CreateToken", async () => {
    const sender = await addressFromSeedByte(1);
    const recipient = await addressFromSeedByte(9);
    const metadata: TokenMetadataJson = {
      name: hexOfText("Acme"),
      symbol: hexOfText("ACME"),
      decimals: 6,
      metadata_hash: "1f".repeat(32),
    };
    const tokenId = await deriveTokenIdHex("55".repeat(32), sender, 7);
    const withSupply = await defaultAccessListAsync(
      sender,
      createToken({
        namespace: "55".repeat(32),
        createNonce: 7,
        metadata,
        mintAuthority: recipient,
        freezeAuthority: null,
        initialSupply: "1000",
        initialRecipient: recipient,
      }),
    );
    expect(withSupply.read_write).toEqual([
      accountKey(sender),
      tokenKey(tokenId),
      tokenBalanceKey(tokenId, recipient),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
    // A zero initial supply mints nothing, so the balance key is omitted.
    const zeroSupply = await defaultAccessListAsync(
      sender,
      createToken({
        namespace: "55".repeat(32),
        createNonce: 7,
        metadata,
        mintAuthority: recipient,
        freezeAuthority: null,
        initialSupply: "0",
        initialRecipient: recipient,
      }),
    );
    expect(zeroSupply.read_write).toEqual([
      accountKey(sender),
      tokenKey(tokenId),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });
});

describe("native token state-key wire vectors", () => {
  it("pins Token / TokenBalance / TokenFreeze canonical JSON", async () => {
    const holder = await addressFromSeedByte(9);
    expect(canonicalJson(tokenKey(ID_88))).toBe(
      `{"kind":{"Token":{"token_id":"${ID_88}"}},"version":1}`,
    );
    expect(canonicalJson(tokenBalanceKey(ID_88, holder))).toBe(
      `{"kind":{"TokenBalance":{"owner":"${holder}","token_id":"${ID_88}"}},"version":1}`,
    );
    expect(canonicalJson(tokenFreezeKey(ID_88, holder))).toBe(
      `{"kind":{"TokenFreeze":{"account":"${holder}","token_id":"${ID_88}"}},"version":1}`,
    );
  });
});

describe("native NFT operation wire vectors", () => {
  const ITEM_HEX = "3a".repeat(32);

  it("pins CreateNftCollection canonical JSON (Some/None authorities, Some cap)", async () => {
    const recipient = await addressFromSeedByte(9);
    const metadata: NftMetadataJson = {
      name: hexOfText("Acme Apes"),
      symbol: hexOfText("APE"),
      metadata_hash: "1f".repeat(32),
    };
    const op = createNftCollection({
      namespace: "55".repeat(32),
      createNonce: 7,
      metadata,
      mintAuthority: recipient,
      freezeAuthority: null,
      maxSupply: 10_000,
      royaltyBps: 500,
    });
    expect(canonicalJson(op)).toBe(
      `{"CreateNftCollection":{"create_nonce":7,"freeze_authority":null,"max_supply":10000,` +
        `"metadata":{"metadata_hash":"${"1f".repeat(32)}","name":"${hexOfText("Acme Apes")}",` +
        `"symbol":"${hexOfText("APE")}"},"mint_authority":"${recipient}","namespace":"${"55".repeat(32)}",` +
        `"royalty_bps":500}}`,
    );
  });

  it("pins MintNft / TransferNft / BurnNft canonical JSON", async () => {
    const recipient = await addressFromSeedByte(9);
    expect(canonicalJson(mintNft(ID_88, recipient, ITEM_HEX))).toBe(
      `{"MintNft":{"collection_id":"${ID_88}","item_metadata_hash":"${ITEM_HEX}","recipient":"${recipient}"}}`,
    );
    expect(canonicalJson(transferNft(ID_88, 3, recipient))).toBe(
      `{"TransferNft":{"collection_id":"${ID_88}","recipient":"${recipient}","serial":3}}`,
    );
    expect(canonicalJson(burnNft(ID_88, 3))).toBe(
      `{"BurnNft":{"collection_id":"${ID_88}","serial":3}}`,
    );
  });

  it("pins pause / freeze / thaw / authority canonical JSON", async () => {
    const recipient = await addressFromSeedByte(9);
    expect(canonicalJson(setNftCollectionPaused(ID_88, true))).toBe(
      `{"SetNftCollectionPaused":{"collection_id":"${ID_88}","paused":true}}`,
    );
    expect(canonicalJson(freezeNftItem(ID_88, 3))).toBe(
      `{"FreezeNftItem":{"collection_id":"${ID_88}","serial":3}}`,
    );
    expect(canonicalJson(thawNftItem(ID_88, 3))).toBe(
      `{"ThawNftItem":{"collection_id":"${ID_88}","serial":3}}`,
    );
    expect(canonicalJson(setNftAuthority(ID_88, "Mint", recipient))).toBe(
      `{"SetNftAuthority":{"authority_kind":"Mint","collection_id":"${ID_88}","new_authority":"${recipient}"}}`,
    );
    expect(canonicalJson(setNftAuthority(ID_88, "Freeze", null))).toBe(
      `{"SetNftAuthority":{"authority_kind":"Freeze","collection_id":"${ID_88}","new_authority":null}}`,
    );
  });
});

describe("native NFT state keys and access lists", () => {
  it("pins NftCollection / NftItem canonical JSON", () => {
    expect(canonicalJson(nftCollectionKey(ID_88))).toBe(
      `{"kind":{"NftCollection":{"collection_id":"${ID_88}"}},"version":1}`,
    );
    expect(canonicalJson(nftItemKey(ID_88, 7))).toBe(
      `{"kind":{"NftItem":{"collection_id":"${ID_88}","serial":7}},"version":1}`,
    );
  });

  it("declares the collection read-only and the item read-write on TransferNft", async () => {
    const sender = await addressFromSeedByte(1);
    const recipient = await addressFromSeedByte(9);
    const list = defaultAccessList(sender, transferNft(ID_88, 3, recipient));
    expect(list.read_only).toEqual([
      protocolKey("BaseFee"),
      nftCollectionKey(ID_88),
      authorizationPolicyKey(sender),
    ]);
    expect(list.read_write).toEqual([
      accountKey(sender),
      nftItemKey(ID_88, 3),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });

  it("names the derived collection record on CreateNftCollection", async () => {
    const sender = await addressFromSeedByte(1);
    const recipient = await addressFromSeedByte(9);
    const metadata: NftMetadataJson = {
      name: hexOfText("Acme Apes"),
      symbol: hexOfText("APE"),
      metadata_hash: "1f".repeat(32),
    };
    const collectionId = await deriveNftCollectionIdHex("55".repeat(32), sender, 7);
    const list = await defaultAccessListAsync(
      sender,
      createNftCollection({
        namespace: "55".repeat(32),
        createNonce: 7,
        metadata,
        mintAuthority: recipient,
        freezeAuthority: null,
        maxSupply: null,
        royaltyBps: 500,
      }),
    );
    expect(list.read_write).toEqual([
      accountKey(sender),
      nftCollectionKey(collectionId),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });
});
