/**
 * `NftClient` — the ergonomic entry point for native NFTs on WEBC (Phase 13b, §15).
 * It COMPOSES the reviewed low-level SDK into the flows a collection creator or item
 * holder actually performs:
 *
 *   - create a collection and mint items into it (build -> sign -> submit);
 *   - transfer / burn an item and freeze / thaw one (build -> sign -> submit);
 *   - read a collection record, one item, and page a collection's items.
 *
 * It introduces no new operation, access list, or wire format: every write goes
 * through a `transaction.ts` builder and lets `signTransaction` derive the default
 * access list (the same list the low-level API auto-derives for these ops — none is
 * state-derived). The client-derived collection id on create is computed with the
 * SAME `deriveNftCollectionIdHex` the builder documents.
 *
 * ## Signer role
 * Each write signs an ordinary account transaction with this client's `signer`: the
 * collection's mint authority (create / mint), the freeze authority (freeze /
 * thaw), or the item's owner (transfer / burn). Construct the client with whichever
 * `signer` is authorized for the flow.
 */

import type {
  NftItemEntry,
  Page,
  PageOptions,
} from "../node-client.js";
import type {
  HexString,
  NftCollection,
  NftItem,
  NftMetadataJson,
  WebcAddress,
} from "../types.js";
import {
  burnNft,
  createNftCollection,
  deriveNftCollectionIdHex,
  freezeNftItem,
  mintNft,
  thawNftItem,
  transferNft,
} from "../transaction.js";
import {
  SigningClient,
  type SubmitOutcome,
  type TxOverrides,
} from "./common.js";

/**
 * Arguments for {@link NftClient.createCollection}. Mirrors the low-level
 * `createNftCollection` builder: `metadata.name`/`metadata.symbol` are the
 * LOWERCASE HEX of their UTF-8 bytes, `maxSupply` is an optional hard cap (`null` =
 * no cap), `royaltyBps` is a recorded-only royalty (≤ 10000), and the collection id
 * is derived on-chain from `(namespace, creator, createNonce)` where the creator is
 * the signer.
 */
export interface CreateNftCollectionArgs {
  /** 32-byte lowercase-hex namespace the collection is created under. */
  readonly namespace: HexString;
  /** Creator-chosen nonce; disambiguates collections under the same namespace. */
  readonly createNonce: number;
  /** Validated bounded metadata (name/symbol lowercase hex, commitment). */
  readonly metadata: NftMetadataJson;
  /** Initial mint (and pause) authority, or `null` to renounce minting at birth. */
  readonly mintAuthority: WebcAddress | null;
  /** Initial freeze/thaw authority, or `null` to renounce freezing at birth. */
  readonly freezeAuthority: WebcAddress | null;
  /** Optional hard cap on total items ever minted, or `null` for no cap. */
  readonly maxSupply: number | null;
  /** Creator royalty commitment in basis points (≤ 10000; metadata only). */
  readonly royaltyBps: number;
}

/** Result of a collection write: the submit outcome plus the affected collection id. */
export interface NftCollectionResult extends SubmitOutcome {
  /** The collection id the write applies to, 32-byte lowercase hex. */
  readonly collectionId: HexString;
}

/**
 * High-level client for native NFTs: create a collection, mint/transfer/burn items,
 * freeze/thaw an item, and the collection/item reads. Construct it with a
 * `WebcNodeClient` and a signer; every method signs with that signer.
 */
export class NftClient extends SigningClient {
  /**
   * Creates an NFT collection. Builds `CreateNftCollection`, lets `signTransaction`
   * derive the default access list, submits, and returns the receipt plus the
   * client-derived collection id (identical to the id the chain assigns from
   * `(namespace, creator, createNonce)`).
   */
  async createCollection(
    args: CreateNftCollectionArgs,
    overrides: TxOverrides = {},
  ): Promise<NftCollectionResult> {
    const operation = createNftCollection({
      namespace: args.namespace,
      createNonce: args.createNonce,
      metadata: args.metadata,
      mintAuthority: args.mintAuthority,
      freezeAuthority: args.freezeAuthority,
      maxSupply: args.maxSupply,
      royaltyBps: args.royaltyBps,
    });
    const collectionId = await deriveNftCollectionIdHex(
      args.namespace,
      this.signer.address,
      args.createNonce,
    );
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, collectionId };
  }

  /**
   * Mints a new item of a collection to `recipient` (signer = mint authority).
   * Builds `MintNft` with the default access list and submits. The fresh item's
   * serial is chain-assigned; read it back with {@link listItems} or the receipt.
   */
  async mintItem(
    collectionId: HexString,
    recipient: WebcAddress,
    itemMetadataHash: HexString,
    overrides: TxOverrides = {},
  ): Promise<NftCollectionResult> {
    const operation = mintNft(collectionId, recipient, itemMetadataHash);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, collectionId };
  }

  /**
   * Transfers one item (by serial) to `recipient` (signer = current owner). Builds
   * `TransferNft` with the default access list and submits.
   */
  async transfer(
    collectionId: HexString,
    serial: number,
    recipient: WebcAddress,
    overrides: TxOverrides = {},
  ): Promise<NftCollectionResult> {
    const operation = transferNft(collectionId, serial, recipient);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, collectionId };
  }

  /**
   * Burns one item (by serial) held by the signer. Builds `BurnNft` with the
   * default access list and submits.
   */
  async burn(
    collectionId: HexString,
    serial: number,
    overrides: TxOverrides = {},
  ): Promise<NftCollectionResult> {
    const operation = burnNft(collectionId, serial);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, collectionId };
  }

  /**
   * Freezes one item (signer = freeze authority). Builds `FreezeNftItem` with the
   * default access list and submits.
   */
  async freeze(
    collectionId: HexString,
    serial: number,
    overrides: TxOverrides = {},
  ): Promise<NftCollectionResult> {
    const operation = freezeNftItem(collectionId, serial);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, collectionId };
  }

  /**
   * Thaws (unfreezes) one item (signer = freeze authority). Builds `ThawNftItem`
   * with the default access list and submits.
   */
  async thaw(
    collectionId: HexString,
    serial: number,
    overrides: TxOverrides = {},
  ): Promise<NftCollectionResult> {
    const operation = thawNftItem(collectionId, serial);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, collectionId };
  }

  /**
   * Reads a collection's authority/supply record by id. Thin wrapper over
   * `getNftCollection`.
   */
  async getCollection(collectionId: HexString): Promise<NftCollection> {
    return this.node.getNftCollection(collectionId);
  }

  /** Reads one item by collection id and serial. Thin wrapper over `getNftItem`. */
  async getItem(collectionId: HexString, serial: number): Promise<NftItem> {
    return this.node.getNftItem(collectionId, serial);
  }

  /**
   * Pages a collection's items via the collection-items endpoint. Thin wrapper over
   * `listNftCollectionItems`; each entry carries the item's serial alongside its
   * full record.
   */
  async listItems(
    collectionId: HexString,
    options: PageOptions = {},
  ): Promise<Page<NftItemEntry>> {
    return this.node.listNftCollectionItems(collectionId, options);
  }
}
