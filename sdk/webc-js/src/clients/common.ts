/**
 * Shared plumbing for the high-level WEBC client classes (`clients/`).
 *
 * The high-level clients COMPOSE the reviewed low-level SDK: they build an
 * `OperationJson` with a `transaction.ts` builder, compute the access list with
 * the matching `accessListFor*` helper (or let `signTransaction` derive the
 * generic default), sign with `signTransaction`, submit through a
 * `WebcNodeClient`, and expose the client-derived id. This module holds the parts
 * every client repeats: how a submit resolves its transaction context (chain id,
 * nonce, fee, lane) and the shared result shape. It introduces NO new operation,
 * parser, or wire format — only orchestration over the existing primitives.
 */

import type {
  SubmitReceipt,
  WebcNodeClient,
} from "../node-client.js";
import type {
  AuthorizationLaneIdJson,
  FeeBid,
  OperationJson,
  SignedTransactionJson,
  StateAccessListJson,
} from "../types.js";
import type { WebcWallet } from "../wallet.js";
import {
  CURRENT_TRANSACTION_PROTOCOL_VERSION,
  DEFAULT_AUTHORIZATION_LANE,
  signTransaction,
  transactionHashHex,
} from "../transaction.js";

/**
 * Construction config shared by every high-level client. A `WebcNodeClient` reads
 * state and relays signed transactions; the `signer` is an in-process
 * {@link WebcWallet} (from `createWalletFromSeed` / the wallet-derivation APIs)
 * whose key never leaves the trusted context.
 *
 * `chainId` and `fee` are optional DEFAULTS applied to every submit that does not
 * override them. When `chainId` is omitted it is resolved once per submit from the
 * node's `health()`; when `fee` is omitted every submit MUST pass its own `fee`.
 */
export interface SigningClientConfig {
  /** Node client used for reads, list endpoints, and `submitTransaction`. */
  readonly node: WebcNodeClient;
  /** In-process wallet that signs each transaction this client submits. */
  readonly signer: WebcWallet;
  /** Default chain id every submit signs for unless a call overrides it. */
  readonly chainId?: string;
  /** Default fee bid applied to every submit that does not pass its own. */
  readonly fee?: FeeBid;
}

/**
 * Per-call transaction-context overrides accepted by every submit method. Each
 * field falls back to the client default (then, for `chainId`/`nonce`, to a node
 * lookup) so the common case needs no boilerplate while advanced callers stay in
 * full control.
 */
export interface TxOverrides {
  /**
   * Account nonce to sign under. Omit to resolve the signer's current nonce from
   * the node (`account(...).nonce`) at submit time.
   */
  readonly nonce?: number;
  /** Fee bid for this transaction (overrides the client default). */
  readonly fee?: FeeBid;
  /** Chain id for this transaction (overrides the client default / node lookup). */
  readonly chainId?: string;
  /** Non-default authorization lane the transaction is charged to. */
  readonly authorizationLane?: AuthorizationLaneIdJson;
  /** Authorization-policy revision the signer signs under (default 0). */
  readonly authorizationPolicyRevision?: number;
}

/**
 * The outcome of a build->sign->submit flow: the node's {@link SubmitReceipt}, the
 * exact `SignedTransactionJson` that was relayed (so callers can inspect its
 * operation, access list, or signature), and the transaction hash. Client methods
 * that create a keyed object extend this with the client-derived id.
 */
export interface SubmitOutcome {
  /** The node's acceptance receipt for the submitted transaction. */
  readonly receipt: SubmitReceipt;
  /** The signed transaction that was submitted. */
  readonly transaction: SignedTransactionJson;
  /** Hash of the submitted transaction, 32-byte lowercase hex. */
  readonly txHash: string;
}

/**
 * Base class for the high-level clients. Holds the node + signer and centralizes
 * transaction-context resolution and the sign+submit step. Subclasses build the
 * operation and (for state-derived ops) the access list, then call
 * {@link signAndSubmit}; this class never invents an operation or access list.
 */
export abstract class SigningClient {
  /** Node client used for reads, list endpoints, and submission. */
  readonly node: WebcNodeClient;
  /** Wallet that signs this client's transactions. */
  readonly signer: WebcWallet;
  readonly #chainId?: string;
  readonly #fee?: FeeBid;

  constructor(config: SigningClientConfig) {
    this.node = config.node;
    this.signer = config.signer;
    this.#chainId = config.chainId;
    this.#fee = config.fee;
  }

  /** Resolves the chain id: call override, then client default, then node health. */
  protected async resolveChainId(overrides: TxOverrides): Promise<string> {
    if (overrides.chainId !== undefined) {
      return overrides.chainId;
    }
    if (this.#chainId !== undefined) {
      return this.#chainId;
    }
    return (await this.node.health()).chainId;
  }

  /** Resolves the fee bid: call override, then client default, else throws. */
  protected resolveFee(overrides: TxOverrides): FeeBid {
    const fee = overrides.fee ?? this.#fee;
    if (fee === undefined) {
      throw new Error(
        "no fee bid available: pass a `fee` to this call or configure a default fee on the client",
      );
    }
    return fee;
  }

  /** Resolves the nonce: call override, else the signer's current account nonce. */
  protected async resolveNonce(overrides: TxOverrides): Promise<number> {
    if (overrides.nonce !== undefined) {
      return overrides.nonce;
    }
    return (await this.node.account(this.signer.address)).nonce;
  }

  /**
   * Signs `operation` with the configured signer and submits it, returning the
   * receipt, the signed transaction, and its hash.
   *
   * Pass `accessList` for a STATE-DERIVED operation (built by the matching
   * `accessListFor*` helper with the on-chain key resolved). Pass `undefined` for
   * every other operation: `signTransaction` then derives the generic default
   * access list (`defaultAccessListAsync`), exactly as the low-level API does.
   */
  protected async signAndSubmit(
    operation: OperationJson,
    accessList: StateAccessListJson | undefined,
    overrides: TxOverrides,
  ): Promise<SubmitOutcome> {
    const chainId = await this.resolveChainId(overrides);
    const fee = this.resolveFee(overrides);
    const nonce = await this.resolveNonce(overrides);
    const lane = overrides.authorizationLane ?? DEFAULT_AUTHORIZATION_LANE;
    const transaction = await signTransaction(
      this.signer,
      chainId,
      nonce,
      operation,
      fee,
      accessList,
      lane,
      CURRENT_TRANSACTION_PROTOCOL_VERSION,
      overrides.authorizationPolicyRevision ?? 0,
    );
    const receipt = await this.node.submitTransaction(transaction);
    const txHash = await transactionHashHex(transaction);
    return { receipt, transaction, txHash };
  }
}
