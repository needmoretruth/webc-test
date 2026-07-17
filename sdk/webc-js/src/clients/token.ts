/**
 * `TokenClient` — the ergonomic entry point for native fungible tokens on WEBC
 * (Phase 13a, §15). It COMPOSES the reviewed low-level SDK into the flows a token
 * issuer or holder actually performs:
 *
 *   - create a token and mint / burn / transfer its units (build -> sign -> submit);
 *   - pause transfers and freeze / thaw a holder's balance (build -> sign -> submit);
 *   - read a token record, a holder balance, the supply reconciliation, and page an
 *     address's held balances.
 *
 * It introduces no new operation, access list, or wire format: every write goes
 * through a `transaction.ts` builder and lets `signTransaction` derive the default
 * access list (the same list the low-level API auto-derives for these ops — none is
 * state-derived). The client-derived token id on create is computed with the SAME
 * `deriveTokenIdHex` the builder documents.
 *
 * ## Signer role
 * Each write signs an ordinary account transaction with this client's `signer`: the
 * token's mint authority (create / mint / pause), the freeze authority (freeze /
 * thaw), or the holder (burn / transfer). Construct the client with whichever
 * `signer` is authorized for the flow.
 */

import type {
  Page,
  PageOptions,
  TokenBalanceEntry,
} from "../node-client.js";
import type {
  HexString,
  TokenMetadataJson,
  TokenRecord,
  TokenSupplyReport,
  WebcAddress,
} from "../types.js";
import {
  burnToken,
  createToken,
  deriveTokenIdHex,
  freezeTokenAccount,
  mintToken,
  setTokenPaused,
  thawTokenAccount,
  transferToken,
} from "../transaction.js";
import {
  SigningClient,
  type SubmitOutcome,
  type TxOverrides,
} from "./common.js";

/**
 * Arguments for {@link TokenClient.create}. Mirrors the low-level `createToken`
 * builder: `metadata.name`/`metadata.symbol` are the LOWERCASE HEX of their UTF-8
 * bytes, and the token id is derived on-chain from `(namespace, creator,
 * createNonce)` where the creator is the signer.
 */
export interface CreateTokenArgs {
  /** 32-byte lowercase-hex namespace the token is created under. */
  readonly namespace: HexString;
  /** Creator-chosen nonce; disambiguates tokens under the same namespace. */
  readonly createNonce: number;
  /** Validated bounded metadata (name/symbol lowercase hex, decimals, commitment). */
  readonly metadata: TokenMetadataJson;
  /** Initial mint (and pause) authority, or `null` to renounce minting at birth. */
  readonly mintAuthority: WebcAddress | null;
  /** Initial freeze/thaw authority, or `null` to renounce freezing at birth. */
  readonly freezeAuthority: WebcAddress | null;
  /** Units minted to `initialRecipient` at creation (decimal string). */
  readonly initialSupply: string;
  /** Account credited the initial supply. */
  readonly initialRecipient: WebcAddress;
}

/** Result of a token write: the submit outcome plus the affected token id. */
export interface TokenResult extends SubmitOutcome {
  /** The token id the write applies to, 32-byte lowercase hex. */
  readonly tokenId: HexString;
}

/**
 * High-level client for native fungible tokens: create/mint/burn/transfer,
 * pause/freeze/thaw, and the token/balance/supply reads. Construct it with a
 * `WebcNodeClient` and a signer; every method signs with that signer.
 */
export class TokenClient extends SigningClient {
  /**
   * Creates a native token. Builds `CreateToken`, lets `signTransaction` derive the
   * default access list, submits, and returns the receipt plus the client-derived
   * token id (identical to the id the chain assigns from `(namespace, creator,
   * createNonce)`).
   */
  async create(
    args: CreateTokenArgs,
    overrides: TxOverrides = {},
  ): Promise<TokenResult> {
    const operation = createToken({
      namespace: args.namespace,
      createNonce: args.createNonce,
      metadata: args.metadata,
      mintAuthority: args.mintAuthority,
      freezeAuthority: args.freezeAuthority,
      initialSupply: args.initialSupply,
      initialRecipient: args.initialRecipient,
    });
    const tokenId = await deriveTokenIdHex(
      args.namespace,
      this.signer.address,
      args.createNonce,
    );
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, tokenId };
  }

  /**
   * Mints `amount` units of a token to `recipient` (signer = mint authority). Builds
   * `MintToken` with the default access list and submits.
   */
  async mint(
    tokenId: HexString,
    recipient: WebcAddress,
    amount: string,
    overrides: TxOverrides = {},
  ): Promise<TokenResult> {
    const operation = mintToken(tokenId, recipient, amount);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, tokenId };
  }

  /**
   * Burns `amount` units of a token from the signer's balance. Builds `BurnToken`
   * with the default access list and submits.
   */
  async burn(
    tokenId: HexString,
    amount: string,
    overrides: TxOverrides = {},
  ): Promise<TokenResult> {
    const operation = burnToken(tokenId, amount);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, tokenId };
  }

  /**
   * Transfers `amount` token units from the signer to `recipient`. Builds
   * `TransferToken` with the default access list and submits.
   */
  async transfer(
    tokenId: HexString,
    recipient: WebcAddress,
    amount: string,
    overrides: TxOverrides = {},
  ): Promise<TokenResult> {
    const operation = transferToken(tokenId, recipient, amount);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, tokenId };
  }

  /**
   * Pauses or unpauses all transfers of a token (signer = mint authority). Builds
   * `SetTokenPaused` with the default access list and submits.
   */
  async setPaused(
    tokenId: HexString,
    paused: boolean,
    overrides: TxOverrides = {},
  ): Promise<TokenResult> {
    const operation = setTokenPaused(tokenId, paused);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, tokenId };
  }

  /**
   * Freezes one account's balance of a token (signer = freeze authority). Builds
   * `FreezeTokenAccount` with the default access list and submits.
   */
  async freeze(
    tokenId: HexString,
    account: WebcAddress,
    overrides: TxOverrides = {},
  ): Promise<TokenResult> {
    const operation = freezeTokenAccount(tokenId, account);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, tokenId };
  }

  /**
   * Thaws (unfreezes) one account's balance of a token (signer = freeze authority).
   * Builds `ThawTokenAccount` with the default access list and submits.
   */
  async thaw(
    tokenId: HexString,
    account: WebcAddress,
    overrides: TxOverrides = {},
  ): Promise<TokenResult> {
    const operation = thawTokenAccount(tokenId, account);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, tokenId };
  }

  /** Reads a token's authority/supply record by id. Thin wrapper over `getToken`. */
  async getToken(tokenId: HexString): Promise<TokenRecord> {
    return this.node.getToken(tokenId);
  }

  /**
   * Reads a holder's balance of a token as a decimal string of base units. A known
   * token with no balance entry for the holder reads back as `"0"`. Thin wrapper
   * over `getTokenBalance`.
   */
  async getBalance(tokenId: HexString, address: WebcAddress): Promise<string> {
    return this.node.getTokenBalance(tokenId, address);
  }

  /** Reads a token's supply reconciliation. Thin wrapper over `getTokenSupply`. */
  async getSupply(tokenId: HexString): Promise<TokenSupplyReport> {
    return this.node.getTokenSupply(tokenId);
  }

  /**
   * Pages the token balances held by `address` via the account token-balances
   * endpoint. Thin wrapper over `listAccountTokenBalances`; each entry carries a
   * held token id and the balance as a decimal string.
   */
  async listHolderBalances(
    address: WebcAddress,
    options: PageOptions = {},
  ): Promise<Page<TokenBalanceEntry>> {
    return this.node.listAccountTokenBalances(address, options);
  }
}
