/**
 * Tests for `TokenClient` (`clients/token.ts`).
 *
 * The `WebcNodeClient` is MOCKED (its read + submit methods) — no network is
 * touched — while a real `WebcWallet` signs. Each write is pinned against the EXACT
 * operation JSON AND the EXACT default access list the low-level `transaction.ts`
 * builders produce (none of these ops is state-derived), so any drift from the
 * composed primitives fails the test. Reads are asserted against mocked responses,
 * and a fail-closed case (invalid metadata) is rejected before any submit.
 */

import { describe, expect, it } from "vitest";

import { bytesToHex } from "../hex.js";
import { canonicalJson } from "../canonical.js";
import { createWalletFromSeed } from "../wallet.js";
import type { WebcWallet } from "../wallet.js";
import type { AccountView, SubmitReceipt, WebcNodeClient } from "../node-client.js";
import type {
  SignedTransactionJson,
  TokenMetadataJson,
  TokenRecord,
  TokenSupplyReport,
} from "../types.js";
import {
  DEFAULT_AUTHORIZATION_LANE,
  burnToken,
  createToken,
  defaultAccessListAsync,
  deriveTokenIdHex,
  freezeTokenAccount,
  mintToken,
  setTokenPaused,
  thawTokenAccount,
  transferToken,
  transactionHashHex,
  verifySignedTransaction,
} from "../transaction.js";
import { TokenClient } from "./token.js";

const TOKEN_ID = "aa".repeat(32);
const NAMESPACE = "dd".repeat(32);
const CHAIN_ID = "webc-devnet-1";
const FEE = { gasLimit: 1000, maxFeePerUnit: 1, priorityFeePerUnit: 0 };

function hexOfText(text: string): string {
  return bytesToHex(new TextEncoder().encode(text));
}

const METADATA: TokenMetadataJson = {
  name: hexOfText("Gold"),
  symbol: hexOfText("GLD"),
  decimals: 6,
  metadata_hash: "11".repeat(32),
};

const SUPPLY: TokenSupplyReport = { issued: "1000", held: "1000", balanced: true };

function walletFromSeedByte(byte: number): Promise<WebcWallet> {
  return createWalletFromSeed(new Uint8Array(32).fill(byte));
}

function mkToken(creator: string): TokenRecord {
  return {
    creator,
    metadata: METADATA,
    mint_authority: creator,
    freeze_authority: creator,
    paused: false,
    issued_supply: "1000",
  };
}

interface MockHandlers {
  tokens?: Record<string, TokenRecord>;
  balance?: string;
  supply?: TokenSupplyReport;
  balancePage?: { items: readonly unknown[]; nextCursor: string | null };
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
    async getToken(id: string): Promise<TokenRecord> {
      const token = handlers.tokens?.[id];
      if (!token) throw new Error(`no mocked token ${id}`);
      return token;
    },
    async getTokenBalance(_id: string, _address: string): Promise<string> {
      return handlers.balance ?? "0";
    },
    async getTokenSupply(_id: string): Promise<TokenSupplyReport> {
      return handlers.supply ?? SUPPLY;
    },
    async listAccountTokenBalances(address: string, options: unknown) {
      listCalls.push({ address, options });
      return handlers.balancePage ?? { items: [], nextCursor: null };
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

describe("TokenClient writes", () => {
  it("create pins the op + default access list, signs, submits, derives the id", async () => {
    const creator = await walletFromSeedByte(1);
    const recipient = (await walletFromSeedByte(2)).address;
    const { node, submitted } = makeNode();
    const client = new TokenClient({ node, signer: creator, chainId: CHAIN_ID, fee: FEE });

    const args = {
      namespace: NAMESPACE,
      createNonce: 4,
      metadata: METADATA,
      mintAuthority: creator.address,
      freezeAuthority: creator.address,
      initialSupply: "1000",
      initialRecipient: recipient,
    };
    const result = await client.create(args, { nonce: 0 });

    expect(canonicalJson(result.transaction.operation)).toBe(canonicalJson(createToken(args)));
    await expectDefaultAccessList(creator.address, result.transaction, createToken(args));
    expect(result.tokenId).toBe(await deriveTokenIdHex(NAMESPACE, creator.address, 4));
    expect(await verifySignedTransaction(result.transaction)).toBe(true);
    expect(submitted).toHaveLength(1);
    expect(submitted[0]).toBe(result.transaction);
    expect(result.txHash).toBe(await transactionHashHex(result.transaction));
  });

  it("mint pins the op + default access list and returns the token id", async () => {
    const signer = await walletFromSeedByte(1);
    const recipient = (await walletFromSeedByte(2)).address;
    const { node, submitted } = makeNode();
    const client = new TokenClient({ node, signer, chainId: CHAIN_ID, fee: FEE });

    const result = await client.mint(TOKEN_ID, recipient, "250", { nonce: 1 });
    expect(canonicalJson(result.transaction.operation)).toBe(
      canonicalJson(mintToken(TOKEN_ID, recipient, "250")),
    );
    await expectDefaultAccessList(signer.address, result.transaction, mintToken(TOKEN_ID, recipient, "250"));
    expect(result.tokenId).toBe(TOKEN_ID);
    expect(submitted[0]).toBe(result.transaction);
    expect(await verifySignedTransaction(result.transaction)).toBe(true);
  });

  it("burn pins the op + default access list", async () => {
    const signer = await walletFromSeedByte(1);
    const { node, submitted } = makeNode();
    const client = new TokenClient({ node, signer, chainId: CHAIN_ID, fee: FEE });

    const result = await client.burn(TOKEN_ID, "10", { nonce: 2 });
    expect(canonicalJson(result.transaction.operation)).toBe(canonicalJson(burnToken(TOKEN_ID, "10")));
    await expectDefaultAccessList(signer.address, result.transaction, burnToken(TOKEN_ID, "10"));
    expect(result.tokenId).toBe(TOKEN_ID);
    expect(submitted[0]).toBe(result.transaction);
  });

  it("transfer pins the op + default access list", async () => {
    const signer = await walletFromSeedByte(1);
    const recipient = (await walletFromSeedByte(3)).address;
    const { node, submitted } = makeNode();
    const client = new TokenClient({ node, signer, chainId: CHAIN_ID, fee: FEE });

    const result = await client.transfer(TOKEN_ID, recipient, "40", { nonce: 3 });
    expect(canonicalJson(result.transaction.operation)).toBe(
      canonicalJson(transferToken(TOKEN_ID, recipient, "40")),
    );
    await expectDefaultAccessList(signer.address, result.transaction, transferToken(TOKEN_ID, recipient, "40"));
    expect(result.tokenId).toBe(TOKEN_ID);
    expect(submitted[0]).toBe(result.transaction);
  });

  it("setPaused pins the op + default access list", async () => {
    const signer = await walletFromSeedByte(1);
    const { node, submitted } = makeNode();
    const client = new TokenClient({ node, signer, chainId: CHAIN_ID, fee: FEE });

    const result = await client.setPaused(TOKEN_ID, true, { nonce: 4 });
    expect(canonicalJson(result.transaction.operation)).toBe(canonicalJson(setTokenPaused(TOKEN_ID, true)));
    await expectDefaultAccessList(signer.address, result.transaction, setTokenPaused(TOKEN_ID, true));
    expect(submitted[0]).toBe(result.transaction);
  });

  it("freeze / thaw pin their op + default access list", async () => {
    const signer = await walletFromSeedByte(1);
    const account = (await walletFromSeedByte(6)).address;
    const { node, submitted } = makeNode();
    const client = new TokenClient({ node, signer, chainId: CHAIN_ID, fee: FEE });

    const frozen = await client.freeze(TOKEN_ID, account, { nonce: 5 });
    expect(canonicalJson(frozen.transaction.operation)).toBe(
      canonicalJson(freezeTokenAccount(TOKEN_ID, account)),
    );
    await expectDefaultAccessList(signer.address, frozen.transaction, freezeTokenAccount(TOKEN_ID, account));

    const thawed = await client.thaw(TOKEN_ID, account, { nonce: 6 });
    expect(canonicalJson(thawed.transaction.operation)).toBe(
      canonicalJson(thawTokenAccount(TOKEN_ID, account)),
    );
    await expectDefaultAccessList(signer.address, thawed.transaction, thawTokenAccount(TOKEN_ID, account));
    expect(submitted).toHaveLength(2);
  });

  it("throws (and never submits) invalid metadata before signing (fail-closed)", async () => {
    const creator = await walletFromSeedByte(1);
    const recipient = (await walletFromSeedByte(2)).address;
    const { node, submitted } = makeNode();
    const client = new TokenClient({ node, signer: creator, chainId: CHAIN_ID, fee: FEE });

    await expect(
      client.create(
        {
          namespace: NAMESPACE,
          createNonce: 0,
          metadata: { ...METADATA, decimals: 19 },
          mintAuthority: creator.address,
          freezeAuthority: creator.address,
          initialSupply: "0",
          initialRecipient: recipient,
        },
        { nonce: 0 },
      ),
    ).rejects.toThrow(/decimals/u);
    expect(submitted).toHaveLength(0);
  });
});

describe("TokenClient reads", () => {
  it("getToken / getBalance / getSupply wrap the node reads", async () => {
    const creator = await walletFromSeedByte(1);
    const token = mkToken(creator.address);
    const { node } = makeNode({ tokens: { [TOKEN_ID]: token }, balance: "42", supply: SUPPLY });
    const client = new TokenClient({ node, signer: creator, chainId: CHAIN_ID, fee: FEE });

    expect(await client.getToken(TOKEN_ID)).toEqual(token);
    expect(await client.getBalance(TOKEN_ID, creator.address)).toBe("42");
    expect(await client.getSupply(TOKEN_ID)).toEqual(SUPPLY);
  });

  it("listHolderBalances threads the address + options through to the endpoint", async () => {
    const holder = await walletFromSeedByte(1);
    const page = { items: [{ tokenId: TOKEN_ID, balance: "5" }], nextCursor: "cursor-2" as string | null };
    const { node, listCalls } = makeNode({ balancePage: page });
    const client = new TokenClient({ node, signer: holder, chainId: CHAIN_ID, fee: FEE });

    const result = await client.listHolderBalances(holder.address, { limit: 10 });
    expect(result).toEqual(page);
    expect(listCalls).toEqual([{ address: holder.address, options: { limit: 10 } }]);
  });
});
