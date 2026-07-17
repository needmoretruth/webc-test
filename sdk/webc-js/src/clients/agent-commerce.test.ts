/**
 * Tests for `AgentCommerceClient` (`clients/agent-commerce.ts`).
 *
 * The `WebcNodeClient` is MOCKED (its read + submit methods) — no network is
 * touched — while a real `WebcWallet` signs. Each write is pinned against the EXACT
 * operation JSON and access list the low-level `transaction.ts` builders/helpers
 * produce, so any drift from the composed primitives fails the test; the read/list
 * helpers are asserted against mocked node responses. `payForResource` is checked
 * end-to-end AND for its fail-closed behaviour: a price/pay-to-mismatched challenge
 * is rejected against the fetched on-chain entry with NO transaction submitted.
 */

import { describe, expect, it } from "vitest";

import { bytesToHex } from "../hex.js";
import { canonicalJson } from "../canonical.js";
import { createWalletFromSeed } from "../wallet.js";
import type { WebcWallet } from "../wallet.js";
import type { AccountView, SubmitReceipt, WebcNodeClient } from "../node-client.js";
import type { Mandate, SignedTransactionJson } from "../types.js";
import type { ServiceEntry } from "../http402.js";
import {
  DEFAULT_AUTHORIZATION_LANE,
  accessListForServiceSpend,
  defaultAccessListAsync,
  deriveMandateIdHex,
  grantMandate,
  revokeMandate,
  spendUnderMandateToService,
  topUpMandate,
  transactionHashHex,
  verifySignedTransaction,
} from "../transaction.js";
import { AgentCommerceClient } from "./agent-commerce.js";

const SERVICE_ID = "88".repeat(32);
const SERVICE_ID_B = "77".repeat(32);
const MANDATE_ID = "99".repeat(32);
const OP_INFER = "11".repeat(32);
const INVOICE_NONCE = "deadbeef";
const PRICE = "1000";
const EXPIRY = 2_000_000_000;
const NOW = 1_000_000_000;
const CHAIN_ID = "webc-devnet-1";
const FEE = { gasLimit: 1000, maxFeePerUnit: 1, priorityFeePerUnit: 0 };

function walletFromSeedByte(byte: number): Promise<WebcWallet> {
  return createWalletFromSeed(new Uint8Array(32).fill(byte));
}

function hexOfText(text: string): string {
  return bytesToHex(new TextEncoder().encode(text));
}

function mkEntry(owner: string, serviceId = SERVICE_ID): ServiceEntry {
  return {
    service_id: serviceId,
    owner,
    status: "Active",
    pricing: [{ operation: OP_INFER, price: PRICE, unit: hexOfText("call") }],
    payment_flags: { on_chain_direct: true, http_402: true, subscription: false },
  };
}

function mkChallenge(owner: string) {
  return {
    service_id: SERVICE_ID,
    operation: OP_INFER,
    price: { amount: PRICE, asset: "NativeWebc" as const },
    pay_to: owner,
    invoice_nonce: INVOICE_NONCE,
    expiry: EXPIRY,
  };
}

function mkMandate(principal: string, agentKey: string): Mandate {
  return {
    principal,
    agent_key: agentKey,
    budget_total: "1000",
    spent: "0",
    expiry_epoch: 100,
    per_tx_max: "100",
    rate_limit_per_day: 5,
    counterparty_policy: "Open",
    revoked: false,
    window_index: 0,
    spends_in_window: 0,
  };
}

interface MockHandlers {
  services?: Record<string, ServiceEntry>;
  serviceList?: { items: readonly string[]; nextCursor: string | null };
  mandates?: Record<string, Mandate>;
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
    async getService(id: string): Promise<ServiceEntry> {
      const entry = handlers.services?.[id];
      if (!entry) throw new Error(`no mocked service ${id}`);
      return entry;
    },
    async getMandate(id: string): Promise<Mandate> {
      const mandate = handlers.mandates?.[id];
      if (!mandate) throw new Error(`no mocked mandate ${id}`);
      return mandate;
    },
    async listServices(options: unknown) {
      listCalls.push(options);
      return handlers.serviceList ?? { items: [], nextCursor: null };
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

describe("AgentCommerceClient mandate writes", () => {
  it("grantMandate pins the op + default access list, signs, submits, derives the id", async () => {
    const principal = await walletFromSeedByte(1);
    const agentKey = bytesToHex((await walletFromSeedByte(9)).publicKey);
    const { node, submitted } = makeNode();
    const client = new AgentCommerceClient({ node, signer: principal, chainId: CHAIN_ID, fee: FEE });

    const args = {
      agentKey,
      grantNonce: 3,
      budgetTotal: "1000",
      expiryEpoch: 100,
      perTxMax: "100",
      rateLimitPerDay: 5,
      counterpartyPolicy: "Open" as const,
    };
    const result = await client.grantMandate(args, { nonce: 0 });

    // Byte-identical to the low-level builder.
    expect(canonicalJson(result.transaction.operation)).toBe(canonicalJson(grantMandate(args)));
    // Access list is the generic default the low-level API derives.
    expect(result.transaction.access_list).toEqual(
      await defaultAccessListAsync(principal.address, grantMandate(args), DEFAULT_AUTHORIZATION_LANE),
    );
    expect(result.transaction.sender).toBe(principal.address);
    expect(await verifySignedTransaction(result.transaction)).toBe(true);
    // The exact signed tx is what was submitted.
    expect(submitted).toHaveLength(1);
    expect(submitted[0]).toBe(result.transaction);
    // Client-derived id matches the builder's on-chain derivation.
    expect(result.mandateId).toBe(await deriveMandateIdHex(principal.address, agentKey, 3));
    expect(result.receipt.accepted).toBe(true);
    expect(result.txHash).toBe(await transactionHashHex(result.transaction));
  });

  it("topUpMandate pins the op + default access list and returns the mandate id", async () => {
    const principal = await walletFromSeedByte(1);
    const { node, submitted } = makeNode();
    const client = new AgentCommerceClient({ node, signer: principal, chainId: CHAIN_ID, fee: FEE });

    const result = await client.topUpMandate(MANDATE_ID, "500", { nonce: 2 });
    expect(canonicalJson(result.transaction.operation)).toBe(canonicalJson(topUpMandate(MANDATE_ID, "500")));
    expect(result.transaction.access_list).toEqual(
      await defaultAccessListAsync(principal.address, topUpMandate(MANDATE_ID, "500"), DEFAULT_AUTHORIZATION_LANE),
    );
    expect(result.mandateId).toBe(MANDATE_ID);
    expect(submitted[0]).toBe(result.transaction);
    expect(await verifySignedTransaction(result.transaction)).toBe(true);
  });

  it("revokeMandate pins the op + default access list and returns the mandate id", async () => {
    const principal = await walletFromSeedByte(1);
    const { node, submitted } = makeNode();
    const client = new AgentCommerceClient({ node, signer: principal, chainId: CHAIN_ID, fee: FEE });

    const result = await client.revokeMandate(MANDATE_ID, { nonce: 5 });
    expect(canonicalJson(result.transaction.operation)).toBe(canonicalJson(revokeMandate(MANDATE_ID)));
    expect(result.transaction.access_list).toEqual(
      await defaultAccessListAsync(principal.address, revokeMandate(MANDATE_ID), DEFAULT_AUTHORIZATION_LANE),
    );
    expect(result.mandateId).toBe(MANDATE_ID);
    expect(submitted[0]).toBe(result.transaction);
  });

  it("resolves chainId from health() and nonce from account() when omitted", async () => {
    const principal = await walletFromSeedByte(1);
    const agentKey = bytesToHex((await walletFromSeedByte(9)).publicKey);
    const { node } = makeNode({ chainId: "webc-test-9", accountNonce: 42 });
    const client = new AgentCommerceClient({ node, signer: principal, fee: FEE });

    const result = await client.grantMandate(
      {
        agentKey,
        grantNonce: 1,
        budgetTotal: "1",
        expiryEpoch: 10,
        perTxMax: "1",
        rateLimitPerDay: 0,
        counterpartyPolicy: "Open",
      },
      {},
    );
    expect(result.transaction.chain_id).toBe("webc-test-9");
    expect(result.transaction.nonce).toBe(42);
  });

  it("throws (and never submits) when no fee is available", async () => {
    const principal = await walletFromSeedByte(1);
    const { node, submitted } = makeNode();
    const client = new AgentCommerceClient({ node, signer: principal, chainId: CHAIN_ID });
    await expect(client.revokeMandate(MANDATE_ID, { nonce: 0 })).rejects.toThrow(/fee/u);
    expect(submitted).toHaveLength(0);
  });
});

describe("AgentCommerceClient.payForResource (HTTP-402 flow)", () => {
  it("fetches the entry via the node, pins the service spend, submits, returns the reference", async () => {
    const agent = await walletFromSeedByte(1);
    const owner = (await walletFromSeedByte(3)).address;
    const { node, submitted } = makeNode({ services: { [SERVICE_ID]: mkEntry(owner) } });
    const client = new AgentCommerceClient({ node, signer: agent, chainId: CHAIN_ID, fee: FEE });

    const result = await client.payForResource({
      challenge: mkChallenge(owner),
      mandateId: MANDATE_ID,
      nonce: 0,
      now: NOW,
    });

    // Byte-identical op + access list to the low-level composition.
    expect(canonicalJson(result.transaction.operation)).toBe(
      canonicalJson(spendUnderMandateToService(MANDATE_ID, SERVICE_ID, PRICE)),
    );
    expect(result.transaction.access_list).toEqual(
      accessListForServiceSpend({
        sender: agent.address,
        mandateId: MANDATE_ID,
        serviceId: SERVICE_ID,
        serviceOwner: owner,
      }),
    );
    expect(result.transaction.sender).toBe(agent.address);
    expect(await verifySignedTransaction(result.transaction)).toBe(true);
    expect(result.reference).toEqual({
      mandate_id: MANDATE_ID,
      service_id: SERVICE_ID,
      tx_hash: await transactionHashHex(result.transaction),
      invoice_nonce: INVOICE_NONCE,
    });
    expect(submitted).toHaveLength(1);
    expect(submitted[0]).toBe(result.transaction);
  });

  it("cross-checks price against the FETCHED entry and fails closed (no submit)", async () => {
    const agent = await walletFromSeedByte(1);
    const owner = (await walletFromSeedByte(3)).address;
    const { node, submitted } = makeNode({ services: { [SERVICE_ID]: mkEntry(owner) } });
    const client = new AgentCommerceClient({ node, signer: agent, chainId: CHAIN_ID, fee: FEE });

    await expect(
      client.payForResource({
        challenge: { ...mkChallenge(owner), price: { amount: "5000", asset: "NativeWebc" } },
        mandateId: MANDATE_ID,
        nonce: 0,
        now: NOW,
      }),
    ).rejects.toMatchObject({ name: "ChallengeError", code: "price_mismatch" });
    expect(submitted).toHaveLength(0);
  });

  it("rejects a pay_to-diverted challenge and never submits (fail-closed)", async () => {
    const agent = await walletFromSeedByte(1);
    const owner = (await walletFromSeedByte(3)).address;
    const attacker = (await walletFromSeedByte(7)).address;
    const { node, submitted } = makeNode({ services: { [SERVICE_ID]: mkEntry(owner) } });
    const client = new AgentCommerceClient({ node, signer: agent, chainId: CHAIN_ID, fee: FEE });

    await expect(
      client.payForResource({
        challenge: { ...mkChallenge(owner), pay_to: attacker },
        mandateId: MANDATE_ID,
        nonce: 0,
        now: NOW,
      }),
    ).rejects.toMatchObject({ name: "ChallengeError", code: "pay_to_mismatch" });
    expect(submitted).toHaveLength(0);
  });
});

describe("AgentCommerceClient reads", () => {
  it("discoverServices lists ids then hydrates each entry via getService", async () => {
    const owner = (await walletFromSeedByte(3)).address;
    const { node, listCalls } = makeNode({
      services: {
        [SERVICE_ID]: mkEntry(owner, SERVICE_ID),
        [SERVICE_ID_B]: mkEntry(owner, SERVICE_ID_B),
      },
      serviceList: { items: [SERVICE_ID, SERVICE_ID_B], nextCursor: "cursor-2" },
    });
    const client = new AgentCommerceClient({ node, signer: await walletFromSeedByte(1), chainId: CHAIN_ID, fee: FEE });

    const category = "cc".repeat(32);
    const discovered = await client.discoverServices({ category });
    expect(discovered.services.map((service) => service.service_id)).toEqual([SERVICE_ID, SERVICE_ID_B]);
    expect(discovered.nextCursor).toBe("cursor-2");
    // The filter is threaded through to the list endpoint verbatim.
    expect(listCalls).toEqual([{ category }]);
  });

  it("getMandateStatus wraps getMandate", async () => {
    const principal = await walletFromSeedByte(1);
    const agentKey = bytesToHex((await walletFromSeedByte(9)).publicKey);
    const mandate = mkMandate(principal.address, agentKey);
    const { node } = makeNode({ mandates: { [MANDATE_ID]: mandate } });
    const client = new AgentCommerceClient({ node, signer: principal, chainId: CHAIN_ID, fee: FEE });

    expect(await client.getMandateStatus(MANDATE_ID)).toEqual(mandate);
  });
});
