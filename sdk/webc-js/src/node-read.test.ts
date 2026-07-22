/**
 * Tests for the native-state read methods on `WebcNodeClient` (`node-client.ts`,
 * Phase 9/13 GET endpoints) and the HTTP-402 node-fetch convenience
 * (`http402.ts`).
 *
 * Every response is served by a MOCK `fetch` (no network). Each read method is
 * exercised for three things the task requires:
 *   1. a well-formed response parses into the right typed object;
 *   2. a malformed / short / extra-field response is rejected FAIL-CLOSED;
 *   3. a 404 surfaces as the existing `NodeApiError`.
 * The bodies mirror the exact Rust serde JSON (snake_case fields, decimal-string
 * amounts, `webc1` addresses, lowercase-hex ids/keys, `null` for `Option`s).
 */

import { describe, expect, it } from "vitest";

import { addressFromBytes } from "./address.js";
import { bytesToHex } from "./hex.js";
import { NodeApiError, WebcNodeClient, type FetchLike } from "./node-client.js";
import { buildPayment, validateChallengeAgainstSource } from "./http402.js";
import type { PaymentChallenge } from "./http402.js";
import { createWalletFromSeed } from "./wallet.js";

/** Builds a fake `fetch` that serves scripted responses keyed by "METHOD path". */
function fakeFetch(
  routes: Record<string, { ok: boolean; status: number; body: unknown }>,
): { fetchImpl: FetchLike; calls: string[] } {
  const calls: string[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    const method = init?.method ?? "GET";
    const path = url.slice(url.indexOf("/v1"));
    calls.push(`${method} ${path}`);
    const route = routes[`${method} ${path}`];
    if (!route) {
      return {
        ok: false,
        status: 404,
        text: async () => JSON.stringify({ error: "not found", kind: "not_found" }),
      };
    }
    return {
      ok: route.ok,
      status: route.status,
      text: async () => (route.body === undefined ? "" : JSON.stringify(route.body)),
    };
  };
  return { fetchImpl, calls };
}

function client(routes: Parameters<typeof fakeFetch>[0]): WebcNodeClient {
  return new WebcNodeClient("http://node.test", { fetchImpl: fakeFetch(routes).fetchImpl });
}

/** Lowercase hex of a UTF-8 string, matching the SDK's byte-string encoding. */
function hexOfText(text: string): string {
  return bytesToHex(new TextEncoder().encode(text));
}

const ADDR = addressFromBytes(new Uint8Array(32).fill(1));
const ADDR2 = addressFromBytes(new Uint8Array(32).fill(2));
const HASH = "a".repeat(64);
const HASH2 = "b".repeat(64);
const OK = { ok: true, status: 200 } as const;

const TOKEN_ID = "11".repeat(32);
const COLLECTION_ID = "22".repeat(32);
const SERVICE_ID = "33".repeat(32);
const INSTANCE_ID = "44".repeat(32);
const PROPOSAL_ID = "55".repeat(32);
const MANDATE_ID = "66".repeat(32);

const TOKEN_BODY = {
  creator: ADDR,
  metadata: {
    name: hexOfText("Acme Dollar"),
    symbol: hexOfText("ACME"),
    decimals: 6,
    metadata_hash: HASH,
  },
  mint_authority: ADDR,
  freeze_authority: null,
  paused: false,
  issued_supply: "1000",
};

const NFT_COLLECTION_BODY = {
  creator: ADDR,
  metadata: { name: hexOfText("Acme Apes"), symbol: hexOfText("APE"), metadata_hash: HASH },
  mint_authority: ADDR,
  freeze_authority: null,
  paused: false,
  next_serial: 1,
  minted_count: 1,
  burned_count: 0,
  max_supply: null,
  royalty_bps: 500,
};

const SERVICE_BODY = {
  owner: ADDR,
  namespace: HASH2,
  categories: [HASH],
  title: hexOfText("inference"),
  endpoint: hexOfText("https://api.example/infer"),
  interface: HASH,
  pricing: [{ operation: HASH, price: "1000", unit: hexOfText("call") }],
  payment_flags: { on_chain_direct: true, http_402: true, subscription: false },
  status: "Active",
  revision: 1,
};

const GOV_CONFIG = {
  voting_period_epochs: 10,
  timelock_epochs: 3,
  quorum_bps: 2000,
  proposal_threshold: "100",
  approval_threshold_bps: 5000,
};

const INSTANCE_BODY = {
  creator: ADDR,
  weight_token: TOKEN_ID,
  config: GOV_CONFIG,
  treasury: "0",
  next_proposal_nonce: 1,
};

const PROPOSAL_BODY = {
  instance_id: INSTANCE_ID,
  proposer: ADDR,
  weight_token: HASH,
  config: GOV_CONFIG,
  action: "Signaling",
  created_epoch: 1,
  voting_ends_epoch: 11,
  eta_epoch: null,
  status: "Active",
  yes: "150",
  no: "50",
  abstain: "0",
};

const MANDATE_BODY = {
  principal: ADDR,
  agent_key: HASH,
  budget_total: "10000000000000",
  spent: "0",
  expiry_epoch: 100,
  per_tx_max: "100000000000",
  rate_limit_per_day: 5,
  counterparty_policy: "Open",
  revoked: false,
  window_index: 0,
  spends_in_window: 0,
};

describe("WebcNodeClient.getToken", () => {
  it("parses a well-formed token record", async () => {
    const c = client({ [`GET /v1/tokens/${TOKEN_ID}`]: { ...OK, body: TOKEN_BODY } });
    const token = await c.getToken(TOKEN_ID);
    expect(token.creator).toBe(ADDR);
    expect(token.metadata.decimals).toBe(6);
    expect(token.metadata.name).toBe(hexOfText("Acme Dollar"));
    expect(token.mint_authority).toBe(ADDR);
    expect(token.freeze_authority).toBeNull();
    expect(token.paused).toBe(false);
    expect(token.issued_supply).toBe("1000");
  });

  it("rejects an extra field fail-closed", async () => {
    const c = client({
      [`GET /v1/tokens/${TOKEN_ID}`]: { ...OK, body: { ...TOKEN_BODY, surprise: 1 } },
    });
    await expect(c.getToken(TOKEN_ID)).rejects.toThrow(/unexpected field/u);
  });

  it("rejects a short (missing-field) record", async () => {
    const { creator: _drop, ...missing } = TOKEN_BODY;
    const c = client({ [`GET /v1/tokens/${TOKEN_ID}`]: { ...OK, body: missing } });
    await expect(c.getToken(TOKEN_ID)).rejects.toThrow();
  });

  it("rejects a wrong-typed amount", async () => {
    const c = client({
      [`GET /v1/tokens/${TOKEN_ID}`]: { ...OK, body: { ...TOKEN_BODY, issued_supply: 1000 } },
    });
    await expect(c.getToken(TOKEN_ID)).rejects.toThrow(/issued_supply/u);
  });

  it("rejects an out-of-range decimals", async () => {
    const c = client({
      [`GET /v1/tokens/${TOKEN_ID}`]: {
        ...OK,
        body: { ...TOKEN_BODY, metadata: { ...TOKEN_BODY.metadata, decimals: 19 } },
      },
    });
    await expect(c.getToken(TOKEN_ID)).rejects.toThrow(/decimals/u);
  });

  it("surfaces a 404 as NodeApiError", async () => {
    const c = client({});
    await expect(c.getToken(TOKEN_ID)).rejects.toBeInstanceOf(NodeApiError);
    await expect(c.getToken(TOKEN_ID)).rejects.toMatchObject({ status: 404, kind: "not_found" });
  });
});

describe("WebcNodeClient.getTokenBalance", () => {
  it("returns a decimal-string balance", async () => {
    const c = client({
      [`GET /v1/tokens/${TOKEN_ID}/balances/${ADDR}`]: { ...OK, body: "1000" },
    });
    expect(await c.getTokenBalance(TOKEN_ID, ADDR)).toBe("1000");
  });

  it("returns \"0\" for a holder with no balance entry", async () => {
    const c = client({
      [`GET /v1/tokens/${TOKEN_ID}/balances/${ADDR2}`]: { ...OK, body: "0" },
    });
    expect(await c.getTokenBalance(TOKEN_ID, ADDR2)).toBe("0");
  });

  it("rejects a non-canonical amount", async () => {
    const c = client({
      [`GET /v1/tokens/${TOKEN_ID}/balances/${ADDR}`]: { ...OK, body: "01" },
    });
    await expect(c.getTokenBalance(TOKEN_ID, ADDR)).rejects.toThrow(/amount/u);
  });

  it("surfaces a 404 (unknown token) as NodeApiError", async () => {
    const c = client({});
    await expect(c.getTokenBalance(TOKEN_ID, ADDR)).rejects.toBeInstanceOf(NodeApiError);
  });
});

describe("WebcNodeClient.getTokenSupply", () => {
  it("parses a balanced supply report", async () => {
    const c = client({
      [`GET /v1/tokens/${TOKEN_ID}/supply`]: {
        ...OK,
        body: { issued: "1000", held: "1000", balanced: true },
      },
    });
    const report = await c.getTokenSupply(TOKEN_ID);
    expect(report).toEqual({ issued: "1000", held: "1000", balanced: true });
  });

  it("rejects a non-boolean balanced flag", async () => {
    const c = client({
      [`GET /v1/tokens/${TOKEN_ID}/supply`]: {
        ...OK,
        body: { issued: "1000", held: "1000", balanced: "yes" },
      },
    });
    await expect(c.getTokenSupply(TOKEN_ID)).rejects.toThrow(/balanced/u);
  });

  it("surfaces a 404 as NodeApiError", async () => {
    await expect(client({}).getTokenSupply(TOKEN_ID)).rejects.toBeInstanceOf(NodeApiError);
  });
});

describe("WebcNodeClient.getNftCollection", () => {
  it("parses a collection record with a null cap", async () => {
    const c = client({
      [`GET /v1/nft/collections/${COLLECTION_ID}`]: { ...OK, body: NFT_COLLECTION_BODY },
    });
    const col = await c.getNftCollection(COLLECTION_ID);
    expect(col.creator).toBe(ADDR);
    expect(col.minted_count).toBe(1);
    expect(col.max_supply).toBeNull();
    expect(col.royalty_bps).toBe(500);
  });

  it("parses a numeric max_supply", async () => {
    const c = client({
      [`GET /v1/nft/collections/${COLLECTION_ID}`]: {
        ...OK,
        body: { ...NFT_COLLECTION_BODY, max_supply: 10000 },
      },
    });
    expect((await c.getNftCollection(COLLECTION_ID)).max_supply).toBe(10000);
  });

  it("rejects an out-of-range royalty", async () => {
    const c = client({
      [`GET /v1/nft/collections/${COLLECTION_ID}`]: {
        ...OK,
        body: { ...NFT_COLLECTION_BODY, royalty_bps: 10001 },
      },
    });
    await expect(c.getNftCollection(COLLECTION_ID)).rejects.toThrow(/royalty_bps/u);
  });

  it("surfaces a 404 as NodeApiError", async () => {
    await expect(client({}).getNftCollection(COLLECTION_ID)).rejects.toBeInstanceOf(NodeApiError);
  });
});

describe("WebcNodeClient.getNftItem", () => {
  it("parses an item record", async () => {
    const c = client({
      [`GET /v1/nft/collections/${COLLECTION_ID}/items/7`]: {
        ...OK,
        body: { owner: ADDR2, item_metadata_hash: HASH, frozen: false },
      },
    });
    const item = await c.getNftItem(COLLECTION_ID, 7);
    expect(item.owner).toBe(ADDR2);
    expect(item.item_metadata_hash).toBe(HASH);
    expect(item.frozen).toBe(false);
  });

  it("rejects a bad metadata hash", async () => {
    const c = client({
      [`GET /v1/nft/collections/${COLLECTION_ID}/items/7`]: {
        ...OK,
        body: { owner: ADDR2, item_metadata_hash: "xyz", frozen: false },
      },
    });
    await expect(c.getNftItem(COLLECTION_ID, 7)).rejects.toThrow(/item_metadata_hash/u);
  });

  it("surfaces a 404 (unknown serial) as NodeApiError", async () => {
    await expect(client({}).getNftItem(COLLECTION_ID, 999)).rejects.toBeInstanceOf(NodeApiError);
  });
});

describe("WebcNodeClient.getService", () => {
  it("parses the full on-chain entry and fills service_id from the id", async () => {
    const c = client({ [`GET /v1/services/${SERVICE_ID}`]: { ...OK, body: SERVICE_BODY } });
    const entry = await c.getService(SERVICE_ID);
    expect(entry.service_id).toBe(SERVICE_ID);
    expect(entry.owner).toBe(ADDR);
    expect(entry.status).toBe("Active");
    expect(entry.payment_flags.http_402).toBe(true);
    expect(entry.pricing).toHaveLength(1);
    expect(entry.pricing[0].price).toBe("1000");
    expect(entry.categories).toEqual([HASH]);
    expect(entry.title).toBe(hexOfText("inference"));
    expect(entry.revision).toBe(1);
  });

  it("parses a Retired status", async () => {
    const c = client({
      [`GET /v1/services/${SERVICE_ID}`]: { ...OK, body: { ...SERVICE_BODY, status: "Retired" } },
    });
    expect((await c.getService(SERVICE_ID)).status).toBe("Retired");
  });

  it("rejects an unknown status", async () => {
    const c = client({
      [`GET /v1/services/${SERVICE_ID}`]: { ...OK, body: { ...SERVICE_BODY, status: "Closed" } },
    });
    await expect(c.getService(SERVICE_ID)).rejects.toThrow(/service status/u);
  });

  it("rejects too many categories fail-closed", async () => {
    const c = client({
      [`GET /v1/services/${SERVICE_ID}`]: {
        ...OK,
        body: { ...SERVICE_BODY, categories: new Array(9).fill(HASH) },
      },
    });
    await expect(c.getService(SERVICE_ID)).rejects.toThrow(/categories/u);
  });

  it("surfaces a 404 as NodeApiError", async () => {
    await expect(client({}).getService(SERVICE_ID)).rejects.toBeInstanceOf(NodeApiError);
  });
});

describe("WebcNodeClient.getGovernanceInstance", () => {
  it("parses an instance record", async () => {
    const c = client({
      [`GET /v1/governance/instances/${INSTANCE_ID}`]: { ...OK, body: INSTANCE_BODY },
    });
    const inst = await c.getGovernanceInstance(INSTANCE_ID);
    expect(inst.creator).toBe(ADDR);
    expect(inst.config.quorum_bps).toBe(2000);
    expect(inst.config.proposal_threshold).toBe("100");
    expect(inst.treasury).toBe("0");
    expect(inst.next_proposal_nonce).toBe(1);
  });

  it("rejects an out-of-range quorum in the config", async () => {
    const c = client({
      [`GET /v1/governance/instances/${INSTANCE_ID}`]: {
        ...OK,
        body: { ...INSTANCE_BODY, config: { ...GOV_CONFIG, quorum_bps: 10001 } },
      },
    });
    await expect(c.getGovernanceInstance(INSTANCE_ID)).rejects.toThrow(/quorum_bps/u);
  });

  it("surfaces a 404 as NodeApiError", async () => {
    await expect(
      client({}).getGovernanceInstance(INSTANCE_ID),
    ).rejects.toBeInstanceOf(NodeApiError);
  });
});

describe("WebcNodeClient.getGovernanceProposal", () => {
  it("parses a signaling proposal", async () => {
    const c = client({
      [`GET /v1/governance/proposals/${PROPOSAL_ID}`]: { ...OK, body: PROPOSAL_BODY },
    });
    const prop = await c.getGovernanceProposal(PROPOSAL_ID);
    expect(prop.status).toBe("Active");
    expect(prop.action).toBe("Signaling");
    expect(prop.eta_epoch).toBeNull();
    expect(prop.yes).toBe("150");
  });

  it("parses a TreasuryTransfer action with an eta", async () => {
    const c = client({
      [`GET /v1/governance/proposals/${PROPOSAL_ID}`]: {
        ...OK,
        body: {
          ...PROPOSAL_BODY,
          action: { TreasuryTransfer: { recipient: ADDR2, amount: "42" } },
          eta_epoch: 14,
          status: "Passed",
        },
      },
    });
    const prop = await c.getGovernanceProposal(PROPOSAL_ID);
    expect(prop.action).toEqual({ TreasuryTransfer: { recipient: ADDR2, amount: "42" } });
    expect(prop.eta_epoch).toBe(14);
    expect(prop.status).toBe("Passed");
  });

  it("rejects an unknown action tag fail-closed", async () => {
    const c = client({
      [`GET /v1/governance/proposals/${PROPOSAL_ID}`]: {
        ...OK,
        body: { ...PROPOSAL_BODY, action: { Mint: { amount: "1" } } },
      },
    });
    await expect(c.getGovernanceProposal(PROPOSAL_ID)).rejects.toThrow(/governance action/u);
  });

  it("surfaces a 404 as NodeApiError", async () => {
    await expect(
      client({}).getGovernanceProposal(PROPOSAL_ID),
    ).rejects.toBeInstanceOf(NodeApiError);
  });
});

describe("WebcNodeClient.getMandate", () => {
  it("parses an open-policy mandate", async () => {
    const c = client({ [`GET /v1/mandates/${MANDATE_ID}`]: { ...OK, body: MANDATE_BODY } });
    const mandate = await c.getMandate(MANDATE_ID);
    expect(mandate.principal).toBe(ADDR);
    expect(mandate.agent_key).toBe(HASH);
    expect(mandate.budget_total).toBe("10000000000000");
    expect(mandate.expiry_epoch).toBe(100);
    expect(mandate.counterparty_policy).toBe("Open");
    expect(mandate.revoked).toBe(false);
  });

  it("parses an Allowlist counterparty policy", async () => {
    const c = client({
      [`GET /v1/mandates/${MANDATE_ID}`]: {
        ...OK,
        body: {
          ...MANDATE_BODY,
          counterparty_policy: { Allowlist: [{ Category: HASH }, { Recipient: ADDR2 }] },
        },
      },
    });
    const mandate = await c.getMandate(MANDATE_ID);
    expect(mandate.counterparty_policy).toEqual({
      Allowlist: [{ Category: HASH }, { Recipient: ADDR2 }],
    });
  });

  it("rejects a malformed allowlist entry fail-closed", async () => {
    const c = client({
      [`GET /v1/mandates/${MANDATE_ID}`]: {
        ...OK,
        body: { ...MANDATE_BODY, counterparty_policy: { Allowlist: [{ Bogus: HASH }] } },
      },
    });
    await expect(c.getMandate(MANDATE_ID)).rejects.toThrow(/counterparty/u);
  });

  it("rejects a non-object response", async () => {
    const c = client({ [`GET /v1/mandates/${MANDATE_ID}`]: { ...OK, body: "not-an-object" } });
    await expect(c.getMandate(MANDATE_ID)).rejects.toThrow();
  });

  it("surfaces a 404 as NodeApiError", async () => {
    await expect(client({}).getMandate(MANDATE_ID)).rejects.toBeInstanceOf(NodeApiError);
  });
});

describe("HTTP-402 flow with a node-fetched ServiceEntry", () => {
  const CHAIN_ID = "webc-devnet-1";
  const FEE = { gasLimit: 1000, maxFeePerUnit: 1, priorityFeePerUnit: 0 };
  const OP = HASH; // matches the pricing operation in the served entry
  const NOW = 1_000_000_000;

  /** A service entry served by a mocked node, owned by `owner`, pricing `OP`. */
  function serviceRoutes(owner: string, price: string) {
    return {
      [`GET /v1/services/${SERVICE_ID}`]: {
        ...OK,
        body: {
          ...SERVICE_BODY,
          owner,
          pricing: [{ operation: OP, price, unit: hexOfText("call") }],
        },
      },
    };
  }

  function challengeFor(owner: string, amount: string): PaymentChallenge {
    return {
      service_id: SERVICE_ID,
      operation: OP,
      price: { amount, asset: "NativeWebc" },
      pay_to: owner,
      invoice_nonce: "deadbeef",
      expiry: 2_000_000_000,
    };
  }

  it("fetches the entry via the node client and completes buildPayment", async () => {
    const agent = await createWalletFromSeed(new Uint8Array(32).fill(7));
    const node = client(serviceRoutes(agent.address, "1000"));

    const { transaction, reference } = await buildPayment({
      agentWallet: agent,
      mandateId: MANDATE_ID,
      challenge: challengeFor(agent.address, "1000"),
      // The node client is passed as the entry source; buildPayment fetches the
      // on-chain ServiceEntry itself and cross-checks the challenge against it.
      serviceEntry: node,
      chainId: CHAIN_ID,
      nonce: 0,
      fee: FEE,
      now: NOW,
    });

    expect(transaction.signature).toBeTruthy();
    expect(reference.service_id).toBe(SERVICE_ID);
    expect(reference.mandate_id).toBe(MANDATE_ID);
    expect(reference.invoice_nonce).toBe("deadbeef");
  });

  it("cross-checks against the FETCHED price, not the endpoint challenge", async () => {
    const agent = await createWalletFromSeed(new Uint8Array(32).fill(7));
    // The on-chain entry prices the op at 1000, but the challenge quotes 5000.
    const node = client(serviceRoutes(agent.address, "1000"));

    await expect(
      buildPayment({
        agentWallet: agent,
        mandateId: MANDATE_ID,
        challenge: challengeFor(agent.address, "5000"),
        serviceEntry: node,
        chainId: CHAIN_ID,
        nonce: 0,
        fee: FEE,
        now: NOW,
      }),
    ).rejects.toMatchObject({ name: "ChallengeError", code: "price_mismatch" });
  });

  it("validateChallengeAgainstSource resolves and validates via a fetcher", async () => {
    const agent = await createWalletFromSeed(new Uint8Array(32).fill(7));
    const node = client(serviceRoutes(agent.address, "1000"));
    const fetcher = (serviceId: string) => node.getService(serviceId);

    const entry = await validateChallengeAgainstSource(
      challengeFor(agent.address, "1000"),
      fetcher,
      { now: NOW },
    );
    expect(entry.service_id).toBe(SERVICE_ID);
    expect(entry.owner).toBe(agent.address);
  });
});
