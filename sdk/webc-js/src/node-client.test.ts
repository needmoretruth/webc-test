import { describe, expect, it } from "vitest";

import {
  NodeApiError,
  WebcNodeClient,
  parseBlockEvent,
  type FetchLike,
  type WebSocketLike,
} from "./node-client.js";

/** Builds a fake `fetch` that serves scripted responses keyed by "METHOD path". */
function fakeFetch(
  routes: Record<string, { ok: boolean; status: number; body: unknown }>,
): { fetchImpl: FetchLike; calls: Array<{ url: string; method: string; body?: string }> } {
  const calls: Array<{ url: string; method: string; body?: string }> = [];
  const fetchImpl: FetchLike = async (url, init) => {
    const method = init?.method ?? "GET";
    calls.push({ url, method, body: init?.body });
    const path = url.slice(url.indexOf("/v1"));
    const route = routes[`${method} ${path}`];
    if (!route) {
      return { ok: false, status: 404, text: async () => JSON.stringify({ error: "nf", kind: "not_found" }) };
    }
    return {
      ok: route.ok,
      status: route.status,
      text: async () => (route.body === undefined ? "" : JSON.stringify(route.body)),
    };
  };
  return { fetchImpl, calls };
}

const HASH = "a".repeat(64);

describe("WebcNodeClient HTTP", () => {
  it("parses health", async () => {
    const { fetchImpl } = fakeFetch({
      "GET /v1/health": {
        ok: true,
        status: 200,
        body: {
          api_version: "v1",
          chain_id: "webc-devnet-1",
          height: 3,
          tip_hash: HASH,
          state_root: HASH,
          mempool_size: 0,
          faucet_enabled: true,
        },
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    const health = await client.health();
    expect(health.apiVersion).toBe("v1");
    expect(health.height).toBe(3);
    expect(health.tipHash).toBe(HASH);
    expect(health.faucetEnabled).toBe(true);
  });

  it("parses fees as bigints", async () => {
    const { fetchImpl } = fakeFetch({
      "GET /v1/fees": {
        ok: true,
        status: 200,
        body: { api_version: "v1", base_fee_per_unit: 1, max_block_units: 2_000_000 },
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    const fees = await client.fees();
    expect(fees.baseFeePerUnit).toBe(1n);
    expect(fees.maxBlockUnits).toBe(2_000_000n);
  });

  it("parses an account with a string-amount balance", async () => {
    const { fetchImpl } = fakeFetch({
      "GET /v1/accounts/webc1abc": {
        ok: true,
        status: 200,
        body: { address: "webc1abc", account: { balance: "10000000000000", nonce: 2 } },
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    const account = await client.account("webc1abc");
    expect(account.balance).toBe(10_000_000_000_000n);
    expect(account.nonce).toBe(2);
  });

  it("throws a typed NodeApiError on a 404 with the node's kind", async () => {
    const { fetchImpl } = fakeFetch({
      "GET /v1/accounts/webc1missing": {
        ok: false,
        status: 404,
        body: { error: "not found", kind: "not_found" },
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    await expect(client.account("webc1missing")).rejects.toMatchObject({
      name: "NodeApiError",
      status: 404,
      kind: "not_found",
    });
  });

  it("posts a transaction and parses the receipt", async () => {
    const { fetchImpl, calls } = fakeFetch({
      "POST /v1/transactions": {
        ok: true,
        status: 200,
        body: { tx_hash: HASH, accepted: true, mempool_size: 1 },
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    const receipt = await client.submitTransaction({ any: "tx" });
    expect(receipt.accepted).toBe(true);
    expect(receipt.txHash).toBe(HASH);
    // The request carried the JSON body.
    expect(calls[0].body).toBe(JSON.stringify({ any: "tx" }));
  });

  it("requests a faucet drip and surfaces the disclaimer", async () => {
    const { fetchImpl } = fakeFetch({
      "POST /v1/faucet/webc1new": {
        ok: true,
        status: 200,
        body: {
          recipient: "webc1new",
          amount: "100000000000000",
          block_height: 1,
          new_balance: "100000000000000",
          disclaimer: "DEVNET faucet: valueless test units.",
        },
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    const receipt = await client.requestFaucet("webc1new");
    expect(receipt.amount).toBe(100_000_000_000_000n);
    expect(receipt.blockHeight).toBe(1);
    expect(receipt.disclaimer.length).toBeGreaterThan(0);
  });

  it("parses the validator set with derived stakes and a tagged status", async () => {
    const { fetchImpl } = fakeFetch({
      "GET /v1/validators": {
        ok: true,
        status: 200,
        body: {
          api_version: "v1",
          validators: [
            {
              operator: "webc1op1",
              consensus_key: HASH,
              self_stake: "100000000000000",
              delegated_stake: "50000000000000",
              commission_bps: 500,
              status: "Active",
              bootstrap: false,
              accumulated_rewards: "0",
              total_stake: "150000000000000",
            },
            {
              operator: "webc1op2",
              consensus_key: HASH,
              self_stake: "1",
              delegated_stake: "0",
              commission_bps: 0,
              status: { Jailed: { reason: "double sign" } },
              bootstrap: false,
              accumulated_rewards: "0",
              total_stake: "1",
            },
          ],
        },
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    const response = await client.getValidators();
    expect(response.apiVersion).toBe("v1");
    expect(response.validators).toHaveLength(2);
    expect(response.validators[0].operator).toBe("webc1op1");
    expect(response.validators[0].selfStake).toBe(100_000_000_000_000n);
    expect(response.validators[0].delegatedStake).toBe(50_000_000_000_000n);
    expect(response.validators[0].commissionBps).toBe(500);
    expect(response.validators[0].totalStake).toBe(150_000_000_000_000n);
    expect(response.validators[0].status).toBe("Active");
    expect(response.validators[1].status).toEqual({ Jailed: { reason: "double sign" } });
  });

  it("parses a single validator", async () => {
    const { fetchImpl } = fakeFetch({
      "GET /v1/validators/webc1op1": {
        ok: true,
        status: 200,
        body: {
          operator: "webc1op1",
          consensus_key: HASH,
          self_stake: "100000000000000",
          delegated_stake: "0",
          commission_bps: 1000,
          status: "Draining",
          bootstrap: false,
          accumulated_rewards: "7",
          total_stake: "100000000000000",
        },
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    const validator = await client.getValidator("webc1op1");
    expect(validator.operator).toBe("webc1op1");
    expect(validator.consensusKey).toBe(HASH);
    expect(validator.status).toBe("Draining");
    expect(validator.accumulatedRewards).toBe(7n);
    expect(validator.totalStake).toBe(100_000_000_000_000n);
  });

  it("throws a typed NodeApiError on a 404 for a missing validator", async () => {
    const { fetchImpl } = fakeFetch({
      "GET /v1/validators/webc1missing": {
        ok: false,
        status: 404,
        body: { error: "not found", kind: "not_found" },
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    await expect(client.getValidator("webc1missing")).rejects.toMatchObject({
      name: "NodeApiError",
      status: 404,
      kind: "not_found",
    });
  });

  it("parses the supply-invariant report as bigints", async () => {
    const { fetchImpl } = fakeFetch({
      "GET /v1/supply": {
        ok: true,
        status: 200,
        body: {
          issued: "1002000000000000000000",
          liquid: "1000000000000000000000",
          staked: "2000000000000000000",
          delegated: "0",
          unbonding: "0",
          escrowed: "0",
          lane_fees: "0",
          pending_rewards: "0",
          fee_reward_pool: "0",
          burned: "0",
          slashed: "0",
          accounted: "1002000000000000000000",
          balanced: true,
        },
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    const supply = await client.getSupply();
    expect(supply.issued).toBe(1_002_000_000_000_000_000_000n);
    expect(supply.staked).toBe(2_000_000_000_000_000_000n);
    expect(supply.accounted).toBe(1_002_000_000_000_000_000_000n);
    expect(supply.balanced).toBe(true);
  });

  it("rejects a validator with an unknown status variant", async () => {
    const { fetchImpl } = fakeFetch({
      "GET /v1/validators/webc1bad": {
        ok: true,
        status: 200,
        body: {
          operator: "webc1bad",
          consensus_key: HASH,
          self_stake: "1",
          delegated_stake: "0",
          commission_bps: 0,
          status: "Frozen",
          bootstrap: false,
          accumulated_rewards: "0",
          total_stake: "1",
        },
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    await expect(client.getValidator("webc1bad")).rejects.toThrow(/validator status/u);
  });

  it("rejects a malformed response shape", async () => {
    const { fetchImpl } = fakeFetch({
      "GET /v1/health": { ok: true, status: 200, body: { api_version: "v1" } },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    await expect(client.health()).rejects.toThrow();
  });

  it("truncates a node-supplied error string before surfacing it (S6)", async () => {
    // A hostile node error message must not carry megabytes of node-controlled
    // text into host UI. It is bounded to a short prefix.
    const huge = "x".repeat(5_000);
    const fetchImpl: FetchLike = async () => ({
      ok: false,
      status: 500,
      text: async () => JSON.stringify({ error: huge, kind: "y".repeat(5_000) }),
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    await expect(client.health()).rejects.toMatchObject({ name: "NodeApiError" });
    try {
      await client.health();
      throw new Error("expected rejection");
    } catch (error) {
      const api = error as { message: string; kind: string };
      expect(api.message.length).toBeLessThanOrEqual(256);
      expect(api.kind.length).toBeLessThanOrEqual(256);
    }
  });

  it("caps the body by bytes, not UTF-16 units, for a text response (S6)", async () => {
    // Each "€" is one UTF-16 unit but three UTF-8 bytes; a byte cap must count
    // bytes. With a 100-byte cap, 60 euro signs (180 bytes, 60 units) is over.
    const body = "€".repeat(60);
    const fetchImpl: FetchLike = async () => ({
      ok: true,
      status: 200,
      text: async () => body,
    });
    const client = new WebcNodeClient("http://node.test", {
      fetchImpl,
      maxResponseBytes: 100,
    });
    await expect(client.health()).rejects.toThrow(/maximum allowed size/u);
  });

  it("aborts a streamed body once the byte cap is exceeded (S6)", async () => {
    // A ReadableStream body is capped while reading and aborted early instead of
    // being fully buffered first.
    let reads = 0;
    let canceled = false;
    const chunk = new Uint8Array(64);
    const body = {
      getReader() {
        return {
          async read() {
            reads += 1;
            return { done: false, value: chunk };
          },
          async cancel() {
            canceled = true;
          },
        };
      },
    };
    const fetchImpl: FetchLike = async () =>
      ({
        ok: true,
        status: 200,
        body,
        text: async () => {
          throw new Error("text() must not be used when a stream body exists");
        },
      }) as unknown as Awaited<ReturnType<FetchLike>>;
    const client = new WebcNodeClient("http://node.test", {
      fetchImpl,
      maxResponseBytes: 256,
    });
    await expect(client.health()).rejects.toThrow(/maximum allowed size/u);
    // 256-byte cap / 64-byte chunks: aborted after a few reads, not unbounded.
    expect(reads).toBeLessThanOrEqual(6);
    expect(canceled).toBe(true);
  });
});

describe("parseBlockEvent", () => {
  it("accepts a valid event", () => {
    const event = parseBlockEvent({ height: 5, block_hash: HASH, state_root: HASH });
    expect(event.height).toBe(5);
    expect(event.blockHash).toBe(HASH);
  });

  it("rejects a bad hash", () => {
    expect(() => parseBlockEvent({ height: 5, block_hash: "xyz", state_root: null })).toThrow();
  });

  it("rejects a negative height", () => {
    expect(() => parseBlockEvent({ height: -1, block_hash: null, state_root: null })).toThrow();
  });
});

/** A controllable fake WebSocket for the subscription test. */
class FakeWebSocket {
  static last: FakeWebSocket | undefined;
  readonly url: string;
  closed = false;
  #listeners: Record<string, Array<(event: unknown) => void>> = {};

  constructor(url: string) {
    this.url = url;
    FakeWebSocket.last = this;
  }

  addEventListener(type: string, listener: (event: unknown) => void): void {
    (this.#listeners[type] ??= []).push(listener);
  }

  emit(type: string, event: unknown): void {
    for (const listener of this.#listeners[type] ?? []) {
      listener(event);
    }
  }

  close(): void {
    this.closed = true;
  }
}

describe("WebcNodeClient subscribeBlocks", () => {
  it("delivers parsed block events and uses a ws:// URL", () => {
    const client = new WebcNodeClient("http://node.test", {
      fetchImpl: (async () => ({ ok: true, status: 200, text: async () => "" })) as FetchLike,
      webSocketImpl: FakeWebSocket as unknown as new (url: string) => WebSocketLike,
    });

    const received: number[] = [];
    const subscription = client.subscribeBlocks({ onBlock: (event) => received.push(event.height) });

    const socket = FakeWebSocket.last!;
    expect(socket.url).toBe("ws://node.test/v1/subscribe/blocks");

    socket.emit("message", { data: JSON.stringify({ height: 7, block_hash: HASH, state_root: HASH }) });
    expect(received).toEqual([7]);

    subscription.close();
    expect(socket.closed).toBe(true);
  });

  it("routes malformed messages to onError, not onBlock", () => {
    const client = new WebcNodeClient("http://node.test", {
      fetchImpl: (async () => ({ ok: true, status: 200, text: async () => "" })) as FetchLike,
      webSocketImpl: FakeWebSocket as unknown as new (url: string) => WebSocketLike,
    });
    let errors = 0;
    client.subscribeBlocks({
      onBlock: () => {
        throw new Error("should not be called");
      },
      onError: () => {
        errors += 1;
      },
    });
    FakeWebSocket.last!.emit("message", { data: "not json" });
    expect(errors).toBe(1);
  });
});
