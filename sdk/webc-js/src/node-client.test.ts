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

  it("rejects a malformed response shape", async () => {
    const { fetchImpl } = fakeFetch({
      "GET /v1/health": { ok: true, status: 200, body: { api_version: "v1" } },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    await expect(client.health()).rejects.toThrow();
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
