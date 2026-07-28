/**
 * Adversarial contract tests for the protocol-2 transaction client surface.
 *
 * Responsibilities: freeze the Rust `/v2/transactions` JSON contract, verify
 * request/response identity binding, exercise the existing V1 receipt validator,
 * and prove lifecycle WebSocket bounds plus explicit resynchronization. Non-
 * responsibilities: transaction signing and finalized-proof verification remain
 * in their owning modules. Security boundary: every HTTP and WebSocket response
 * in this file represents hostile node input and must fail closed.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  NodeApiError,
  WebcNodeClient,
  type FetchLike,
  type WebSocketLike,
} from "./node-client.js";
import {
  MAX_TRANSACTION_LIFECYCLE_IDS_V2,
  MAX_TRANSACTION_LIFECYCLE_WS_MESSAGE_BYTES_V2,
  TransactionLifecycleSubscriptionError,
  parseTransactionLifecycleV2,
} from "./transaction-api-v2.js";
import type { ReceiptV1Json } from "./receipt-v1.js";
import type { SignedTransactionV5Json } from "./transaction-v5.js";

const fixture = JSON.parse(
  readFileSync(
    new URL("../../../fixtures/finalized-transaction-proof-v1.json", import.meta.url),
    "utf8",
  ),
) as {
  proof: { transaction: SignedTransactionV5Json; receipt: ReceiptV1Json };
  requirements: { transaction_id: string };
};

const TRANSACTION_ID = fixture.requirements.transaction_id;
const OTHER_TRANSACTION_ID = "b".repeat(64);

function fakeFetch(
  routes: Record<string, { ok: boolean; status: number; body: unknown }>,
): { fetchImpl: FetchLike; calls: Array<{ url: string; method: string; body?: string }> } {
  const calls: Array<{ url: string; method: string; body?: string }> = [];
  const fetchImpl: FetchLike = async (url, init) => {
    const method = init?.method ?? "GET";
    calls.push({ url, method, body: init?.body });
    const parsed = new URL(url);
    const route = routes[`${method} ${parsed.pathname}${parsed.search}`];
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
      text: async () => JSON.stringify(route.body),
    };
  };
  return { fetchImpl, calls };
}

function queuedLifecycle(sequence = "1") {
  return {
    api_version: "v2",
    transaction_id: TRANSACTION_ID,
    sequence,
    status: { kind: "queued", observed_at_ms: "123" },
  };
}

describe("WebcNodeClient protocol-2 HTTP", () => {
  it("submits a signed V5 transaction and binds every returned identity", async () => {
    const { fetchImpl, calls } = fakeFetch({
      "POST /v2/transactions": {
        ok: true,
        status: 200,
        body: {
          api_version: "v2",
          transaction_id: TRANSACTION_ID,
          outcome: { kind: "added" },
          lifecycle: queuedLifecycle(),
          mempool_size: 1,
        },
      },
    });
    const client = new WebcNodeClient("http://node.test/", { fetchImpl });

    const submitted = await client.submitTransactionV2(fixture.proof.transaction);

    expect(submitted.transactionId).toBe(TRANSACTION_ID);
    expect(submitted.outcome).toEqual({ kind: "added" });
    expect(submitted.lifecycle.sequence).toBe(1n);
    expect(submitted.lifecycle.status).toEqual({ kind: "queued", observedAtMs: 123n });
    expect(calls[0]).toEqual({
      url: "http://node.test/v2/transactions",
      method: "POST",
      body: JSON.stringify(fixture.proof.transaction),
    });
  });

  it("rejects an unsigned request before fetch and a mismatched response identity", async () => {
    let calls = 0;
    const noFetch: FetchLike = async () => {
      calls += 1;
      throw new Error("must not fetch");
    };
    const client = new WebcNodeClient("http://node.test", { fetchImpl: noFetch });
    await expect(
      client.submitTransactionV2({
        ...fixture.proof.transaction,
        sender_signature: null,
      } as unknown as SignedTransactionV5Json),
    ).rejects.toThrow(/signature/u);
    expect(calls).toBe(0);

    const { fetchImpl } = fakeFetch({
      "POST /v2/transactions": {
        ok: true,
        status: 200,
        body: {
          api_version: "v2",
          transaction_id: OTHER_TRANSACTION_ID,
          outcome: { kind: "added" },
          lifecycle: {
            ...queuedLifecycle(),
            transaction_id: OTHER_TRANSACTION_ID,
          },
          mempool_size: 1,
        },
      },
    });
    await expect(
      new WebcNodeClient("http://node.test", { fetchImpl })
        .submitTransactionV2(fixture.proof.transaction),
    ).rejects.toThrow(/transaction ID/u);
  });

  it("strictly parses lifecycle statuses and canonical decimal fields", async () => {
    const finalized = parseTransactionLifecycleV2({
      api_version: "v2",
      transaction_id: TRANSACTION_ID,
      sequence: "42",
      status: {
        kind: "finalized",
        position: { height: "11", transaction_index: 7 },
      },
    }, TRANSACTION_ID);
    expect(finalized.status).toEqual({
      kind: "finalized",
      position: { height: 11n, transactionIndex: 7 },
    });

    const dropped = parseTransactionLifecycleV2({
      api_version: "v2",
      transaction_id: TRANSACTION_ID,
      sequence: "43",
      status: {
        kind: "dropped",
        reason: "revalidation_failed",
        observed_at_ms: "999",
      },
    });
    expect(dropped.status).toEqual({
      kind: "dropped",
      reason: "revalidation_failed",
      observedAtMs: 999n,
    });

    expect(() => parseTransactionLifecycleV2({
      ...queuedLifecycle("01"),
    })).toThrow(/canonical/u);
    expect(() => parseTransactionLifecycleV2({
      ...queuedLifecycle(),
      unexpected: true,
    })).toThrow(/field/u);
    expect(() => parseTransactionLifecycleV2({
      ...queuedLifecycle(),
      sequence: null,
    })).toThrow(/sequence/u);
  });

  it("queries a lifecycle and rejects a node response for another ID", async () => {
    const { fetchImpl, calls } = fakeFetch({
      [`GET /v2/transactions/${TRANSACTION_ID}`]: {
        ok: true,
        status: 200,
        body: queuedLifecycle("9"),
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    const lifecycle = await client.transactionLifecycleV2(TRANSACTION_ID);
    expect(lifecycle.sequence).toBe(9n);
    expect(calls[0]?.url).toBe(`http://node.test/v2/transactions/${TRANSACTION_ID}`);

    const mismatched = fakeFetch({
      [`GET /v2/transactions/${TRANSACTION_ID}`]: {
        ok: true,
        status: 200,
        body: { ...queuedLifecycle(), transaction_id: OTHER_TRANSACTION_ID },
      },
    });
    await expect(
      new WebcNodeClient("http://node.test", { fetchImpl: mismatched.fetchImpl })
        .transactionLifecycleV2(TRANSACTION_ID),
    ).rejects.toThrow(/transaction ID/u);
  });

  it("queries a finalized receipt through the existing strict V1 validator", async () => {
    const { fetchImpl } = fakeFetch({
      [`GET /v2/transactions/${TRANSACTION_ID}/receipt`]: {
        ok: true,
        status: 200,
        body: fixture.proof.receipt,
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    const receipt = await client.finalizedTransactionReceiptV2(TRANSACTION_ID);
    expect(receipt.transaction_id).toBe(TRANSACTION_ID);
    expect(receipt.status).toBe("Succeeded");

    const invalidReceipt = structuredClone(fixture.proof.receipt);
    invalidReceipt.fee_summary.charged = "31";
    const hostile = fakeFetch({
      [`GET /v2/transactions/${TRANSACTION_ID}/receipt`]: {
        ok: true,
        status: 200,
        body: invalidReceipt,
      },
    });
    await expect(
      new WebcNodeClient("http://node.test", { fetchImpl: hostile.fetchImpl })
        .finalizedTransactionReceiptV2(TRANSACTION_ID),
    ).rejects.toThrow(/reconcile/u);
  });

  it("surfaces a bounded V2 error code and correlation ID", async () => {
    const { fetchImpl } = fakeFetch({
      [`GET /v2/transactions/${TRANSACTION_ID}/receipt`]: {
        ok: false,
        status: 404,
        body: {
          api_version: "v2",
          code: "receipt_not_finalized",
          message: "no finalized receipt is available",
          request_id: "v2-0000000000000001",
        },
      },
    });
    const client = new WebcNodeClient("http://node.test", { fetchImpl });
    const error = await client.finalizedTransactionReceiptV2(TRANSACTION_ID)
      .catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(NodeApiError);
    expect(error).toMatchObject({
      status: 404,
      kind: "receipt_not_finalized",
      requestId: "v2-0000000000000001",
    });
  });
});

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  readonly url: string;
  readonly sent: string[] = [];
  closed = false;
  #listeners: Record<string, Array<(event: unknown) => void>> = {};

  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  addEventListener(type: string, listener: (event: unknown) => void): void {
    (this.#listeners[type] ??= []).push(listener);
  }

  emit(type: string, event: unknown = {}): void {
    for (const listener of this.#listeners[type] ?? []) listener(event);
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(): void {
    this.closed = true;
  }
}

function websocketClient(): WebcNodeClient {
  FakeWebSocket.instances = [];
  return new WebcNodeClient("https://node.test/", {
    fetchImpl: (async () => ({ ok: true, status: 200, text: async () => "" })) as FetchLike,
    webSocketImpl: FakeWebSocket as unknown as new (url: string) => WebSocketLike,
  });
}

describe("WebcNodeClient protocol-2 lifecycle WebSocket", () => {
  it("sends one bounded subscription and ignores replayed sequence numbers", () => {
    const client = websocketClient();
    const seen: bigint[] = [];
    const subscription = client.subscribeTransactionLifecyclesV2(
      [TRANSACTION_ID],
      {
        onLifecycle: (lifecycle) => seen.push(lifecycle.sequence ?? -1n),
        onResyncRequired: () => undefined,
      },
      { afterSequence: 4n },
    );
    const socket = FakeWebSocket.instances[0];
    expect(socket.url).toBe("wss://node.test/v2/transactions/ws");
    socket.emit("open");
    expect(JSON.parse(socket.sent[0]) as unknown).toEqual({
      version: 1,
      transaction_ids: [TRANSACTION_ID],
      after_sequence: "4",
    });

    socket.emit("message", { data: JSON.stringify({ type: "snapshot", lifecycle: queuedLifecycle("5") }) });
    socket.emit("message", { data: JSON.stringify({ type: "snapshot", lifecycle: queuedLifecycle("5") }) });
    expect(seen).toEqual([5n]);
    expect(subscription.lastSequence).toBe(5n);
  });

  it("rejects invalid subscription sets before opening a socket", () => {
    const client = websocketClient();
    const handlers = {
      onLifecycle: () => undefined,
      onResyncRequired: () => undefined,
    };
    expect(() => client.subscribeTransactionLifecyclesV2([], handlers)).toThrow(/at least one/u);
    expect(() => client.subscribeTransactionLifecyclesV2(
      [TRANSACTION_ID, TRANSACTION_ID],
      handlers,
    )).toThrow(/unique/u);
    expect(() => client.subscribeTransactionLifecyclesV2(
      Array.from({ length: MAX_TRANSACTION_LIFECYCLE_IDS_V2 + 1 }, (_, index) =>
        index.toString(16).padStart(64, "0")),
      handlers,
    )).toThrow(/at most/u);
    expect(FakeWebSocket.instances).toHaveLength(0);
  });

  it("closes on an oversized or out-of-subscription hostile snapshot", () => {
    const client = websocketClient();
    const errors: unknown[] = [];
    client.subscribeTransactionLifecyclesV2([TRANSACTION_ID], {
      onLifecycle: () => undefined,
      onResyncRequired: () => undefined,
      onError: (error) => errors.push(error),
    });
    const socket = FakeWebSocket.instances[0];
    socket.emit("open");
    socket.emit("message", {
      data: JSON.stringify({
        type: "snapshot",
        lifecycle: { ...queuedLifecycle(), transaction_id: OTHER_TRANSACTION_ID },
      }),
    });
    expect(socket.closed).toBe(true);
    expect(errors[0]).toBeInstanceOf(Error);

    const secondClient = websocketClient();
    const secondErrors: unknown[] = [];
    secondClient.subscribeTransactionLifecyclesV2([TRANSACTION_ID], {
      onLifecycle: () => undefined,
      onResyncRequired: () => undefined,
      onError: (error) => secondErrors.push(error),
    });
    const second = FakeWebSocket.instances[0];
    second.emit("open");
    second.emit("message", {
      data: "x".repeat(MAX_TRANSACTION_LIFECYCLE_WS_MESSAGE_BYTES_V2 + 1),
    });
    expect(second.closed).toBe(true);
    expect(secondErrors[0]).toBeInstanceOf(Error);
  });

  it("exposes the server resync marker and reconnects from that sequence", () => {
    const client = websocketClient();
    const resyncs: bigint[] = [];
    const subscription = client.subscribeTransactionLifecyclesV2([TRANSACTION_ID], {
      onLifecycle: () => undefined,
      onResyncRequired: (notice) => resyncs.push(notice.lastSequence),
    });
    const first = FakeWebSocket.instances[0];
    first.emit("open");
    first.emit("message", {
      data: JSON.stringify({
        type: "resync_required",
        last_sequence: "7",
        request_id: "v2-0000000000000007",
      }),
    });
    expect(first.closed).toBe(true);
    expect(resyncs).toEqual([7n]);
    expect(subscription.lastSequence).toBe(7n);

    subscription.reconnect();
    const second = FakeWebSocket.instances[1];
    second.emit("open");
    expect(JSON.parse(second.sent[0]) as unknown).toEqual({
      version: 1,
      transaction_ids: [TRANSACTION_ID],
      after_sequence: "7",
    });
  });

  it("turns a bounded server error into a typed subscription error", () => {
    const client = websocketClient();
    const errors: unknown[] = [];
    client.subscribeTransactionLifecyclesV2([TRANSACTION_ID], {
      onLifecycle: () => undefined,
      onResyncRequired: () => undefined,
      onError: (error) => errors.push(error),
    });
    const socket = FakeWebSocket.instances[0];
    socket.emit("open");
    socket.emit("message", {
      data: JSON.stringify({
        type: "error",
        code: "invalid_subscription",
        message: "send one bounded JSON subscription message",
        request_id: "v2-0000000000000008",
      }),
    });
    expect(errors[0]).toBeInstanceOf(TransactionLifecycleSubscriptionError);
    expect(errors[0]).toMatchObject({
      code: "invalid_subscription",
      requestId: "v2-0000000000000008",
    });
    expect(socket.closed).toBe(true);
  });
});
