/** Adversarial and end-to-end tests for the isolated wallet message boundary. */

import { beforeAll, describe, expect, it } from "vitest";
import { WalletHostClient, type WalletHostEventTarget } from "./wallet-client";
import {
  WALLET_MESSAGE_CHANNEL,
  WALLET_MESSAGE_VERSION,
  type WalletConfirmation,
  type WalletResponse,
  type WalletSpendLimitsJson,
} from "./wallet-request";
import {
  TrustedWalletService,
  type WalletIncomingMessage,
  type WalletMessageSource,
} from "./wallet-service";
import type {
  PermissionPersistencePort,
  PersistedPermissionGrant,
} from "./permission-store";
import { verifySignedTransaction } from "./transaction";
import { createDevnetWalletFromMnemonic } from "./wallet-derivation";
import type { WebcWallet } from "./wallet";

const HOST_ORIGIN = "https://shop.example";
const WALLET_ORIGIN = "https://wallet.webc.example";
const CHAIN_ID = "webc-devnet-1";
const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const RECIPIENT = "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";
const LIMITS: WalletSpendLimitsJson = {
  max_amount_per_transaction: "2000000000000",
  max_total_amount: "2500000000000",
  max_fee_per_transaction: "10000",
};

let wallet: WebcWallet;

beforeAll(async () => {
  wallet = await createDevnetWalletFromMnemonic(MNEMONIC);
});

class CapturingSource implements WalletMessageSource {
  readonly messages: Array<{ response: WalletResponse; targetOrigin: string }> = [];

  postMessage(message: unknown, targetOrigin: string): void {
    this.messages.push({ response: message as WalletResponse, targetOrigin });
  }
}

function requestId(byte: string): string {
  return byte.repeat(64);
}

function connectRequest(id: string) {
  return {
    channel: WALLET_MESSAGE_CHANNEL,
    version: WALLET_MESSAGE_VERSION,
    request_id: id,
    method: "connect",
    params: { scopes: ["sign_native_transfer"], limits: LIMITS },
  };
}

function transferRequest(
  id: string,
  lane: string,
  sessionId: string,
  sequence: number,
  amount = "1000000000000",
) {
  return {
    channel: WALLET_MESSAGE_CHANNEL,
    version: WALLET_MESSAGE_VERSION,
    request_id: id,
    method: "sign_native_transfer",
    params: {
      session_id: sessionId,
      sequence,
      protocol_version: 1,
      chain_id: CHAIN_ID,
      nonce: 0,
      authorization_lane: lane,
      authorization_policy_revision: 0,
      recipient: RECIPIENT,
      amount,
      fee: { gasLimit: 1_000, maxFeePerUnit: 5, priorityFeePerUnit: 1 },
    },
  };
}

describe("trusted wallet service", () => {
  it("binds origin, derives display, signs exact transfer, and rejects replay", async () => {
    const source = new CapturingSource();
    const confirmations: WalletConfirmation[] = [];
    const service = new TrustedWalletService({
      wallet,
      chainId: CHAIN_ID,
      expectedSource: source,
      confirm: async (confirmation) => {
        confirmations.push(confirmation);
        return true;
      },
    });

    await service.handleMessage({
      origin: HOST_ORIGIN,
      source,
      data: connectRequest(requestId("1")),
    });
    const connected = source.messages.at(-1)?.response;
    expect(connected?.ok).toBe(true);
    if (!connected?.ok || !("session_id" in connected.result)) {
      throw new Error("expected connection result");
    }
    const lane = connected.result.authorization_lane;
    const sessionId = connected.result.session_id;
    expect(lane).toMatch(/^[0-9a-f]{64}$/u);

    const request = transferRequest(requestId("2"), lane, sessionId, 0);
    await service.handleMessage({ origin: HOST_ORIGIN, source, data: request });
    const signedResponse = source.messages.at(-1)?.response;
    expect(signedResponse?.ok).toBe(true);
    if (!signedResponse?.ok || !("signature" in signedResponse.result)) {
      throw new Error("expected signed transaction");
    }
    expect(await verifySignedTransaction(signedResponse.result)).toBe(true);
    expect(confirmations.at(-1)).toEqual({
      kind: "native_transfer",
      origin: HOST_ORIGIN,
      action: "Send WEBC",
      asset: "WEBC",
      recipient: RECIPIENT,
      amount_base_units: "1000000000000",
      amount_webc: "1 WEBC",
      maximum_fee_base_units: "5000",
      chain_id: CHAIN_ID,
      authorization_lane: lane,
      authorization_policy_revision: 0,
    });
    expect(source.messages.at(-1)?.targetOrigin).toBe(HOST_ORIGIN);

    await service.handleMessage({ origin: HOST_ORIGIN, source, data: request });
    const replay = source.messages.at(-1)?.response;
    expect(replay?.ok).toBe(false);
    if (replay && !replay.ok) expect(replay.error.code).toBe("REQUEST_REPLAY");

    await service.handleMessage({
      origin: HOST_ORIGIN,
      source,
      data: transferRequest(requestId("a"), lane, sessionId, 0),
    });
    const staleSequence = source.messages.at(-1)?.response;
    expect(staleSequence?.ok).toBe(false);
    if (staleSequence && !staleSequence.ok) {
      expect(staleSequence.error.code).toBe("REQUEST_REPLAY");
    }
  });

  it("serializes cumulative limits and rejects host-invented display fields", async () => {
    const source = new CapturingSource();
    const service = new TrustedWalletService({
      wallet,
      chainId: CHAIN_ID,
      expectedSource: source,
      confirm: async () => true,
    });
    await service.handleMessage({
      origin: HOST_ORIGIN,
      source,
      data: connectRequest(requestId("3")),
    });
    const connection = source.messages.at(-1)?.response;
    if (!connection?.ok || !("session_id" in connection.result)) {
      throw new Error("expected connection result");
    }
    const lane = connection.result.authorization_lane;
    const sessionId = connection.result.session_id;
    await Promise.all([
      service.handleMessage({
        origin: HOST_ORIGIN,
        source,
        data: transferRequest(
          requestId("4"),
          lane,
          sessionId,
          0,
          "1500000000000",
        ),
      }),
      service.handleMessage({
        origin: HOST_ORIGIN,
        source,
        data: transferRequest(
          requestId("5"),
          lane,
          sessionId,
          1,
          "1500000000000",
        ),
      }),
    ]);
    const outcomes = source.messages.slice(-2).map(({ response }) => response.ok);
    expect(outcomes).toEqual([true, false]);

    const blind = {
      ...transferRequest(requestId("6"), lane, sessionId, 1),
      params: {
        ...transferRequest(requestId("6"), lane, sessionId, 1).params,
        display: "Send nothing",
      },
    };
    await service.handleMessage({ origin: HOST_ORIGIN, source, data: blind });
    const invalid = source.messages.at(-1)?.response;
    expect(invalid?.ok).toBe(false);
    if (invalid && !invalid.ok) expect(invalid.error.code).toBe("INVALID_REQUEST");
  });

  it("ignores wrong sources and insecure origins without reflecting data", async () => {
    const source = new CapturingSource();
    const wrongSource = new CapturingSource();
    const service = new TrustedWalletService({
      wallet,
      chainId: CHAIN_ID,
      expectedSource: source,
      confirm: async () => true,
    });
    const events: WalletIncomingMessage[] = [
      {
        origin: HOST_ORIGIN,
        source: wrongSource,
        data: connectRequest(requestId("7")),
      },
      {
        origin: "http://evil.example",
        source,
        data: connectRequest(requestId("8")),
      },
      {
        origin: "null",
        source,
        data: connectRequest(requestId("9")),
      },
    ];
    for (const event of events) await service.handleMessage(event);
    expect(source.messages).toHaveLength(0);
    expect(wrongSource.messages).toHaveLength(0);
  });
});

class FakeEventTarget implements WalletHostEventTarget {
  readonly listeners = new Set<(event: WalletIncomingMessage) => void>();

  addEventListener(
    _type: "message",
    listener: (event: WalletIncomingMessage) => void,
  ): void {
    this.listeners.add(listener);
  }

  removeEventListener(
    _type: "message",
    listener: (event: WalletIncomingMessage) => void,
  ): void {
    this.listeners.delete(listener);
  }

  dispatch(event: WalletIncomingMessage): void {
    for (const listener of this.listeners) listener(event);
  }
}

describe("host client and trusted service", () => {
  it("exchange only public data across exact origins end to end", async () => {
    const eventTarget = new FakeEventTarget();
    let service: TrustedWalletService;
    const hostResponseTarget: WalletMessageSource = {
      postMessage(message, targetOrigin) {
        expect(targetOrigin).toBe(HOST_ORIGIN);
        eventTarget.dispatch({
          origin: WALLET_ORIGIN,
          source: walletFrame,
          data: message,
        });
      },
    };
    const walletFrame: WalletMessageSource = {
      postMessage(message, targetOrigin) {
        expect(targetOrigin).toBe(WALLET_ORIGIN);
        void service.handleMessage({
          origin: HOST_ORIGIN,
          source: hostResponseTarget,
          data: message,
        });
      },
    };
    service = new TrustedWalletService({
      wallet,
      chainId: CHAIN_ID,
      expectedSource: hostResponseTarget,
      confirm: async () => true,
    });
    const client = new WalletHostClient({
      walletWindow: walletFrame,
      walletOrigin: WALLET_ORIGIN,
      eventTarget,
      timeoutMs: 5_000,
    });
    const connection = await client.connect(LIMITS);
    expect("privateKey" in connection).toBe(false);
    const signed = await client.signNativeTransfer({
      protocol_version: 1,
      chain_id: CHAIN_ID,
      nonce: 0,
      authorization_lane: connection.authorization_lane,
      authorization_policy_revision: 0,
      recipient: RECIPIENT,
      amount: "1000000000000",
      fee: { gasLimit: 1_000, maxFeePerUnit: 5, priorityFeePerUnit: 1 },
    });
    expect(await verifySignedTransaction(signed)).toBe(true);
    await client.revoke();
    client.close();
  });
});

/** Reads back a connection result from the last captured response. */
function lastConnection(source: CapturingSource): {
  lane: string;
  sessionId: string;
} {
  const response = source.messages.at(-1)?.response;
  if (!response?.ok || !("session_id" in response.result)) {
    throw new Error("expected connection result");
  }
  return {
    lane: response.result.authorization_lane,
    sessionId: response.result.session_id,
  };
}

describe("trusted wallet service persistence", () => {
  it("persists grants and carries cumulative spend across a restart and reconnect", async () => {
    let saved: readonly PersistedPermissionGrant[] = [];
    const persistence: PermissionPersistencePort = {
      async save(records) {
        saved = records;
      },
    };

    // First wallet session: connect, then spend 2 WEBC of the 2.5 WEBC cap.
    const source1 = new CapturingSource();
    const service1 = new TrustedWalletService({
      wallet,
      chainId: CHAIN_ID,
      expectedSource: source1,
      confirm: async () => true,
      persistence,
    });
    await service1.handleMessage({
      origin: HOST_ORIGIN,
      source: source1,
      data: connectRequest(requestId("1")),
    });
    const first = lastConnection(source1);
    await service1.handleMessage({
      origin: HOST_ORIGIN,
      source: source1,
      data: transferRequest(requestId("2"), first.lane, first.sessionId, 0, "2000000000000"),
    });
    expect(source1.messages.at(-1)?.response.ok).toBe(true);
    // The durable snapshot records the 2 WEBC cumulative spend for this origin.
    expect(saved).toHaveLength(1);
    expect(saved[0]?.origin).toBe(HOST_ORIGIN);
    expect(saved[0]?.spent_amount).toBe("2000000000000");

    // Second wallet session restores the snapshot and the origin reconnects.
    const source2 = new CapturingSource();
    const service2 = new TrustedWalletService({
      wallet,
      chainId: CHAIN_ID,
      expectedSource: source2,
      confirm: async () => true,
      persistence,
      restoredGrants: saved,
    });
    await service2.handleMessage({
      origin: HOST_ORIGIN,
      source: source2,
      data: connectRequest(requestId("3")),
    });
    const second = lastConnection(source2);
    // The lane is deterministic, so it is identical across the restart.
    expect(second.lane).toBe(first.lane);

    // Only 0.5 WEBC of the 2.5 WEBC cumulative cap remains. A 1 WEBC transfer
    // must be rejected: the carried-over spend was not reset by reconnecting.
    await service2.handleMessage({
      origin: HOST_ORIGIN,
      source: source2,
      data: transferRequest(requestId("4"), second.lane, second.sessionId, 0, "1000000000000"),
    });
    const rejected = source2.messages.at(-1)?.response;
    expect(rejected?.ok).toBe(false);
    if (rejected && !rejected.ok) expect(rejected.error.code).toBe("LIMIT_EXCEEDED");
  });

  it("rolls back the spend when the durable write fails, then succeeds on retry", async () => {
    let failNextSave = false;
    let saved: readonly PersistedPermissionGrant[] = [];
    const persistence: PermissionPersistencePort = {
      async save(records) {
        if (failNextSave) {
          failNextSave = false;
          throw new Error("simulated storage failure");
        }
        saved = records;
      },
    };
    const source = new CapturingSource();
    const service = new TrustedWalletService({
      wallet,
      chainId: CHAIN_ID,
      expectedSource: source,
      confirm: async () => true,
      persistence,
    });
    await service.handleMessage({
      origin: HOST_ORIGIN,
      source,
      data: connectRequest(requestId("1")),
    });
    const { lane, sessionId } = lastConnection(source);

    // The next save (the spend) fails; the request must report INTERNAL_ERROR
    // and roll back both the spend and the sequence.
    failNextSave = true;
    await service.handleMessage({
      origin: HOST_ORIGIN,
      source,
      data: transferRequest(requestId("2"), lane, sessionId, 0),
    });
    const failed = source.messages.at(-1)?.response;
    expect(failed?.ok).toBe(false);
    if (failed && !failed.ok) expect(failed.error.code).toBe("INTERNAL_ERROR");

    // Retrying the same sequence now succeeds, proving the sequence rolled back.
    await service.handleMessage({
      origin: HOST_ORIGIN,
      source,
      data: transferRequest(requestId("3"), lane, sessionId, 0),
    });
    const retried = source.messages.at(-1)?.response;
    expect(retried?.ok).toBe(true);
    if (retried?.ok && "signature" in retried.result) {
      expect(await verifySignedTransaction(retried.result)).toBe(true);
    }
    expect(saved[0]?.spent_amount).toBe("1000000000000");
  });

  it("re-validates restoredGrants and rejects a budget-widening negative spend", async () => {
    // A caller that bypasses the store and hands the constructor a hostile grant
    // with a negative cumulative spend must be rejected, not trusted: otherwise
    // `spentAmount` would go negative and widen the effective cumulative cap.
    const hostile: PersistedPermissionGrant[] = [
      {
        origin: HOST_ORIGIN,
        authorization_lane: "a".repeat(64),
        scopes: ["sign_native_transfer"],
        limits: LIMITS,
        spent_amount: "-100",
      },
    ];
    expect(
      () =>
        new TrustedWalletService({
          wallet,
          chainId: CHAIN_ID,
          expectedSource: new CapturingSource(),
          confirm: async () => true,
          restoredGrants: hostile,
        }),
    ).toThrow();
  });

  it("requires user confirmation to revoke, preserving spend when rejected", async () => {
    const source = new CapturingSource();
    let confirmRevoke = false;
    const service = new TrustedWalletService({
      wallet,
      chainId: CHAIN_ID,
      expectedSource: source,
      confirm: async (confirmation) =>
        confirmation.kind === "revoke" ? confirmRevoke : true,
    });
    await service.handleMessage({
      origin: HOST_ORIGIN,
      source,
      data: connectRequest(requestId("1")),
    });
    const { lane, sessionId } = lastConnection(source);
    await service.handleMessage({
      origin: HOST_ORIGIN,
      source,
      data: transferRequest(requestId("2"), lane, sessionId, 0, "2000000000000"),
    });
    expect(source.messages.at(-1)?.response.ok).toBe(true);

    // A host-driven revoke the user rejects must not clear the grant.
    await service.handleMessage({
      origin: HOST_ORIGIN,
      source,
      data: {
        channel: WALLET_MESSAGE_CHANNEL,
        version: WALLET_MESSAGE_VERSION,
        request_id: requestId("3"),
        method: "revoke",
        params: {},
      },
    });
    const rejected = source.messages.at(-1)?.response;
    expect(rejected?.ok).toBe(false);
    if (rejected && !rejected.ok) expect(rejected.error.code).toBe("USER_REJECTED");

    // The grant (and its 2 WEBC spend) survives: a further 1 WEBC transfer that
    // would exceed the 2.5 WEBC cumulative cap is still rejected as over-limit,
    // proving the spend was not reset by the rejected revoke.
    await service.handleMessage({
      origin: HOST_ORIGIN,
      source,
      data: transferRequest(requestId("4"), lane, sessionId, 1, "1000000000000"),
    });
    const overLimit = source.messages.at(-1)?.response;
    expect(overLimit?.ok).toBe(false);
    if (overLimit && !overLimit.ok) expect(overLimit.error.code).toBe("LIMIT_EXCEEDED");
  });

  it("keeps a restored grant dormant until the origin reconnects", async () => {
    const restored: PersistedPermissionGrant[] = [
      {
        origin: HOST_ORIGIN,
        authorization_lane: "a".repeat(64),
        scopes: ["sign_native_transfer"],
        limits: LIMITS,
        spent_amount: "0",
      },
    ];
    const source = new CapturingSource();
    const service = new TrustedWalletService({
      wallet,
      chainId: CHAIN_ID,
      expectedSource: source,
      confirm: async () => true,
      restoredGrants: restored,
    });
    // A signing attempt on the restored lane without reconnecting has no live
    // session, so it is rejected as stale rather than honored.
    await service.handleMessage({
      origin: HOST_ORIGIN,
      source,
      data: transferRequest(requestId("9"), "a".repeat(64), "f".repeat(64), 0),
    });
    const response = source.messages.at(-1)?.response;
    expect(response?.ok).toBe(false);
    if (response && !response.ok) expect(response.error.code).toBe("REQUEST_REPLAY");
  });
});
