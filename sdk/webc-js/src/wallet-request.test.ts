/** Malformed-input and exact-display tests for the wallet postMessage schema. */

import { describe, expect, it } from "vitest";
import {
  WALLET_MESSAGE_CHANNEL,
  WALLET_MESSAGE_VERSION,
  isSecureWalletHostOrigin,
  nativeTransferConfirmation,
  parseWalletRequest,
} from "./wallet-request";

const RECIPIENT = "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";

function transferParams() {
  return {
    session_id: "11".repeat(32),
    sequence: 0,
    protocol_version: 1,
    chain_id: "webc-devnet-1",
    nonce: 7,
    authorization_lane: "22".repeat(32),
    authorization_policy_revision: 0,
    recipient: RECIPIENT,
    amount: "123456000000000",
    fee: { gasLimit: 1_000, maxFeePerUnit: 5, priorityFeePerUnit: 1 },
  };
}

function request(params: unknown) {
  return {
    channel: WALLET_MESSAGE_CHANNEL,
    version: WALLET_MESSAGE_VERSION,
    request_id: "33".repeat(32),
    method: "sign_native_transfer",
    params,
  };
}

describe("wallet request parser", () => {
  it("derives exact human-readable fields from the parsed signing intent", () => {
    const parsed = parseWalletRequest(request(transferParams()));
    if (parsed.method !== "sign_native_transfer") throw new Error("wrong method");
    expect(nativeTransferConfirmation("https://shop.example", parsed.params)).toEqual({
      kind: "native_transfer",
      origin: "https://shop.example",
      action: "Send WEBC",
      asset: "WEBC",
      recipient: RECIPIENT,
      amount_base_units: "123456000000000",
      amount_webc: "123.456 WEBC",
      maximum_fee_base_units: "5000",
      chain_id: "webc-devnet-1",
      authorization_lane: "22".repeat(32),
      authorization_policy_revision: 0,
    });
  });

  it("rejects unknown fields, imprecise numbers, zero/overflow, and bad context", () => {
    expect(() =>
      parseWalletRequest(request({ ...transferParams(), display: "blind" })),
    ).toThrow("invalid");
    expect(() =>
      parseWalletRequest(
        request({
          ...transferParams(),
          fee: { ...transferParams().fee, gasLimit: 1.5 },
        }),
      ),
    ).toThrow("invalid");
    expect(() =>
      parseWalletRequest(request({ ...transferParams(), amount: "0" })),
    ).toThrow("invalid");
    expect(() =>
      parseWalletRequest(
        request({
          ...transferParams(),
          authorization_policy_revision: Number.MAX_SAFE_INTEGER + 1,
        }),
      ),
    ).toThrow("invalid");
    expect(() =>
      parseWalletRequest(
        request({ ...transferParams(), amount: (1n << 128n).toString(10) }),
      ),
    ).toThrow("invalid");
    expect(() =>
      parseWalletRequest(request({ ...transferParams(), chain_id: "INVALID" })),
    ).toThrow("invalid");
    expect(() =>
      parseWalletRequest(request({ ...transferParams(), recipient: "webc1bad" })),
    ).toThrow("invalid");
  });

  it("bounds recipient and amount length before any O(n^2) decode (S2)", () => {
    // A megabyte recipient/amount must be rejected by a cheap length check, not
    // after an O(n^2) base58 decode or an O(n^2) BigInt parse that would freeze
    // the trusted popup mid-confirmation. Pre-fix these fields reach the decode
    // before any bound, so the parse takes seconds; post-fix it is instant.
    const hugeRecipient = "webc1" + "z".repeat(100_000);
    const startRecipient = performance.now();
    expect(() =>
      parseWalletRequest(request({ ...transferParams(), recipient: hugeRecipient })),
    ).toThrow("invalid");
    expect(performance.now() - startRecipient).toBeLessThan(1_000);

    const hugeAmount = "9".repeat(100_000);
    const startAmount = performance.now();
    expect(() =>
      parseWalletRequest(request({ ...transferParams(), amount: hugeAmount })),
    ).toThrow("invalid");
    expect(performance.now() - startAmount).toBeLessThan(1_000);
  }, 30_000);

  it("accepts HTTPS and localhost but rejects opaque and insecure web origins", () => {
    expect(isSecureWalletHostOrigin("https://shop.example")).toBe(true);
    expect(isSecureWalletHostOrigin("http://localhost:5173")).toBe(true);
    expect(isSecureWalletHostOrigin("http://127.0.0.1:8080")).toBe(true);
    expect(isSecureWalletHostOrigin("http://shop.example")).toBe(false);
    expect(isSecureWalletHostOrigin("null")).toBe(false);
    expect(isSecureWalletHostOrigin("https://shop.example/path")).toBe(false);
  });
});
