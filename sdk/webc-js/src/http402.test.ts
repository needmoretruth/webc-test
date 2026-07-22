/**
 * Tests for the HTTP-402 agent-payment flow (`http402.ts`, agent-commerce §4).
 *
 * The whole flow is exercised with MOCK challenges and MOCK registry entries: no
 * network is touched. The registry entry is a plain caller-provided object, so the
 * validator (the security core) is a pure function. The payment assertions pin the
 * built transaction against the EXACT operation JSON and access list the existing
 * `transaction.ts` builders produce, proving this module composes them without
 * changing their output.
 */

import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import { bytesToHex } from "./hex";
import { createWalletFromSeed } from "./wallet";
import type { WebcWallet } from "./wallet";
import {
  accessListForServiceSpend,
  spendUnderMandateToService,
  transactionHashHex,
  verifySignedTransaction,
} from "./transaction";
import {
  auditRecord,
  buildPayment,
  ChallengeError,
  makeRetry,
  parseChallenge,
  validateChallenge,
} from "./http402";
import type { PaymentChallenge, ServiceEntry } from "./http402";

const SERVICE_ID = "88".repeat(32);
const MANDATE_ID = "99".repeat(32);
const OP_INFER = "11".repeat(32);
const INVOICE_NONCE = "deadbeef";
const PRICE = "1000";
const EXPIRY = 2_000_000_000; // ~2033-05-18
const NOW = 1_000_000_000; // ~2001-09-09, well before EXPIRY
const CHAIN_ID = "webc-devnet-1";
const FEE = { gasLimit: 1000, maxFeePerUnit: 1, priorityFeePerUnit: 0 };

async function walletFromSeedByte(byte: number): Promise<WebcWallet> {
  return createWalletFromSeed(new Uint8Array(32).fill(byte));
}

/** Lowercase hex of a UTF-8 string, matching the SDK's `unit` encoding. */
function hexOfText(text: string): string {
  return bytesToHex(new TextEncoder().encode(text));
}

/** A fresh, well-formed registry entry owned by `owner`. */
function mkEntry(owner: string): ServiceEntry {
  return {
    service_id: SERVICE_ID,
    owner,
    status: "Active",
    pricing: [{ operation: OP_INFER, price: PRICE, unit: hexOfText("call") }],
    payment_flags: { on_chain_direct: true, http_402: true, subscription: false },
  };
}

/** A fresh, well-formed challenge that pays `owner` for `OP_INFER`. */
function mkChallenge(owner: string): PaymentChallenge {
  return {
    service_id: SERVICE_ID,
    operation: OP_INFER,
    price: { amount: PRICE, asset: "NativeWebc" },
    pay_to: owner,
    invoice_nonce: INVOICE_NONCE,
    expiry: EXPIRY,
  };
}

/** Asserts a synchronous call throws a `ChallengeError` with `code`. */
function expectReject(fn: () => unknown, code: string): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(ChallengeError);
    expect((err as ChallengeError).code).toBe(code);
    return;
  }
  throw new Error(`expected a ChallengeError(${code}) but none was thrown`);
}

describe("parseChallenge (strict, fail-closed decode)", () => {
  it("parses a well-formed challenge and returns a typed object", async () => {
    const owner = (await walletFromSeedByte(3)).address;
    const raw = JSON.parse(JSON.stringify(mkChallenge(owner)));
    const parsed = parseChallenge(raw);
    expect(parsed).toEqual(mkChallenge(owner));
  });

  it("parses non-native asset variants (validation rejects them later)", () => {
    const wrapped = parseChallenge({
      ...baseRaw(),
      price: { amount: PRICE, asset: { WrappedWebc: { origin_chain: "Ethereum" } } },
    });
    expect(wrapped.price.asset).toEqual({ WrappedWebc: { origin_chain: "Ethereum" } });
    const external = parseChallenge({
      ...baseRaw(),
      price: {
        amount: PRICE,
        asset: { External: { origin_chain: "Solana", symbol: "USDC", contract_or_mint: "x" } },
      },
    });
    expect(external.price.asset).toEqual({
      External: { origin_chain: "Solana", symbol: "USDC", contract_or_mint: "x" },
    });
  });

  it("rejects a non-object body", () => {
    expectReject(() => parseChallenge(null), "malformed");
    expectReject(() => parseChallenge("nope"), "malformed");
    expectReject(() => parseChallenge([1, 2]), "malformed");
  });

  it("rejects an unexpected top-level field", () => {
    expectReject(() => parseChallenge({ ...baseRaw(), extra: 1 }), "malformed");
  });

  it("rejects an unexpected price sub-field", () => {
    expectReject(
      () => parseChallenge({ ...baseRaw(), price: { amount: PRICE, asset: "NativeWebc", tip: 1 } }),
      "malformed",
    );
  });

  it("rejects a missing field", () => {
    const raw = baseRaw();
    delete (raw as Record<string, unknown>).operation;
    expectReject(() => parseChallenge(raw), "malformed");
  });

  it("rejects uppercase / wrong-length hex ids", () => {
    expectReject(() => parseChallenge({ ...baseRaw(), service_id: "AB".repeat(32) }), "malformed");
    expectReject(() => parseChallenge({ ...baseRaw(), operation: "11".repeat(31) }), "malformed");
  });

  it("rejects a non-canonical amount", () => {
    expectReject(
      () => parseChallenge({ ...baseRaw(), price: { amount: "01", asset: "NativeWebc" } }),
      "malformed",
    );
    expectReject(
      () => parseChallenge({ ...baseRaw(), price: { amount: "-5", asset: "NativeWebc" } }),
      "malformed",
    );
  });

  it("rejects an unrecognized asset shape", () => {
    expectReject(
      () => parseChallenge({ ...baseRaw(), price: { amount: PRICE, asset: "Bitcoin" } }),
      "malformed",
    );
    expectReject(
      () =>
        parseChallenge({
          ...baseRaw(),
          price: { amount: PRICE, asset: { WrappedWebc: { origin_chain: "Mars" } } },
        }),
      "malformed",
    );
  });

  it("rejects a non-webc1 pay_to address", () => {
    expectReject(() => parseChallenge({ ...baseRaw(), pay_to: "0xdeadbeef" }), "malformed");
  });

  it("rejects a malformed invoice nonce", () => {
    expectReject(() => parseChallenge({ ...baseRaw(), invoice_nonce: "" }), "malformed");
    expectReject(() => parseChallenge({ ...baseRaw(), invoice_nonce: "abc" }), "malformed"); // odd length
    expectReject(() => parseChallenge({ ...baseRaw(), invoice_nonce: "DE" }), "malformed"); // uppercase
  });

  it("rejects a non-integer / negative expiry", () => {
    expectReject(() => parseChallenge({ ...baseRaw(), expiry: -1 }), "malformed");
    expectReject(() => parseChallenge({ ...baseRaw(), expiry: 1.5 }), "malformed");
    expectReject(() => parseChallenge({ ...baseRaw(), expiry: "2000000000" }), "malformed");
  });
});

/** Raw (untyped) well-formed challenge body reused across parse tests. */
function baseRaw(): Record<string, unknown> {
  return {
    service_id: SERVICE_ID,
    operation: OP_INFER,
    price: { amount: PRICE, asset: "NativeWebc" },
    pay_to: "webc153HwTorSAA3P8GNpTs1Z19dKPKVt5pmMQa2XbJ8Ff71V",
    invoice_nonce: INVOICE_NONCE,
    expiry: EXPIRY,
  };
}

describe("validateChallenge (against the on-chain registry entry)", () => {
  it("accepts a matching challenge before expiry", async () => {
    const owner = (await walletFromSeedByte(3)).address;
    expect(() => validateChallenge(mkChallenge(owner), mkEntry(owner), { now: NOW })).not.toThrow();
  });

  it("rejects a price mismatch (defeats silent overcharge)", async () => {
    const owner = (await walletFromSeedByte(3)).address;
    const challenge = { ...mkChallenge(owner), price: { amount: "2000", asset: "NativeWebc" as const } };
    expectReject(() => validateChallenge(challenge, mkEntry(owner), { now: NOW }), "price_mismatch");
  });

  it("rejects a pay_to mismatch (defeats fund diversion)", async () => {
    const owner = (await walletFromSeedByte(3)).address;
    const attacker = (await walletFromSeedByte(7)).address;
    const challenge = { ...mkChallenge(owner), pay_to: attacker };
    expectReject(() => validateChallenge(challenge, mkEntry(owner), { now: NOW }), "pay_to_mismatch");
  });

  it("rejects an expired challenge (now >= expiry)", async () => {
    const owner = (await walletFromSeedByte(3)).address;
    expectReject(
      () => validateChallenge(mkChallenge(owner), mkEntry(owner), { now: EXPIRY }),
      "expired",
    );
    expectReject(
      () => validateChallenge(mkChallenge(owner), mkEntry(owner), { now: EXPIRY + 1 }),
      "expired",
    );
  });

  it("rejects a non-native asset", async () => {
    const owner = (await walletFromSeedByte(3)).address;
    const challenge = {
      ...mkChallenge(owner),
      price: { amount: PRICE, asset: { WrappedWebc: { origin_chain: "Ethereum" as const } } },
    };
    expectReject(() => validateChallenge(challenge, mkEntry(owner), { now: NOW }), "wrong_asset");
  });

  it("rejects a paused service", async () => {
    const owner = (await walletFromSeedByte(3)).address;
    const entry: ServiceEntry = { ...mkEntry(owner), status: "Paused" };
    expectReject(() => validateChallenge(mkChallenge(owner), entry, { now: NOW }), "service_paused");
  });

  it("rejects a service that does not accept HTTP-402", async () => {
    const owner = (await walletFromSeedByte(3)).address;
    const entry: ServiceEntry = {
      ...mkEntry(owner),
      payment_flags: { on_chain_direct: true, http_402: false, subscription: false },
    };
    expectReject(
      () => validateChallenge(mkChallenge(owner), entry, { now: NOW }),
      "http402_not_accepted",
    );
  });

  it("rejects a service_id mismatch", async () => {
    const owner = (await walletFromSeedByte(3)).address;
    const entry: ServiceEntry = { ...mkEntry(owner), service_id: "77".repeat(32) };
    expectReject(
      () => validateChallenge(mkChallenge(owner), entry, { now: NOW }),
      "service_id_mismatch",
    );
  });

  it("rejects an operation the entry does not price", async () => {
    const owner = (await walletFromSeedByte(3)).address;
    const challenge = { ...mkChallenge(owner), operation: "22".repeat(32) };
    expectReject(
      () => validateChallenge(challenge, mkEntry(owner), { now: NOW }),
      "unknown_operation",
    );
  });

  it("fails closed on a malformed registry entry", async () => {
    const owner = (await walletFromSeedByte(3)).address;
    const badOwner = { ...mkEntry(owner), owner: "0xnotanaddress" };
    expectReject(() => validateChallenge(mkChallenge(owner), badOwner, { now: NOW }), "malformed");
  });
});

describe("buildPayment (composes the existing SpendUnderMandateToService builders)", () => {
  it("builds a tx with the exact operation JSON and access list the builders produce", async () => {
    const agent = await walletFromSeedByte(1);
    const owner = (await walletFromSeedByte(3)).address;
    const { transaction, reference } = await buildPayment({
      agentWallet: agent,
      mandateId: MANDATE_ID,
      challenge: mkChallenge(owner),
      serviceEntry: mkEntry(owner),
      chainId: CHAIN_ID,
      nonce: 0,
      fee: FEE,
      now: NOW,
    });

    // Exact operation JSON — byte-identical to the existing builder.
    expect(canonicalJson(transaction.operation)).toBe(
      canonicalJson(spendUnderMandateToService(MANDATE_ID, SERVICE_ID, PRICE)),
    );
    // Exact access list — byte-identical to the existing helper.
    expect(transaction.access_list).toEqual(
      accessListForServiceSpend({
        sender: agent.address,
        mandateId: MANDATE_ID,
        serviceId: SERVICE_ID,
        serviceOwner: owner,
      }),
    );
    // The spend is agent-key signed and self-consistent.
    expect(transaction.sender).toBe(agent.address);
    expect(await verifySignedTransaction(transaction)).toBe(true);

    // The retry reference correlates the invoice to the on-chain tx.
    expect(reference).toEqual({
      mandate_id: MANDATE_ID,
      service_id: SERVICE_ID,
      tx_hash: await transactionHashHex(transaction),
      invoice_nonce: INVOICE_NONCE,
    });
  });

  it("threads a non-default authorization lane into the access list", async () => {
    const agent = await walletFromSeedByte(1);
    const owner = (await walletFromSeedByte(3)).address;
    const lane = "0a".repeat(32);
    const { transaction } = await buildPayment({
      agentWallet: agent,
      mandateId: MANDATE_ID,
      challenge: mkChallenge(owner),
      serviceEntry: mkEntry(owner),
      chainId: CHAIN_ID,
      nonce: 4,
      fee: FEE,
      authorizationLane: lane,
      now: NOW,
    });
    expect(transaction.authorization_lane).toBe(lane);
    expect(transaction.access_list).toEqual(
      accessListForServiceSpend({
        sender: agent.address,
        mandateId: MANDATE_ID,
        serviceId: SERVICE_ID,
        serviceOwner: owner,
        authorizationLane: lane,
      }),
    );
    expect(await verifySignedTransaction(transaction)).toBe(true);
  });

  it("fails closed: never signs a spend for an invalid challenge", async () => {
    const agent = await walletFromSeedByte(1);
    const owner = (await walletFromSeedByte(3)).address;
    const attacker = (await walletFromSeedByte(7)).address;
    await expect(
      buildPayment({
        agentWallet: agent,
        mandateId: MANDATE_ID,
        challenge: { ...mkChallenge(owner), pay_to: attacker },
        serviceEntry: mkEntry(owner),
        chainId: CHAIN_ID,
        nonce: 0,
        fee: FEE,
        now: NOW,
      }),
    ).rejects.toMatchObject({ code: "pay_to_mismatch" });
  });
});

describe("makeRetry and auditRecord", () => {
  it("makeRetry validates and builds the reference", () => {
    const reference = makeRetry({
      mandateId: MANDATE_ID,
      serviceId: SERVICE_ID,
      txHash: "ab".repeat(32),
      invoiceNonce: INVOICE_NONCE,
    });
    expect(reference).toEqual({
      mandate_id: MANDATE_ID,
      service_id: SERVICE_ID,
      tx_hash: "ab".repeat(32),
      invoice_nonce: INVOICE_NONCE,
    });
  });

  it("makeRetry rejects a malformed tx hash", () => {
    expectReject(
      () =>
        makeRetry({
          mandateId: MANDATE_ID,
          serviceId: SERVICE_ID,
          txHash: "nothex",
          invoiceNonce: INVOICE_NONCE,
        }),
      "malformed",
    );
  });

  it("auditRecord produces the fixed-order dispute tuple", () => {
    const reference = {
      mandate_id: MANDATE_ID,
      service_id: SERVICE_ID,
      tx_hash: "ab".repeat(32),
      invoice_nonce: INVOICE_NONCE,
    };
    const record = auditRecord(reference);
    expect(record).toEqual({
      mandate_id: MANDATE_ID,
      invoice_nonce: INVOICE_NONCE,
      service_id: SERVICE_ID,
      tx_hash: "ab".repeat(32),
    });
    // Directly serializable for durable record-keeping.
    expect(canonicalJson(record)).toBe(
      `{"invoice_nonce":"${INVOICE_NONCE}","mandate_id":"${MANDATE_ID}",` +
        `"service_id":"${SERVICE_ID}","tx_hash":"${"ab".repeat(32)}"}`,
    );
  });

  it("auditRecord fails closed on a malformed reference", () => {
    expectReject(
      () =>
        auditRecord({
          mandate_id: MANDATE_ID,
          service_id: SERVICE_ID,
          tx_hash: "zz".repeat(32),
          invoice_nonce: INVOICE_NONCE,
        }),
      "malformed",
    );
  });
});
