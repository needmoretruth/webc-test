/**
 * Adversarial and cross-language tests for protocol-version-2 receipts.
 *
 * These tests freeze Rust/TypeScript commitment parity and exercise the SDK's
 * hostile-network-data boundary. They do not execute transactions or establish
 * finality; those responsibilities stay with the chain and proof layers.
 */

import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import {
  eventV1DigestHex,
  MAX_RECEIPT_EVENTS_V1,
  receiptRootV1Hex,
  receiptV1DigestHex,
  receiptV1LeafHex,
  transactionRootV1Hex,
  validateReceiptV1,
  verifyTransactionReceiptBindingV1,
  type ReceiptV1Json,
} from "./receipt-v1";
import { transactionV5IdHex, type SignedTransactionV5Json } from "./transaction-v5";

const SENDER = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
const RECIPIENT = "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";
const DEFAULT_LANE = "00".repeat(32);
const SENDER_PAID_ID = "c268d7d32a67ddbe985e18f881bcbd93bcfafcae5fbb6e7145276941b143f50f";
const RECEIPT_DIGEST = "007ce5d68886fc6a1e28688c808f4c5c7fa3213815deb0f924d5c564693e90af";
const RECEIPT_LEAF = "b5a3a00301bb0137b3324657300f8d635d4310b25d239ca9d401f92c04d114de";
const EVENT_DIGEST = "8326e93d7ad7056037c59ca7275b1431905208cf8fab0c95576c7c17c23fe1aa";
const SENDER_PAID_SIGNATURE = "fae71eef9827891d2bc4362ef49ccb9559a7e91fed98f041d0f56d690a120e05f6d3af6396bcd92cd66d63c0af144fdbf654fb2b4cd59162637dbe76592d050a";

function transaction(nonce = "7"): SignedTransactionV5Json {
  return {
    protocol_version: 2,
    chain_id: "webc-devnet-1",
    sender: SENDER,
    sender_public_key: "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
    authorization: { lane: DEFAULT_LANE, policy_revision: "0", nonce },
    validity: { valid_from_height: "10", valid_until_height: "20" },
    kind: { Actions: { actions: [{ Native: { operation: { Transfer: { to: RECIPIENT, amount: "123456" } } } }] } },
    access_list: {
      read_only: [
        { version: 1, kind: { AuthorizationPolicy: { owner: SENDER } } },
        { version: 1, kind: { Protocol: { field: "BaseFee" } } },
      ],
      read_write: [
        { version: 1, kind: { Account: { address: SENDER } } },
        { version: 1, kind: { Account: { address: RECIPIENT } } },
        { version: 1, kind: { FeeAccumulator: { lane: DEFAULT_LANE, payer: SENDER } } },
      ],
    },
    fee_bid: { gas_limit: "1000", max_fee_per_unit: "5", priority_fee_per_unit: "1" },
    fee_payment: "SenderLane",
    sender_signature: nonce === "7" ? SENDER_PAID_SIGNATURE : nonce.padStart(128, "0"),
  };
}

async function receipt(tx: SignedTransactionV5Json, index = 0): Promise<ReceiptV1Json> {
  const transactionId = await transactionV5IdHex(tx);
  return {
    version: 1,
    position: { height: "42", transaction_index: index },
    transaction_id: transactionId,
    sender: SENDER,
    status: "Succeeded",
    fee_summary: {
      version: 1,
      payer: { address: SENDER, lane: DEFAULT_LANE },
      gas_limit: "1000",
      units_consumed: "100",
      base_fee_per_unit: "2",
      priority_fee_per_unit: "1",
      max_fee_per_unit: "5",
      reserved: "5000",
      base_fee: "200",
      priority_fee: "100",
      charged: "300",
      refund: "4700",
      burned: "100",
      validator_reward: "200",
    },
    events: [{
      version: 1,
      transaction_id: transactionId,
      action_index: 0,
      event_index: 0,
      body: { Transfer: { from: SENDER, to: RECIPIENT, amount: "123456" } },
    }],
  };
}

describe("V1 receipts and ordered roots", () => {
  it("validates, domain-separates, and binds a receipt to its signed transaction", async () => {
    const tx = transaction();
    const value = await receipt(tx);
    expect(() => validateReceiptV1(value)).not.toThrow();
    await expect(verifyTransactionReceiptBindingV1("42", [tx], [value])).resolves.toBeUndefined();
    expect(await receiptV1DigestHex(value)).not.toBe(await receiptV1LeafHex(value));
    expect(await eventV1DigestHex(value.events[0])).not.toBe(await receiptV1DigestHex(value));
  });

  it("reproduces the frozen Rust sender-paid receipt vector byte-for-byte", async () => {
    const tx = transaction();
    const value = await receipt(tx);
    expect(await transactionV5IdHex(tx)).toBe(SENDER_PAID_ID);
    expect(canonicalJson(value)).toBe(
      "{\"events\":[{\"action_index\":0,\"body\":{\"Transfer\":{\"amount\":\"123456\",\"from\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\",\"to\":\"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem\"}},\"event_index\":0,\"transaction_id\":\"c268d7d32a67ddbe985e18f881bcbd93bcfafcae5fbb6e7145276941b143f50f\",\"version\":1}],\"fee_summary\":{\"base_fee\":\"200\",\"base_fee_per_unit\":\"2\",\"burned\":\"100\",\"charged\":\"300\",\"gas_limit\":\"1000\",\"max_fee_per_unit\":\"5\",\"payer\":{\"address\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\",\"lane\":\"0000000000000000000000000000000000000000000000000000000000000000\"},\"priority_fee\":\"100\",\"priority_fee_per_unit\":\"1\",\"refund\":\"4700\",\"reserved\":\"5000\",\"units_consumed\":\"100\",\"validator_reward\":\"200\",\"version\":1},\"position\":{\"height\":\"42\",\"transaction_index\":0},\"sender\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\",\"status\":\"Succeeded\",\"transaction_id\":\"c268d7d32a67ddbe985e18f881bcbd93bcfafcae5fbb6e7145276941b143f50f\",\"version\":1}",
    );
    expect(await eventV1DigestHex(value.events[0])).toBe(EVENT_DIGEST);
    expect(await receiptV1DigestHex(value)).toBe(RECEIPT_DIGEST);
    expect(await receiptV1LeafHex(value)).toBe(RECEIPT_LEAF);
    expect(await receiptRootV1Hex([value])).toBe(RECEIPT_LEAF);
  });

  it("rejects fee, ordering, identity, position, and action-bound tampering", async () => {
    const tx = transaction();
    const value = await receipt(tx);

    const badFee = structuredClone(value);
    badFee.fee_summary.refund = "4701";
    expect(() => validateReceiptV1(badFee)).toThrow(/reconcile/u);

    const badEventIndex = structuredClone(value);
    badEventIndex.events[0].event_index = 1;
    expect(() => validateReceiptV1(badEventIndex)).toThrow(/array position/u);

    const wrongPosition = structuredClone(value);
    wrongPosition.position.transaction_index = 1;
    await expect(verifyTransactionReceiptBindingV1("42", [tx], [wrongPosition])).rejects.toThrow(/position/u);

    const wrongSender = structuredClone(value);
    wrongSender.sender = RECIPIENT;
    await expect(verifyTransactionReceiptBindingV1("42", [tx], [wrongSender])).rejects.toThrow(/sender/u);

    const badAction = structuredClone(value);
    badAction.events[0].action_index = 1;
    await expect(verifyTransactionReceiptBindingV1("42", [tx], [badAction])).rejects.toThrow(/out of range/u);
  });

  it("uses zero for empty trees, duplicates odd leaves, and rejects duplicate transaction IDs", async () => {
    expect(await receiptRootV1Hex([])).toBe("00".repeat(32));
    expect(await transactionRootV1Hex("42", [])).toBe("00".repeat(32));

    const first = transaction("7");
    const second = transaction("8");
    const firstReceipt = await receipt(first, 0);
    const secondReceipt = await receipt(second, 1);
    expect(await receiptRootV1Hex([firstReceipt])).not.toBe("00".repeat(32));
    expect(await receiptRootV1Hex([firstReceipt, secondReceipt])).not.toBe(
      await transactionRootV1Hex("42", [first, second]),
    );
    await expect(transactionRootV1Hex("42", [first, first])).rejects.toThrow(/duplicate/u);
  });

  it("rejects unsafe legacy event numbers before hashing", async () => {
    const value = await receipt(transaction());
    value.events[0].body = { EpochRewardsDistributed: { epoch: Number.MAX_SAFE_INTEGER + 1, total: "1" } };
    expect(() => validateReceiptV1(value)).toThrow(/unsafe JSON number/u);
  });

  it("rejects unknown native event variants", async () => {
    const value = await receipt(transaction());
    value.events[0].body = { InventedEvent: {} };
    expect(() => validateReceiptV1(value)).toThrow(/unknown native event variant/u);
  });

  it("rejects unknown native event fields", async () => {
    const value = await receipt(transaction());
    value.events[0].body = {
      Transfer: { from: SENDER, to: RECIPIENT, amount: "123456", memo: "not on the Rust wire" },
    };
    expect(() => validateReceiptV1(value)).toThrow(/unexpected field set/u);
  });

  it("rejects native event fields with the wrong wire type", async () => {
    const value = await receipt(transaction());
    value.events[0].body = { Transfer: { from: SENDER, to: RECIPIENT, amount: true } };
    expect(() => validateReceiptV1(value)).toThrow(/canonical decimal string/u);
  });

  it("accepts the deepest current Rust BridgeEvent shape and rejects nested drift", async () => {
    const value = await receipt(transaction());
    value.events[0].body = {
      Bridge: {
        event: {
          Locked: {
            message: {
              source_chain: "Ethereum",
              destination_chain: "Webc",
              nonce: 9,
              asset: {
                External: {
                  origin_chain: "Ethereum",
                  symbol: "USDC",
                  contract_or_mint: "0x1234",
                },
              },
              sender: "abcd",
              recipient: "12".repeat(32),
              amount: "77",
              source_tx: "77".repeat(32),
            },
            message_hash: "88".repeat(32),
          },
        },
      },
    };
    expect(() => validateReceiptV1(value)).not.toThrow();

    const unknownField = structuredClone(value);
    const bridge = unknownField.events[0].body.Bridge as Record<string, unknown>;
    const event = bridge.event as Record<string, unknown>;
    const locked = event.Locked as Record<string, unknown>;
    const message = locked.message as Record<string, unknown>;
    message.proof = "not part of BridgeMessage";
    expect(() => validateReceiptV1(unknownField)).toThrow(/unexpected field set/u);

    const oversizedAddress = structuredClone(value);
    const oversizedBridge = oversizedAddress.events[0].body.Bridge as Record<string, unknown>;
    const oversizedEvent = oversizedBridge.event as Record<string, unknown>;
    const oversizedLocked = oversizedEvent.Locked as Record<string, unknown>;
    const oversizedMessage = oversizedLocked.message as Record<string, unknown>;
    oversizedMessage.recipient = "aa".repeat(129);
    expect(() => validateReceiptV1(oversizedAddress)).toThrow(/128 bytes/u);
  });

  it("rejects deeply nested native event JSON without recursive descent", async () => {
    const value = await receipt(transaction());
    let nested: unknown = null;
    for (let depth = 0; depth < 64; depth += 1) nested = { child: nested };
    value.events[0].body = { Transfer: nested };
    expect(() => validateReceiptV1(value)).toThrow(/depth limit/u);
  });

  it("rejects native event JSON that exceeds the structural node budget", async () => {
    const value = await receipt(transaction());
    value.events[0].body = {
      Transfer: Object.fromEntries(Array.from({ length: 512 }, (_, index) => [`field_${index}`, null])),
    };
    expect(() => validateReceiptV1(value)).toThrow(/node budget/u);
  });

  it("rejects an oversized hostile event array before hashing", async () => {
    const value = await receipt(transaction());
    const template = value.events[0];
    value.events = Array.from({ length: MAX_RECEIPT_EVENTS_V1 + 1 }, (_, index) => ({
      ...structuredClone(template),
      event_index: index,
    }));
    expect(() => validateReceiptV1(value)).toThrow(/event array exceeds/u);
    await expect(receiptV1LeafHex(value)).rejects.toThrow(/event array exceeds/u);
  });
});
