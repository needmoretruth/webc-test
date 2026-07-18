/**
 * Frozen protocol-version-2 (V5) cross-language transaction fixtures.
 *
 * Every value here is produced by the Rust reference verifier
 * `webc_chain::transaction_v5` and is asserted byte-for-byte, so the browser SDK
 * and the node cannot silently diverge on the signed wire, the transaction
 * identity, action/fee-bid digests, or the scoped-sponsor bindings. The exact
 * Rust generators are the inline tests
 * `sender_paid_transfer_has_frozen_cross_language_v5_vector` and
 * `scoped_sponsor_has_frozen_cross_language_v5_vector`. Changing any frozen value
 * is a wire-compatibility break: it requires a coordinated protocol-version bump
 * and a matching Rust update. Never edit a frozen vector to make a test pass.
 */

import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import {
  createSponsorUseV1,
  feeBidV1DigestHex,
  revokeSponsorGrantActionV1,
  sessionAuthorizationAccessListV1,
  signSponsorGrantV1,
  sponsorGrantSigningBytes,
  sponsorGrantV1DigestHex,
  sponsorUseV1DigestHex,
  transactionKindV1DigestHex,
  transactionV5IdHex,
  transactionV5SigningBytes,
  verifySignedTransactionV5,
  verifySponsorGrantV1,
} from "./transaction-v5";
import { createWalletFromSeed } from "./wallet";
import type {
  SignedTransactionV5Json,
  SponsorGrantV1Json,
  SponsorUseV1Json,
  TransactionKindV1Json,
} from "./transaction-v5";

const SENDER = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
const RECIPIENT = "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";
const SPONSOR = "webc121uVaRnHeoTdcumRjrvYZuEaBBiHn4wito3PKSpNzjAf";
const DEFAULT_LANE = "00".repeat(32);

const SENDER_PUBLIC_KEY =
  "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const SPONSOR_PUBLIC_KEY =
  "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1";
const ACTION_DIGEST =
  "bb25a54623accd384abc84091335e289a9d3cfca5728b7f775f0329c6fa3e0a0";
const FEE_BID_DIGEST =
  "3b304bcd83127294f126ab796e0614bed9472e888420b0bcbcbabc4ca6004c0c";
const GRANT_DIGEST =
  "4bae024a7f9c82f7218cbdda309a7734d4e8c02b2c2a530376ac7531a499eb57";
const SPONSOR_USE_DIGEST =
  "4d929bbcb2e2e6bb8b827b3a584de213cca91aca95ce9e6e838c16b4da29fc83";

const SENDER_PAID_SIGNATURE =
  "fae71eef9827891d2bc4362ef49ccb9559a7e91fed98f041d0f56d690a120e05f6d3af6396bcd92cd66d63c0af144fdbf654fb2b4cd59162637dbe76592d050a";
const SENDER_PAID_ID =
  "c268d7d32a67ddbe985e18f881bcbd93bcfafcae5fbb6e7145276941b143f50f";
const SPONSORED_SIGNATURE =
  "eb06340360bf3147dff476900edbe65e1f9c90fb4ca2196056ef5a22ce46bcc665d432dbef9585ef42ef6aba5031574a42efae1ffed743f8ca3895ce258a1904";
const SPONSOR_GRANT_SIGNATURE =
  "8114099820bc2d1cdfd7be9a9180fe848c98dad6b9a1b54cbfa3a5dbb61f73b82bbe9ba37f2f0370ed73d3d460bed9a3faebee629c7743fa4d53bd554650820d";
const SPONSORED_ID =
  "b44978261941c3bb0f6f42722d9671330ba9c7d307ee5e3e697906fcc16b89bd";

const SENDER_PAID_SIGNING_JSON =
  '{"access_list":{"read_only":[{"kind":{"AuthorizationPolicy":{"owner":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3"}},"version":1},{"kind":{"Protocol":{"field":"BaseFee"}},"version":1}],"read_write":[{"kind":{"Account":{"address":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3"}},"version":1},{"kind":{"Account":{"address":"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem"}},"version":1},{"kind":{"FeeAccumulator":{"lane":"0000000000000000000000000000000000000000000000000000000000000000","payer":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3"}},"version":1}]},"authorization":{"lane":"0000000000000000000000000000000000000000000000000000000000000000","nonce":"7","policy_revision":"0"},"chain_id":"webc-devnet-1","domain":"WEBC_SIGNED_TRANSACTION_V5","fee_bid":{"gas_limit":"1000","max_fee_per_unit":"5","priority_fee_per_unit":"1"},"fee_payment":"SenderLane","kind":{"Actions":{"actions":[{"Native":{"operation":{"Transfer":{"amount":"123456","to":"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem"}}}}]}},"protocol_version":2,"sender":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3","sender_public_key":"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c","validity":{"valid_from_height":"10","valid_until_height":"20"}}';

const SENDER_PAID_FULL_JSON =
  '{"access_list":{"read_only":[{"kind":{"AuthorizationPolicy":{"owner":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3"}},"version":1},{"kind":{"Protocol":{"field":"BaseFee"}},"version":1}],"read_write":[{"kind":{"Account":{"address":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3"}},"version":1},{"kind":{"Account":{"address":"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem"}},"version":1},{"kind":{"FeeAccumulator":{"lane":"0000000000000000000000000000000000000000000000000000000000000000","payer":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3"}},"version":1}]},"authorization":{"lane":"0000000000000000000000000000000000000000000000000000000000000000","nonce":"7","policy_revision":"0"},"chain_id":"webc-devnet-1","fee_bid":{"gas_limit":"1000","max_fee_per_unit":"5","priority_fee_per_unit":"1"},"fee_payment":"SenderLane","kind":{"Actions":{"actions":[{"Native":{"operation":{"Transfer":{"amount":"123456","to":"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem"}}}}]}},"protocol_version":2,"sender":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3","sender_public_key":"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c","sender_signature":"fae71eef9827891d2bc4362ef49ccb9559a7e91fed98f041d0f56d690a120e05f6d3af6396bcd92cd66d63c0af144fdbf654fb2b4cd59162637dbe76592d050a","validity":{"valid_from_height":"10","valid_until_height":"20"}}';

const SPONSOR_GRANT_SIGNING_JSON =
  '{"action_scope":{"exact_action_digest":"bb25a54623accd384abc84091335e289a9d3cfca5728b7f775f0329c6fa3e0a0"},"application_namespace":null,"chain_id":"webc-devnet-1","domain":"WEBC_SPONSOR_GRANT_V1","grant_id":"4444444444444444444444444444444444444444444444444444444444444444","max_cumulative_fee":"100000","max_fee_per_transaction":"10000","max_uses":"10","payer_lane":"5555555555555555555555555555555555555555555555555555555555555555","protocol_version":2,"sender":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3","site_namespace":"6666666666666666666666666666666666666666666666666666666666666666","sponsor":"webc121uVaRnHeoTdcumRjrvYZuEaBBiHn4wito3PKSpNzjAf","sponsor_public_key":"ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1","validity":{"valid_from_height":"10","valid_until_height":"20"}}';

const SPONSORED_FULL_JSON =
  '{"access_list":{"read_only":[{"kind":{"AuthorizationPolicy":{"owner":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3"}},"version":1},{"kind":{"Protocol":{"field":"BaseFee"}},"version":1}],"read_write":[{"kind":{"Account":{"address":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3"}},"version":1},{"kind":{"Account":{"address":"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem"}},"version":1},{"kind":{"FeeAccumulator":{"lane":"0000000000000000000000000000000000000000000000000000000000000000","payer":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3"}},"version":1}]},"authorization":{"lane":"0000000000000000000000000000000000000000000000000000000000000000","nonce":"7","policy_revision":"0"},"chain_id":"webc-devnet-1","fee_bid":{"gas_limit":"1000","max_fee_per_unit":"5","priority_fee_per_unit":"1"},"fee_payment":{"Sponsored":{"action_digest":"bb25a54623accd384abc84091335e289a9d3cfca5728b7f775f0329c6fa3e0a0","fee_bid_digest":"3b304bcd83127294f126ab796e0614bed9472e888420b0bcbcbabc4ca6004c0c","grant":{"action_scope":{"exact_action_digest":"bb25a54623accd384abc84091335e289a9d3cfca5728b7f775f0329c6fa3e0a0"},"application_namespace":null,"chain_id":"webc-devnet-1","grant_id":"4444444444444444444444444444444444444444444444444444444444444444","max_cumulative_fee":"100000","max_fee_per_transaction":"10000","max_uses":"10","payer_lane":"5555555555555555555555555555555555555555555555555555555555555555","protocol_version":2,"sender":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3","site_namespace":"6666666666666666666666666666666666666666666666666666666666666666","sponsor":"webc121uVaRnHeoTdcumRjrvYZuEaBBiHn4wito3PKSpNzjAf","sponsor_public_key":"ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1","sponsor_signature":"8114099820bc2d1cdfd7be9a9180fe848c98dad6b9a1b54cbfa3a5dbb61f73b82bbe9ba37f2f0370ed73d3d460bed9a3faebee629c7743fa4d53bd554650820d","validity":{"valid_from_height":"10","valid_until_height":"20"}},"grant_digest":"4bae024a7f9c82f7218cbdda309a7734d4e8c02b2c2a530376ac7531a499eb57","use_nonce":"0"}},"kind":{"Actions":{"actions":[{"Native":{"operation":{"Transfer":{"amount":"123456","to":"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem"}}}}]}},"protocol_version":2,"sender":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3","sender_public_key":"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c","sender_signature":"eb06340360bf3147dff476900edbe65e1f9c90fb4ca2196056ef5a22ce46bcc665d432dbef9585ef42ef6aba5031574a42efae1ffed743f8ca3895ce258a1904","validity":{"valid_from_height":"10","valid_until_height":"20"}}';

/** Builds the frozen sender-paid transfer exactly as the Rust fixture. */
function senderPaidFixture(): SignedTransactionV5Json {
  return {
    protocol_version: 2,
    chain_id: "webc-devnet-1",
    sender: SENDER,
    sender_public_key: SENDER_PUBLIC_KEY,
    authorization: { lane: DEFAULT_LANE, policy_revision: "0", nonce: "7" },
    validity: { valid_from_height: "10", valid_until_height: "20" },
    kind: {
      Actions: {
        actions: [
          { Native: { operation: { Transfer: { to: RECIPIENT, amount: "123456" } } } },
        ],
      },
    },
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
    sender_signature: SENDER_PAID_SIGNATURE,
  };
}

/** Builds the frozen scoped-sponsor grant exactly as the Rust fixture. */
function sponsorGrantFixture(): SponsorGrantV1Json {
  return {
    protocol_version: 2,
    chain_id: "webc-devnet-1",
    grant_id: "44".repeat(32),
    sponsor: SPONSOR,
    sponsor_public_key: SPONSOR_PUBLIC_KEY,
    payer_lane: "55".repeat(32),
    sender: SENDER,
    site_namespace: "66".repeat(32),
    application_namespace: null,
    action_scope: { exact_action_digest: ACTION_DIGEST },
    validity: { valid_from_height: "10", valid_until_height: "20" },
    max_fee_per_transaction: "10000",
    max_cumulative_fee: "100000",
    max_uses: "10",
    sponsor_signature: SPONSOR_GRANT_SIGNATURE,
  };
}

/** Builds the frozen sponsored transfer exactly as the Rust fixture. */
function sponsoredFixture(): SignedTransactionV5Json {
  const sponsorUse: SponsorUseV1Json = {
    grant: sponsorGrantFixture(),
    grant_digest: GRANT_DIGEST,
    use_nonce: "0",
    action_digest: ACTION_DIGEST,
    fee_bid_digest: FEE_BID_DIGEST,
  };
  return {
    ...senderPaidFixture(),
    fee_payment: { Sponsored: sponsorUse },
    sender_signature: SPONSORED_SIGNATURE,
  };
}

function decode(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

describe("V5 cross-language transaction fixtures", () => {
  it("accepts a sponsor paying from its default account lane like Rust", async () => {
    const sponsor = await createWalletFromSeed(new Uint8Array(32).fill(3));
    const grant = await signSponsorGrantV1(sponsor, {
      chain_id: "webc-devnet-1",
      grant_id: "77".repeat(32),
      payer_lane: DEFAULT_LANE,
      sender: SENDER,
      site_namespace: null,
      application_namespace: null,
      action_scope: { exact_action_digest: ACTION_DIGEST },
      validity: { valid_from_height: "10", valid_until_height: "20" },
      max_fee_per_transaction: "10000",
      max_cumulative_fee: "100000",
      max_uses: "10",
    });
    expect(grant.sponsor).toBe(SPONSOR);
    expect(grant.payer_lane).toBe(DEFAULT_LANE);
    expect(await verifySponsorGrantV1(grant)).toBe(true);
  });

  it("inserts the Rust-derived session budget key in consensus order", async () => {
    const access = await sessionAuthorizationAccessListV1(
      senderPaidFixture().access_list,
      SENDER,
      "11".repeat(32),
    );
    expect(access.read_write).toEqual([
      { version: 1, kind: { Account: { address: SENDER } } },
      { version: 1, kind: { Account: { address: RECIPIENT } } },
      {
        version: 1,
        kind: { FeeAccumulator: { lane: DEFAULT_LANE, payer: SENDER } },
      },
      {
        version: 1,
        kind: {
          SessionKey: {
            owner: SENDER,
            session_key:
              "0ccf7ce5d50b1e08cb4b7d2f7c5b7af9eb094dce0c9d1668a2e270de7fb40c74",
          },
        },
      },
    ]);
    await expect(
      sessionAuthorizationAccessListV1(access, SENDER, "11".repeat(32)),
    ).rejects.toThrow("already contains session-key state");
  });

  it("matches the Rust sponsor-grant revocation action digest", async () => {
    const kind: TransactionKindV1Json = {
      Actions: { actions: [revokeSponsorGrantActionV1("44".repeat(32))] },
    };
    expect(await transactionKindV1DigestHex(kind)).toBe(
      "9ee7f737d552bfc49ba6351b0c8954c70a83b989175a0892b106e95c36846de8",
    );
    expect(() => revokeSponsorGrantActionV1("00".repeat(32))).toThrow();
  });

  it("reproduces the Rust sender-paid transfer wire byte-for-byte", async () => {
    const transaction = senderPaidFixture();

    // Canonical signing bytes must be byte-identical to Rust; the default
    // (all-zero) authorization lane is a legitimate lane and must round-trip.
    expect(decode(transactionV5SigningBytes(transaction))).toBe(
      SENDER_PAID_SIGNING_JSON,
    );
    // Verifying the exact Rust Ed25519 signature over those bytes proves parity.
    expect(await verifySignedTransactionV5(transaction)).toBe(true);
    expect(await transactionKindV1DigestHex(transaction.kind)).toBe(ACTION_DIGEST);
    expect(await transactionV5IdHex(transaction)).toBe(SENDER_PAID_ID);
    expect(canonicalJson(transaction)).toBe(SENDER_PAID_FULL_JSON);
  });

  it("reproduces the Rust scoped-sponsor grant and use bindings byte-for-byte", async () => {
    const grant = sponsorGrantFixture();
    const transaction = sponsoredFixture();

    expect(decode(sponsorGrantSigningBytes(grant))).toBe(SPONSOR_GRANT_SIGNING_JSON);
    expect(await verifySponsorGrantV1(grant)).toBe(true);
    expect(await sponsorGrantV1DigestHex(grant)).toBe(GRANT_DIGEST);
    expect(await feeBidV1DigestHex(transaction.fee_bid)).toBe(FEE_BID_DIGEST);

    // The builder must reconstruct the exact frozen sponsor-use bindings.
    const rebuiltUse = await createSponsorUseV1(
      grant,
      "0",
      transaction.kind,
      transaction.fee_bid,
    );
    expect(rebuiltUse.grant_digest).toBe(GRANT_DIGEST);
    expect(rebuiltUse.action_digest).toBe(ACTION_DIGEST);
    expect(rebuiltUse.fee_bid_digest).toBe(FEE_BID_DIGEST);
    expect(await sponsorUseV1DigestHex(rebuiltUse)).toBe(SPONSOR_USE_DIGEST);

    expect(await verifySignedTransactionV5(transaction)).toBe(true);
    expect(await transactionV5IdHex(transaction)).toBe(SPONSORED_ID);
    expect(canonicalJson(transaction)).toBe(SPONSORED_FULL_JSON);
  });

  it("fails closed on tampered signatures, amounts, sponsor bindings, and chain", async () => {
    // A flipped sender signature must not verify.
    const flippedSig = senderPaidFixture();
    flippedSig.sender_signature = `aa${SENDER_PAID_SIGNATURE.slice(2)}`;
    expect(await verifySignedTransactionV5(flippedSig)).toBe(false);

    // Any change to a signed field (here the transfer amount) breaks the
    // signature over the canonical bytes.
    const tamperedAmount = senderPaidFixture();
    tamperedAmount.kind = {
      Actions: {
        actions: [
          { Native: { operation: { Transfer: { to: RECIPIENT, amount: "123457" } } } },
        ],
      },
    };
    expect(await verifySignedTransactionV5(tamperedAmount)).toBe(false);

    // A verifier configured for another chain must reject the transaction.
    expect(
      await verifySignedTransactionV5(senderPaidFixture(), "webc-other-1"),
    ).toBe(false);

    // Re-bidding the sponsored fee without rebinding the grant breaks the
    // sponsor binding, so verification must fail before the signature check.
    const rebidSponsored = sponsoredFixture();
    rebidSponsored.fee_bid = {
      gas_limit: "1000",
      max_fee_per_unit: "6",
      priority_fee_per_unit: "1",
    };
    expect(await verifySignedTransactionV5(rebidSponsored)).toBe(false);

    // Corrupting the sponsor signature must fail the grant verification.
    const badGrant = sponsorGrantFixture();
    badGrant.sponsor_signature = `aa${SPONSOR_GRANT_SIGNATURE.slice(2)}`;
    expect(await verifySponsorGrantV1(badGrant)).toBe(false);
  });
});
