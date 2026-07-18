/** Cross-language fixtures covering every version-1 logical state-key variant. */

import { describe, expect, it } from "vitest";
import { canonicalJsonHashHex } from "./canonical";
import type { AssetIdJson, StateKeyJson } from "./types";

describe("state-key wire schema", () => {
  it("matches the complete Rust version-1 key vector", async () => {
    const defaultLane = "00".repeat(32);
    const owner = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
    const validator = "webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem";
    const asset: AssetIdJson = {
      External: {
        origin_chain: "Ethereum",
        symbol: "USDC",
        contract_or_mint: "0x1234",
      },
    };
    const keys: StateKeyJson[] = [
      { version: 1, kind: { Account: { address: owner } } },
      { version: 1, kind: { AuthorizationPolicy: { owner } } },
      { version: 1, kind: { AssetBalance: { asset, owner } } },
      { version: 1, kind: { Validator: { operator: validator } } },
      {
        version: 1,
        kind: { Delegation: { delegator: owner, validator } },
      },
      {
        version: 1,
        kind: {
          AuthorizationLane: { owner, lane: "99".repeat(32) },
        },
      },
      {
        version: 1,
        kind: {
          SessionKey: { owner, session_key: "ab".repeat(32) },
        },
      },
      {
        version: 1,
        kind: { FeeAccumulator: { payer: owner, lane: defaultLane } },
      },
      {
        version: 1,
        kind: { BridgeMessage: { message_hash: "11".repeat(32) } },
      },
      { version: 1, kind: { BridgeEscrow: { domain: "Ethereum" } } },
      {
        version: 1,
        kind: { SlashingEvidence: { evidence_hash: "22".repeat(32) } },
      },
      { version: 1, kind: { UnbondingQueue: { validator } } },
      {
        version: 1,
        kind: { Object: { object_id: "33".repeat(32) } },
      },
      {
        version: 1,
        kind: { Module: { module_id: "44".repeat(32) } },
      },
      {
        version: 1,
        kind: {
          Application: {
            namespace: "55".repeat(32),
            key_hash: "66".repeat(32),
          },
        },
      },
      { version: 1, kind: { Protocol: { field: "BaseFee" } } },
      { version: 1, kind: { Protocol: { field: "BridgeNonce" } } },
      {
        version: 1,
        kind: { SponsorGrant: { sponsor: owner, grant_id: "77".repeat(32) } },
      },
    ];

    expect(await canonicalJsonHashHex(keys)).toBe(
      "ce844cddc2979f04aacc81550845f574da2bbc1eeef9aa0f6bf2710a64dc68f4",
    );
  });
});
