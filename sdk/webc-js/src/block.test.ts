/** Cross-language fixtures for the authoritative PoH-free block header. */

import { describe, expect, it } from "vitest";
import {
  BLOCK_HEADER_DOMAIN,
  BLOCK_HEADER_V4_DOMAIN,
  blockHeaderHashHex,
  blockHeaderV4HashHex,
} from "./block";
import type { BlockHeaderJson, BlockHeaderV4Json } from "./types";

describe("block header wire schema", () => {
  it("matches the Rust V3 header hash fixture", async () => {
    const header: BlockHeaderJson = {
      protocol_version: 1,
      chain_id: "webc-devnet-1",
      height: 7,
      epoch: 2,
      previous_hash: "00".repeat(32),
      state_root: "11".repeat(32),
      account_root: "22".repeat(32),
      tx_root: "33".repeat(32),
      receipt_root: "44".repeat(32),
      evidence_root: "55".repeat(32),
      proposer: "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3",
      timestamp_ms: 1_700_000_000_000,
      base_fee_per_unit: 5,
    };

    expect(BLOCK_HEADER_DOMAIN).toBe("WEBC_BLOCK_HEADER_V3");
    expect("poh_hash" in header).toBe(false);
    expect(await blockHeaderHashHex(header)).toBe(
      "c5f26fe6564fcc1394e12cab50783f561ca586f0fb80a9c04b9fe5bdb3be7b74",
    );
  });

  it("matches the Rust protocol-2 V4 header hash fixture", async () => {
    const header: BlockHeaderV4Json = {
      protocol_version: 2,
      chain_id: "webc-devnet-1",
      height: "42",
      epoch: "3",
      previous_hash: "00".repeat(32),
      state_root: "11".repeat(32),
      account_root: "22".repeat(32),
      tx_root: "33".repeat(32),
      receipt_root: "44".repeat(32),
      evidence_root: "55".repeat(32),
      finality_authority_set_root: "66".repeat(32),
      next_finality_authority_set_root: "77".repeat(32),
      proposer: "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3",
      timestamp_ms: "1700000000000",
      base_fee_per_unit: "5",
    };

    expect(BLOCK_HEADER_V4_DOMAIN).toBe("WEBC_BLOCK_HEADER_V4");
    expect(await blockHeaderV4HashHex(header)).toBe(
      "9855e491949296206f38c03e12a5f4aa82ca332170d1e42bb9dc1dfab5bb9949",
    );
  });
});
