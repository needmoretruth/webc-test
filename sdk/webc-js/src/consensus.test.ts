/** Cross-language consensus vote signing fixture. */

import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import type { ConsensusVoteJson } from "./types";

describe("consensus vote schema", () => {
  it("matches the Rust domain-separated vote payload byte-for-byte", () => {
    const vote: ConsensusVoteJson = {
      protocol_version: 1,
      chain_id: "webc-devnet-1",
      height: 42,
      round: 3,
      vote_type: "Precommit",
      block_hash:
        "1ca3c063ae95ef8d4f6d50f694a5df3b47df5a4aec6dada057c85c5dfdff0090",
      validator: "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3",
    };

    expect(canonicalJson({ domain: "WEBC_CONSENSUS_VOTE_V1", vote })).toBe(
      '{"domain":"WEBC_CONSENSUS_VOTE_V1","vote":{"block_hash":"1ca3c063ae95ef8d4f6d50f694a5df3b47df5a4aec6dada057c85c5dfdff0090","chain_id":"webc-devnet-1","height":42,"protocol_version":1,"round":3,"validator":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3","vote_type":"Precommit"}}',
    );
  });
});
