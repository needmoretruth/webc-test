/** Frozen Rust/browser vector for the protocol-2 finality authority set. */

import { describe, expect, it } from "vitest";
import {
  FINALITY_AUTHORITY_SET_V1_DOMAIN,
  finalityAuthoritySetV1CommitmentHex,
  type FinalityAuthoritySetV1Json,
} from "./finality-authority";

describe("finality authority set V1", () => {
  it("matches the Rust authority commitment fixture", async () => {
    const authoritySet: FinalityAuthoritySetV1Json = {
      version: 1,
      protocol_version: 2,
      chain_id: "webc-devnet-1",
      epoch: "3",
      authorities: [{
        validator_id: "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3",
        consensus_key: "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
        voting_power: "100",
      }],
      total_power: "100",
    };
    expect(FINALITY_AUTHORITY_SET_V1_DOMAIN).toBe("WEBC_FINALITY_AUTHORITY_SET_V1");
    expect(await finalityAuthoritySetV1CommitmentHex(authoritySet)).toBe(
      "4361528bc72a2ea4e098119168f5eec6c5087d2958d48c2bccd26d0de2651899",
    );
  });
});
