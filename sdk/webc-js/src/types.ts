/**
 * Shared TypeScript types for the WEBC browser SDK.
 *
 * These types intentionally mirror the Rust `webc-chain` wire format. Every
 * field that crosses the network uses one of:
 *   - base58 `webc1...` strings for addresses;
 *   - lowercase hex strings for hashes/keys/signatures;
 *   - decimal strings for `Amount` values (u128 cannot be safely represented
 *     as a JavaScript number, so strings keep full precision);
 *   - plain numbers for small integers like nonces and gas limits.
 */

/** A WEBC account address in its display form, e.g. `webc1...`. */
export type WebcAddress = string;

/** Lowercase hex string for a 32-byte hash, public key, or variant tag. */
export type HexString = string;

/** Lowercase 32-byte hex identity of one independent wallet lane. */
export type AuthorizationLaneIdJson = HexString;

/** Candidate post-quantum recovery-root commitment stored by policy V1. */
export interface PostQuantumRootJson {
  /** NIST FIPS 204 parameter set; verification is not enabled yet. */
  scheme: "MlDsa65";
  /** Non-zero SHA-256 commitment to the exact encoded public key. */
  public_key_hash: HexString;
}

/** Fee bid submitted with every transaction. All integers; no floats. */
export interface FeeBid {
  gasLimit: number;
  maxFeePerUnit: number;
  priorityFeePerUnit: number;
}

/** Exact fee-bid object serialized on the Rust transaction wire. */
export interface FeeBidJson {
  gas_limit: number;
  max_fee_per_unit: number;
  priority_fee_per_unit: number;
}

/** Account state returned by the node. Amounts are decimal strings. */
export interface WebcAccountJson {
  balance: string;
  nonce: number;
  staked: string;
  delegated: string;
  unbonding: string;
}

/** Single Merkle proof step: a sibling hash plus which side it sits on. */
export interface MerkleProofStepJson {
  sibling: HexString;
  direction: "Left" | "Right";
}

/** Full Merkle proof: the leaf hash and the ordered list of sibling steps. */
export interface MerkleProofJson {
  leaf: HexString;
  steps: MerkleProofStepJson[];
}

/**
 * Browser-verifiable proof that an account is committed to by a block header.
 * The node returns this; the browser SDK verifies it without downloading full
 * chain state.
 */
export interface AccountStateProofJson {
  address: WebcAddress;
  account: WebcAccountJson;
  account_root: HexString;
  proof: MerkleProofJson;
}

/**
 * Block header returned by the node.
 *
 * Every hash field is a 32-byte hex string. Browser light wallets can
 * recompute the header hash over this exact JSON shape using canonical encoding
 * (see `canonical.ts`), matching the Rust `BlockHeader::hash` implementation.
 */
export interface BlockHeaderJson {
  /** Version of the immutable protocol configuration schema. */
  protocol_version: number;
  /** Replay-protection network identifier fixed by genesis. */
  chain_id: string;
  /** Monotonic block height, starting at one after genesis. */
  height: number;
  /** Validator-snapshot epoch authorizing the proposer. */
  epoch: number;
  /** Hash of the immediately preceding authoritative block. */
  previous_hash: HexString;
  /** Root of every consensus state subtree after execution. */
  state_root: HexString;
  /** Account-only root used by lightweight balance proofs. */
  account_root: HexString;
  /** Ordered Merkle root of signed transactions. */
  tx_root: HexString;
  /** Ordered Merkle root of deterministic receipts. */
  receipt_root: HexString;
  /** Validator operator address that proposed the block. */
  proposer: WebcAddress;
  /** Consensus-validated Unix timestamp in milliseconds. */
  timestamp_ms: number;
  /** Native base units charged per execution unit. */
  base_fee_per_unit: number;
}

/**
 * A fully signed transaction ready for submission to the node.
 *
 * `operation` matches the Rust `Operation` enum's canonical JSON exactly.
 * `signature` is a 64-byte Ed25519
 * signature over the canonical signing payload.
 */
export interface SignedTransactionJson {
  /** Protocol schema version interpreting this signed wire object. */
  protocol_version: number;
  /** Canonical lowercase network identifier preventing cross-chain replay. */
  chain_id: string;
  sender: WebcAddress;
  public_key: HexString;
  authorization_lane: AuthorizationLaneIdJson;
  /** Monotonic account-policy revision; zero is legacy migration only. */
  authorization_policy_revision: number;
  nonce: number;
  operation: OperationJson;
  access_list: StateAccessListJson;
  fee: FeeBidJson;
  signature: HexString;
}

/** Versioned logical state key matching Rust `StateKey` canonical JSON. */
export interface StateKeyJson {
  /** State-key schema version; currently protocol version 1. */
  version: number;
  /** Externally tagged logical key identity. */
  kind: StateKeyKindJson;
}

/** Exact read-only and writable keys signed by a transaction. */
export interface StateAccessListJson {
  /** Keys execution may inspect but must not change. */
  read_only: StateKeyJson[];
  /** Keys execution may inspect and change. */
  read_write: StateKeyJson[];
}

/** Logical state-key variants shared with the Rust protocol. */
export type StateKeyKindJson =
  | { Account: { address: WebcAddress } }
  | { AuthorizationPolicy: { owner: WebcAddress } }
  | { AssetBalance: { asset: AssetIdJson; owner: WebcAddress } }
  | { Validator: { operator: WebcAddress } }
  | {
      Delegation: { delegator: WebcAddress; validator: WebcAddress };
    }
  | {
      AuthorizationLane: {
        owner: WebcAddress;
        lane: AuthorizationLaneIdJson;
      };
    }
  | {
      FeeAccumulator: {
        payer: WebcAddress;
        lane: AuthorizationLaneIdJson;
      };
    }
  | {
      SessionKey: {
        owner: WebcAddress;
        session_key: HexString;
      };
    }
  | { BridgeMessage: { message_hash: HexString } }
  | { BridgeEscrow: { domain: ExternalChainJson } }
  | { SlashingEvidence: { evidence_hash: HexString } }
  | { UnbondingQueue: { validator: WebcAddress } }
  | { Object: { object_id: HexString } }
  | { Module: { module_id: HexString } }
  | { Application: { namespace: HexString; key_hash: HexString } }
  | { Protocol: { field: "BaseFee" | "BridgeNonce" } };

/**
 * Operation variant union. IMPORTANT: Rust's `serde` serializes enums in the
 * default "externally tagged" form, so the JSON for a transfer looks like
 * `{"Transfer":{"to":"...","amount":"..."}}` — the variant name is the outer
 * key and the payload is the inner object. We mirror that exact shape here so
 * the canonical JSON signing payload produced in the browser is byte-identical
 * to the one Rust computes.
 */
export type OperationJson =
  | {
      InstallAuthorizationPolicy: {
        post_quantum_root: PostQuantumRootJson;
      };
    }
  | { Transfer: { to: WebcAddress; amount: string } }
  | {
      OpenAuthorizationLane: {
        lane: AuthorizationLaneIdJson;
        fee_deposit: string;
      };
    }
  | {
      FundAuthorizationLane: {
        lane: AuthorizationLaneIdJson;
        fee_deposit: string;
      };
    }
  | {
      CreateObject: {
        object_id: HexString;
        namespace: HexString;
        data: HexString;
      };
    }
  | {
      MutateObject: {
        object_id: HexString;
        namespace: HexString;
        expected_version: number;
        data: HexString;
      };
    }
  | {
      TransferObject: {
        object_id: HexString;
        namespace: HexString;
        expected_version: number;
        new_owner: WebcAddress;
      };
    }
  | {
      RegisterValidator: {
        consensus_key: HexString;
        self_stake: string;
        commission_bps: number;
        bootstrap: boolean;
      };
    }
  | { Delegate: { validator: WebcAddress; amount: string } }
  | { Undelegate: { validator: WebcAddress; amount: string } }
  | { UnstakeValidator: { amount: string } }
  | { ClaimUnbonded: { validator: WebcAddress; request_id: number } }
  | "ClaimValidatorRewards"
  | { ClaimDelegatorRewards: { validator: WebcAddress } }
  | { SubmitSlashingEvidence: { evidence: SlashingEvidenceJson } }
  | {
      BridgeLock: {
        asset: AssetIdJson;
        destination_chain: ExternalChainJson;
        recipient: HexString;
        amount: string;
      };
    }
  | {
      BridgeBurn: {
        asset: AssetIdJson;
        destination_chain: ExternalChainJson;
        recipient: HexString;
        amount: string;
      };
    }
  | { BridgeMint: { message: BridgeMessageJson } }
  | { BridgeRelease: { message: BridgeMessageJson } };

/** External chain identifier; matches the Rust `ExternalChain` enum. */
export type ExternalChainJson = "Webc" | "Ethereum" | "Solana";

/**
 * Asset identifier; matches the Rust `AssetId` enum (externally tagged). Rust
 * names are preserved verbatim.
 */
export type AssetIdJson =
  | "NativeWebc"
  | { WrappedWebc: { origin_chain: ExternalChainJson } }
  | {
      External: {
        origin_chain: ExternalChainJson;
        symbol: string;
        contract_or_mint: string;
      };
    };

/** Exact domain-separated consensus vote payload signed by a validator key. */
export interface ConsensusVoteJson {
  protocol_version: number;
  chain_id: string;
  height: number;
  round: number;
  vote_type: "Prevote" | "Precommit";
  block_hash: HexString;
  validator: WebcAddress;
}

/** Signed consensus vote matching Rust `SignedVote` canonical JSON. */
export interface SignedVoteJson {
  payload: ConsensusVoteJson;
  signature: HexString;
}

/**
 * Objective slashing evidence accepted by the current Rust state machine.
 * Label-only invalid-block, bridge-fraud, downtime, or majority-attack claims
 * are intentionally absent until their signed verification paths exist.
 */
export type SlashingEvidenceJson = {
  DoubleVote: {
    first: SignedVoteJson;
    second: SignedVoteJson;
  };
};

/** Bridge message; matches the Rust `BridgeMessage` struct. */
export interface BridgeMessageJson {
  source_chain: ExternalChainJson;
  destination_chain: ExternalChainJson;
  nonce: number;
  asset: AssetIdJson;
  sender: HexString;
  recipient: HexString;
  amount: string;
  source_tx: HexString;
}
