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

/**
 * Opaque, non-secret session-key identity: the lowercase-hex SHA-256 of
 * `"WEBC_SESSION_KEY_ID_V1" || session_public_key`. Derive it with
 * `deriveSessionKeyIdHex` in `transaction.ts`.
 */
export type SessionKeyIdJson = HexString;

/** Operation kinds a session key may authorize. v1 exposes transfers only. */
export interface SessionAllowedOperationsJson {
  /** Whether native `Transfer` is permitted (the only v1 capability). */
  transfer: boolean;
}

/**
 * Immutable constraint grant fixed when a session key is installed. Amounts are
 * exact native base units encoded as decimal strings, matching Rust `Amount`.
 */
export interface SessionKeyConstraintsJson {
  /** Lane the key is bound to (or the all-zero default lane). */
  authorization_lane: AuthorizationLaneIdJson;
  /** Operation kinds the key may authorize. */
  allowed_operations: SessionAllowedOperationsJson;
  /** Maximum native principal per session-signed transaction, base units. */
  max_amount_per_use: string;
  /** Maximum cumulative native principal over the key's life, base units. */
  total_amount_budget: string;
  /** Maximum fee authorized on one transaction, base units. */
  max_fee_per_use: string;
  /** Maximum cumulative fee over the key's life, base units. */
  total_fee_budget: string;
  /** Requested lifetime in consensus epochs from the install epoch. */
  lifetime_epochs: number;
}

/**
 * Post-quantum root signature authorizing one exact critical action (session-key
 * install/revoke, active-key rotation, or root rotation). The public key is
 * checked against the account's stored commitment and the signature is verified
 * over the exact action, so knowing the public root alone is not enough.
 */
export interface PostQuantumRootRevealJson {
  /** NIST FIPS 204 parameter set the key and signature are interpreted under. */
  scheme: "MlDsa65";
  /** Exact encoded ML-DSA public key bytes, lowercase hex. */
  public_key: HexString;
  /** ML-DSA signature over the authorization message, lowercase hex. */
  signature: HexString;
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
  /** Ordered Merkle root of objective slashing-evidence identifiers. */
  evidence_root: HexString;
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
  /**
   * Optional sponsoring application namespace (fee sponsorship, §15.35): a
   * 32-byte hash as a lowercase 64-char hex string. When present, the sender
   * opts into having that app's pre-funded sponsor budget pay this transaction's
   * fee (best-effort, fail-open). It is signed and, matching Rust's manual
   * `Transaction` serializer, **omitted entirely from the canonical JSON when
   * absent**, so every non-sponsored transaction is byte-identical to before.
   */
  sponsor?: HexString;
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
  // --- Native tokens (Phase 13a, §15) -------------------------------------
  | { Token: { token_id: HexString } }
  | { TokenBalance: { token_id: HexString; owner: WebcAddress } }
  | { TokenFreeze: { token_id: HexString; account: WebcAddress } }
  // --- Native NFTs (Phase 13b, §15) ---------------------------------------
  | { NftCollection: { collection_id: HexString } }
  | { NftItem: { collection_id: HexString; serial: number } }
  // --- Native governance (Phase 13c, §15) ---------------------------------
  | { GovernanceInstance: { instance_id: HexString } }
  | { GovernanceProposal: { proposal_id: HexString } }
  | { GovernanceVote: { proposal_id: HexString; voter: WebcAddress } }
  // --- Agent mandates (Phase 9a, §15.32) ----------------------------------
  | { Mandate: { mandate_id: HexString } }
  // --- Service registry (Phase 9b, §15.5) ---------------------------------
  | { Service: { service_id: HexString } }
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
  | { BridgeRelease: { message: BridgeMessageJson } }
  | {
      InstallSessionKey: {
        session_public_key: HexString;
        constraints: SessionKeyConstraintsJson;
        post_quantum_root_reveal: PostQuantumRootRevealJson;
      };
    }
  | {
      RevokeSessionKey: {
        session_key: SessionKeyIdJson;
        post_quantum_root_reveal: PostQuantumRootRevealJson;
      };
    }
  | {
      RotateActiveTransactionKey: {
        new_active_transaction_key: HexString;
        post_quantum_root_reveal: PostQuantumRootRevealJson;
      };
    }
  | {
      RotatePostQuantumRoot: {
        new_post_quantum_root: PostQuantumRootJson;
        post_quantum_root_reveal: PostQuantumRootRevealJson;
      };
    }
  // --- Native tokens (Phase 13a, §15) -------------------------------------
  | {
      CreateToken: {
        namespace: HexString;
        create_nonce: number;
        metadata: TokenMetadataJson;
        mint_authority: WebcAddress | null;
        freeze_authority: WebcAddress | null;
        initial_supply: string;
        initial_recipient: WebcAddress;
      };
    }
  | { MintToken: { token_id: HexString; recipient: WebcAddress; amount: string } }
  | { BurnToken: { token_id: HexString; amount: string } }
  | {
      TransferToken: {
        token_id: HexString;
        recipient: WebcAddress;
        amount: string;
      };
    }
  | { SetTokenPaused: { token_id: HexString; paused: boolean } }
  | { FreezeTokenAccount: { token_id: HexString; account: WebcAddress } }
  | { ThawTokenAccount: { token_id: HexString; account: WebcAddress } }
  | {
      SetTokenAuthority: {
        token_id: HexString;
        authority_kind: TokenAuthorityKindJson;
        new_authority: WebcAddress | null;
      };
    }
  // --- Native NFTs (Phase 13b, §15) ---------------------------------------
  | {
      CreateNftCollection: {
        namespace: HexString;
        create_nonce: number;
        metadata: NftMetadataJson;
        mint_authority: WebcAddress | null;
        freeze_authority: WebcAddress | null;
        max_supply: number | null;
        royalty_bps: number;
      };
    }
  | {
      MintNft: {
        collection_id: HexString;
        recipient: WebcAddress;
        item_metadata_hash: HexString;
      };
    }
  | {
      TransferNft: {
        collection_id: HexString;
        serial: number;
        recipient: WebcAddress;
      };
    }
  | { BurnNft: { collection_id: HexString; serial: number } }
  | { SetNftCollectionPaused: { collection_id: HexString; paused: boolean } }
  | { FreezeNftItem: { collection_id: HexString; serial: number } }
  | { ThawNftItem: { collection_id: HexString; serial: number } }
  | {
      SetNftAuthority: {
        collection_id: HexString;
        authority_kind: NftAuthorityKindJson;
        new_authority: WebcAddress | null;
      };
    }
  // --- Native governance (Phase 13c, §15) ---------------------------------
  | {
      CreateGovernanceInstance: {
        namespace: HexString;
        create_nonce: number;
        weight_token: HexString;
        config: GovernanceConfigJson;
      };
    }
  | { FundGovernanceTreasury: { instance_id: HexString; amount: string } }
  | { OpenProposal: { instance_id: HexString; action: GovernanceActionJson } }
  | {
      CastVote: {
        proposal_id: HexString;
        choice: VoteChoiceJson;
        weight_amount: string;
      };
    }
  | { ResolveProposal: { proposal_id: HexString } }
  | { ExecuteProposal: { proposal_id: HexString } }
  | { ReclaimVote: { proposal_id: HexString } }
  // --- Agent mandates (Phase 9a, §15.32) ----------------------------------
  | {
      GrantMandate: {
        agent_key: HexString;
        grant_nonce: number;
        budget_total: string;
        expiry_epoch: number;
        per_tx_max: string;
        rate_limit_per_day: number;
        counterparty_policy: MandateCounterpartyPolicyJson;
      };
    }
  | { TopUpMandate: { mandate_id: HexString; amount: string } }
  | {
      SpendUnderMandate: {
        mandate_id: HexString;
        recipient: WebcAddress;
        amount: string;
      };
    }
  | { RevokeMandate: { mandate_id: HexString } }
  // --- Service registry (Phase 9b, §15.5) ---------------------------------
  | {
      RegisterService: {
        namespace: HexString;
        create_nonce: number;
        categories: HexString[];
        title: HexString;
        endpoint: HexString;
        interface: HexString;
        pricing: ServicePriceJson[];
        payment_flags: ServicePaymentFlagsJson;
      };
    }
  | {
      UpdateService: {
        service_id: HexString;
        categories: HexString[];
        title: HexString;
        endpoint: HexString;
        interface: HexString;
        pricing: ServicePriceJson[];
        payment_flags: ServicePaymentFlagsJson;
      };
    }
  | { SetServiceStatus: { service_id: HexString; status: ServiceStatusJson } }
  | {
      SpendUnderMandateToService: {
        mandate_id: HexString;
        service_id: HexString;
        amount: string;
      };
    };

/** Lifecycle status of a registered service, mirroring Rust `ServiceStatus`. */
export type ServiceStatusJson = "Active" | "Paused";

/** One priced operation a service exposes, mirroring Rust `ServicePrice`. */
export interface ServicePriceJson {
  /** 32-byte lowercase-hex operation discriminant. */
  operation: HexString;
  /** Price in native base units (decimal string). */
  price: string;
  /** Unit label, LOWERCASE HEX of its bytes (≤ 32 bytes). */
  unit: HexString;
}

/** Accepted payment flows, mirroring Rust `ServicePaymentFlags`. */
export interface ServicePaymentFlagsJson {
  on_chain_direct: boolean;
  http_402: boolean;
  subscription: boolean;
}

/**
 * One allowlist entry, mirroring Rust `MandateCounterparty` (externally tagged):
 * an opaque registry category tag (32-byte hex) or a specific recipient address.
 */
export type MandateCounterpartyJson =
  | { Category: HexString }
  | { Recipient: WebcAddress };

/**
 * Which counterparties a mandate may pay, mirroring Rust
 * `MandateCounterpartyPolicy`. `"Open"` permits any recipient; `Allowlist`
 * permits only the listed entries. NOTE: Rust stores the allowlist in a
 * `BTreeSet`, so entries serialize in canonical (Category before Recipient, then
 * byte order) order — `grantMandate` sorts and deduplicates them for you.
 */
export type MandateCounterpartyPolicyJson =
  | "Open"
  | { Allowlist: MandateCounterpartyJson[] };

/** Which of a token's two authorities `SetTokenAuthority` targets. */
export type TokenAuthorityKindJson = "Mint" | "Freeze";

/** Immutable per-instance governance rule set, mirroring Rust `GovernanceConfig`. */
export interface GovernanceConfigJson {
  /** Voting window length in epochs (must be > 0). */
  voting_period_epochs: number;
  /** Delay in epochs after voting ends before a passed proposal may execute. */
  timelock_epochs: number;
  /** Participation quorum in basis points (≤ 10000). */
  quorum_bps: number;
  /** Minimum weight-token balance to open a proposal (decimal string). */
  proposal_threshold: string;
  /** Yes-ratio approval threshold in basis points (≤ 10000). */
  approval_threshold_bps: number;
}

/**
 * The single bounded typed effect a proposal carries, mirroring Rust
 * `GovernanceAction` (externally tagged). `"Signaling"` has no on-chain effect.
 */
export type GovernanceActionJson =
  | "Signaling"
  | { TreasuryTransfer: { recipient: WebcAddress; amount: string } };

/** One voter's choice, mirroring Rust `VoteChoice`. */
export type VoteChoiceJson = "Yes" | "No" | "Abstain";

/** Which of a collection's two authorities `SetNftAuthority` targets. */
export type NftAuthorityKindJson = "Mint" | "Freeze";

/**
 * Bounded NFT collection metadata mirroring Rust `NftMetadata`. `name`/`symbol`
 * are LOWERCASE HEX of their UTF-8 bytes; `metadata_hash` is a 32-byte hex
 * commitment. (Unlike tokens, there is no `decimals` field.)
 */
export interface NftMetadataJson {
  /** Lowercase hex of the UTF-8 name bytes (non-empty, ≤ 32 bytes). */
  name: HexString;
  /** Lowercase hex of the UTF-8 symbol bytes (non-empty, ≤ 12 bytes). */
  symbol: HexString;
  /** 32-byte lowercase-hex commitment to off-chain metadata. */
  metadata_hash: HexString;
}

/**
 * Bounded token metadata mirroring Rust `TokenMetadata`. `name` and `symbol` are
 * the LOWERCASE HEX of their UTF-8 bytes on the wire (Rust `bounded_*_hex`), not
 * plain text; `metadata_hash` is a 32-byte lowercase-hex content commitment.
 */
export interface TokenMetadataJson {
  /** Lowercase hex of the UTF-8 name bytes (non-empty, ≤ 32 bytes). */
  name: HexString;
  /** Lowercase hex of the UTF-8 symbol bytes (non-empty, ≤ 12 bytes). */
  symbol: HexString;
  /** Fractional decimal places (≤ 18). */
  decimals: number;
  /** 32-byte lowercase-hex commitment to off-chain metadata. */
  metadata_hash: HexString;
}

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
