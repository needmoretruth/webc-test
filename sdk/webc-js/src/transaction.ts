/**
 * Transaction construction and signing.
 *
 * The signing payload produced here must be byte-identical to Rust's
 * `Transaction::signing_bytes` (see `crates/webc-chain/src/transaction.rs`).
 * That requires three pieces of discipline:
 *
 *   1. Every amount field uses decimal STRING encoding (because
 *      JavaScript numbers cannot represent WEBC's u128 base units).
 *   2. Addresses use canonical `webc1...` base58 text; hashes, public keys,
 *      and signatures use lowercase hex.
 *   3. The payload is serialized with canonical JSON (sorted keys, no
 *      whitespace) — see `canonical.ts`.
 *   4. Protocol version and chain ID are signed to prevent schema ambiguity
 *      and replay on another WEBC network.
 *
 * The wallet signs the canonical JSON bytes directly. Ed25519 performs its own
 * internal hashing, so adding a separate pre-hash would define a different
 * signature scheme. Verification recomputes those exact bytes.
 */

import type {
  AssetIdJson,
  AuthorizationLaneIdJson,
  BridgeMessageJson,
  ExternalChainJson,
  FeeBid,
  FeeBidJson,
  HexString,
  OperationJson,
  PostQuantumRootJson,
  PostQuantumRootRevealJson,
  SessionKeyConstraintsJson,
  SessionKeyIdJson,
  GovernanceActionJson,
  GovernanceConfigJson,
  MandateCounterpartyJson,
  MandateCounterpartyPolicyJson,
  NftAuthorityKindJson,
  NftMetadataJson,
  ServicePaymentFlagsJson,
  ServicePriceJson,
  ServiceStatusJson,
  SlashingEvidenceJson,
  SignedTransactionJson,
  StateAccessListJson,
  StateKeyJson,
  TokenAuthorityKindJson,
  TokenMetadataJson,
  VoteChoiceJson,
  WebcAddress,
} from "./types.js";
import type { WebcWallet } from "./wallet.js";
import { signWithWallet } from "./wallet.js";
import { addressFromBytes, addressToBytes } from "./address.js";
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  toArrayBuffer,
  u64ToBytes,
} from "./hex.js";
import { canonicalJsonBytes } from "./canonical.js";
import { bridgeMessageHashHex } from "./protocol-hash.js";

/** Domain for session-key id derivation — must match Rust `SESSION_KEY_ID_DOMAIN`. */
const SESSION_KEY_ID_DOMAIN = new TextEncoder().encode("WEBC_SESSION_KEY_ID_V1");

/**
 * Fixed application-key discriminant that addresses an app's sponsor record —
 * must match Rust `sponsorship::SPONSOR_STATE_KEY_DISCRIMINANT`. The sponsor
 * state key is `Application { namespace, key_hash: SHA-256(discriminant) }`.
 */
const SPONSOR_STATE_KEY_DISCRIMINANT = new TextEncoder().encode(
  "WEBC_SPONSOR_STATE_KEY_V1",
);

/** Stable signing domain — must match Rust `crate::SIGNING_DOMAIN`. */
export const TRANSACTION_SIGNING_DOMAIN = "WEBC_SIGNED_TRANSACTION_V4";

/** Protocol schema understood by this SDK build. */
export const CURRENT_TRANSACTION_PROTOCOL_VERSION = 1;

/** All-zero lane backed directly by the account balance and legacy nonce. */
export const DEFAULT_AUTHORIZATION_LANE = "00".repeat(32);

/**
 * Builds and signs a transaction in one call. The caller constructs the
 * `OperationJson` using one of the helpers below (`transfer`, `delegate`,
 * etc.), ensuring variant names match the Rust `Operation` enum exactly.
 *
 * `Amount` fields must be decimal strings (e.g. `"123456"`). Use
 * `amountFromWhole` or `amountFromUnits` to convert numbers into strings.
 */
export async function signTransaction(
  wallet: WebcWallet,
  chainId: string,
  nonce: number,
  operation: OperationJson,
  fee: FeeBid,
  accessList?: StateAccessListJson,
  authorizationLane: AuthorizationLaneIdJson = DEFAULT_AUTHORIZATION_LANE,
  protocolVersion: number = CURRENT_TRANSACTION_PROTOCOL_VERSION,
  authorizationPolicyRevision = 0,
  sponsor?: HexString,
): Promise<SignedTransactionJson> {
  validateTransactionContext(protocolVersion, chainId);
  validateAuthorizationPolicyRevision(authorizationPolicyRevision);
  if (sponsor !== undefined) {
    validateSponsor(sponsor);
  }
  // When opting into sponsorship without an explicit access list, mirror Rust
  // `Transaction::for_sponsored_operation`: build the operation's default list
  // and append the app's sponsor state key so execution covers both the
  // sponsored and the self-pay (fail-open) paths.
  const resolvedAccessList =
    accessList ??
    (sponsor !== undefined
      ? await sponsoredAccessListAsync(
          wallet.address,
          operation,
          sponsor,
          authorizationLane,
        )
      : await defaultAccessListAsync(wallet.address, operation, authorizationLane));
  const publicKey = bytesToHex(wallet.publicKey);
  const wireFee = feeWireJson(fee);
  const payload = transactionSigningPayload(
    protocolVersion,
    chainId,
    wallet.address,
    publicKey,
    nonce,
    operation,
    resolvedAccessList,
    fee,
    authorizationLane,
    authorizationPolicyRevision,
    sponsor,
  );
  const signingBytes = canonicalJsonBytes(payload);
  const signature = await signWithWallet(wallet, signingBytes);
  return {
    protocol_version: protocolVersion,
    chain_id: chainId,
    sender: wallet.address,
    public_key: publicKey,
    authorization_lane: authorizationLane,
    authorization_policy_revision: authorizationPolicyRevision,
    nonce,
    operation,
    access_list: resolvedAccessList,
    fee: wireFee,
    signature: bytesToHex(signature),
    // `sponsor` is additive and omitted entirely when absent, so a non-sponsored
    // transaction's wire form and hash are byte-identical to the pre-sponsorship
    // encoding (matching Rust's manual `Serialize` impl for `Transaction`).
    ...(sponsor !== undefined ? { sponsor } : {}),
  };
}

/**
 * Verifies a previously signed transaction by recomputing the signing payload
 * and checking the Ed25519 signature. This is the browser-side trust check
 * before displaying a transaction to a user or relaying it further.
 */
export async function verifySignedTransaction(
  tx: SignedTransactionJson,
): Promise<boolean> {
  validateTransactionContext(tx.protocol_version, tx.chain_id);
  validateAuthorizationPolicyRevision(tx.authorization_policy_revision);
  if (tx.sponsor !== undefined) {
    validateSponsor(tx.sponsor);
  }
  // Import lazily via dynamic require-style access to keep this module
  // dependency-light. `verifyEd25519` is in `wallet.ts`.
  const { verifyEd25519 } = await import("./wallet.js");
  const pubkeyBytes = hexToBytes(tx.public_key);
  const payload = transactionSigningPayloadWire(
    tx.protocol_version,
    tx.chain_id,
    tx.sender,
    tx.public_key,
    tx.authorization_lane,
    tx.authorization_policy_revision,
    tx.nonce,
    tx.operation,
    tx.access_list,
    tx.fee,
    tx.sponsor,
  );
  const signingBytes = canonicalJsonBytes(payload);
  return verifyEd25519(pubkeyBytes, signingBytes, hexToBytes(tx.signature));
}

/** Computes the transaction hash (sha256 of canonical JSON of the full tx). */
export async function transactionHashHex(
  tx: SignedTransactionJson,
): Promise<string> {
  const { canonicalJsonHashHex } = await import("./canonical.js");
  return canonicalJsonHashHex(tx);
}

// ---------------------------------------------------------------------------
// Operation constructors. Centralizing them keeps variant names stable and
// reduces the chance a caller mistypes a field name.
// ---------------------------------------------------------------------------

/** Installs policy V1 with a committed ML-DSA recovery public key. */
export function installAuthorizationPolicy(
  postQuantumRoot: PostQuantumRootJson,
): OperationJson {
  if (
    postQuantumRoot.scheme !== "MlDsa65" ||
    postQuantumRoot.public_key_hash === "00".repeat(32) ||
    postQuantumRoot.public_key_hash.length !== 64 ||
    postQuantumRoot.public_key_hash !== postQuantumRoot.public_key_hash.toLowerCase()
  ) {
    throw new Error("invalid post-quantum root commitment");
  }
  hexToBytes(postQuantumRoot.public_key_hash);
  return {
    InstallAuthorizationPolicy: {
      post_quantum_root: {
        scheme: postQuantumRoot.scheme,
        public_key_hash: postQuantumRoot.public_key_hash,
      },
    },
  };
}

export function transfer(to: WebcAddress, amount: string): OperationJson {
  requireCanonicalAmount(amount, "transfer amount");
  return { Transfer: { to, amount } };
}

/** Opens a non-default lane and prepays its fee balance from the account. */
export function openAuthorizationLane(
  lane: AuthorizationLaneIdJson,
  feeDeposit: string,
): OperationJson {
  requireCanonicalAmount(feeDeposit, "lane fee deposit");
  return { OpenAuthorizationLane: { lane, fee_deposit: feeDeposit } };
}

/** Adds prepaid native fee units to an existing non-default lane. */
export function fundAuthorizationLane(
  lane: AuthorizationLaneIdJson,
  feeDeposit: string,
): OperationJson {
  requireCanonicalAmount(feeDeposit, "lane fee deposit");
  return { FundAuthorizationLane: { lane, fee_deposit: feeDeposit } };
}

/** Creates revision one of an address-owned bounded application object. */
export function createObject(args: {
  objectId: string;
  namespace: string;
  data: string;
}): OperationJson {
  requireLowercaseHex(args.objectId, "object id");
  requireLowercaseHex(args.namespace, "object namespace");
  requireLowercaseHex(args.data, "object data");
  return {
    CreateObject: {
      object_id: args.objectId,
      namespace: args.namespace,
      data: args.data,
    },
  };
}

/** Replaces object bytes when ownership, namespace, and version all match. */
export function mutateObject(args: {
  objectId: string;
  namespace: string;
  expectedVersion: number;
  data: string;
}): OperationJson {
  requireLowercaseHex(args.objectId, "object id");
  requireLowercaseHex(args.namespace, "object namespace");
  requireLowercaseHex(args.data, "object data");
  return {
    MutateObject: {
      object_id: args.objectId,
      namespace: args.namespace,
      expected_version: args.expectedVersion,
      data: args.data,
    },
  };
}

/** Transfers object ownership and advances its optimistic version. */
export function transferObject(args: {
  objectId: string;
  namespace: string;
  expectedVersion: number;
  newOwner: WebcAddress;
}): OperationJson {
  requireLowercaseHex(args.objectId, "object id");
  requireLowercaseHex(args.namespace, "object namespace");
  return {
    TransferObject: {
      object_id: args.objectId,
      namespace: args.namespace,
      expected_version: args.expectedVersion,
      new_owner: args.newOwner,
    },
  };
}

export function registerValidator(args: {
  consensusKey: string;
  selfStake: string;
  commissionBps: number;
  bootstrap: boolean;
}): OperationJson {
  requireCanonicalAmount(args.selfStake, "validator self stake");
  return {
    RegisterValidator: {
      consensus_key: args.consensusKey,
      self_stake: args.selfStake,
      commission_bps: args.commissionBps,
      bootstrap: args.bootstrap,
    },
  };
}

export function delegate(
  validator: WebcAddress,
  amount: string,
): OperationJson {
  requireCanonicalAmount(amount, "delegate amount");
  return { Delegate: { validator, amount } };
}

export function undelegate(
  validator: WebcAddress,
  amount: string,
): OperationJson {
  requireCanonicalAmount(amount, "undelegate amount");
  return { Undelegate: { validator, amount } };
}

/** Requests delayed exit of validator operator self-stake. */
export function unstakeValidator(amount: string): OperationJson {
  requireCanonicalAmount(amount, "unstake amount");
  return { UnstakeValidator: { amount } };
}

/** Claims matured principal from one validator-scoped unbonding request. */
export function claimUnbonded(
  validator: WebcAddress,
  requestId: number,
): OperationJson {
  return { ClaimUnbonded: { validator, request_id: requestId } };
}

export function claimValidatorRewards(): OperationJson {
  return "ClaimValidatorRewards";
}

export function claimDelegatorRewards(
  validator: WebcAddress,
): OperationJson {
  return { ClaimDelegatorRewards: { validator } };
}

/** Wraps already verified objective evidence in the exact Rust operation shape. */
export function submitSlashingEvidence(
  evidence: SlashingEvidenceJson,
): OperationJson {
  return { SubmitSlashingEvidence: { evidence } };
}

/** Creates an outgoing bridge-lock operation using exact snake_case wire fields. */
export function bridgeLock(args: {
  asset: AssetIdJson;
  destinationChain: ExternalChainJson;
  recipient: string;
  amount: string;
}): OperationJson {
  requireLowercaseHex(args.recipient, "bridge recipient");
  requireCanonicalAmount(args.amount, "bridge lock amount");
  return {
    BridgeLock: {
      asset: args.asset,
      destination_chain: args.destinationChain,
      recipient: args.recipient,
      amount: args.amount,
    },
  };
}

/** Creates an outgoing representation-burn operation. */
export function bridgeBurn(args: {
  asset: AssetIdJson;
  destinationChain: ExternalChainJson;
  recipient: string;
  amount: string;
}): OperationJson {
  requireLowercaseHex(args.recipient, "bridge recipient");
  requireCanonicalAmount(args.amount, "bridge burn amount");
  return {
    BridgeBurn: {
      asset: args.asset,
      destination_chain: args.destinationChain,
      recipient: args.recipient,
      amount: args.amount,
    },
  };
}

/** Wraps an incoming mint message; proof authorization remains node-enforced. */
export function bridgeMint(message: BridgeMessageJson): OperationJson {
  return { BridgeMint: { message } };
}

/** Wraps an incoming native release message; proof authorization remains node-enforced. */
export function bridgeRelease(message: BridgeMessageJson): OperationJson {
  return { BridgeRelease: { message } };
}

/** Rejects hex that is not lowercase or not an even number of nibbles. */
function requireLowercaseHex(value: string, label: string): void {
  if (value.length % 2 !== 0 || value !== value.toLowerCase()) {
    throw new Error(`invalid lowercase hex for ${label}`);
  }
  hexToBytes(value); // throws on any non-hex character
}

/**
 * Rejects a value that is not a 32-byte lowercase-hex string. Every id newtype
 * (`TokenId`, `NftCollectionId`, `FeedId`, `MandateId`, …) and every `Hash256`
 * field (namespaces, interface/metadata commitments) serializes to Rust's
 * `hex::encode` form: exactly 64 lowercase hex characters.
 */
function requireHash256Hex(value: string, label: string): void {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    throw new Error(`invalid 32-byte lowercase hex for ${label}`);
  }
}

/**
 * Rejects a bounded lowercase-hex byte string Rust's `bounded_hex` codec would
 * refuse: non-lowercase-hex, empty when `nonEmpty`, or longer than `maxBytes`.
 */
function requireBoundedHex(
  value: string,
  label: string,
  maxBytes: number,
  nonEmpty: boolean,
): void {
  requireLowercaseHex(value, label);
  const byteLength = value.length / 2;
  if (nonEmpty && byteLength === 0) {
    throw new Error(`${label} must not be empty`);
  }
  if (byteLength > maxBytes) {
    throw new Error(`${label} exceeds ${maxBytes} bytes`);
  }
}

/** Rejects a small unsigned integer outside `[0, max]` (bps, decimals, u16/u8). */
function requireBoundedU(value: number, label: string, max: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > max) {
    throw new Error(`invalid ${label} (expected integer in [0, ${max}])`);
  }
}

/** Rejects a non-negative integer that is not a safe u64-range JS integer. */
function requireCountU64(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`invalid ${label} (expected non-negative safe integer)`);
  }
}

/**
 * Validates bounded token metadata, mirroring Rust `TokenMetadata::validate`
 * plus the `bounded_*_hex` wire codec: name ≤ 32 bytes (non-empty), symbol ≤ 12
 * bytes (non-empty), decimals ≤ 18, 32-byte hex commitment.
 */
function requireTokenMetadata(metadata: TokenMetadataJson): void {
  requireBoundedHex(metadata.name, "token name", 32, true);
  requireBoundedHex(metadata.symbol, "token symbol", 12, true);
  requireBoundedU(metadata.decimals, "token decimals", 18);
  requireHash256Hex(metadata.metadata_hash, "token metadata hash");
}

/**
 * Validates bounded NFT metadata, mirroring Rust `NftMetadata::validate` plus its
 * `bounded_*_hex` codec: name ≤ 32 bytes (non-empty), symbol ≤ 12 bytes
 * (non-empty), 32-byte hex commitment. There is no `decimals` field.
 */
function requireNftMetadata(metadata: NftMetadataJson): void {
  requireBoundedHex(metadata.name, "nft name", 32, true);
  requireBoundedHex(metadata.symbol, "nft symbol", 12, true);
  requireHash256Hex(metadata.metadata_hash, "nft metadata hash");
}

/**
 * Validates a governance config, mirroring Rust `GovernanceConfig::validate`:
 * `voting_period_epochs` > 0, both bps ≤ 10000, `proposal_threshold` a canonical
 * amount, epoch counts non-negative u64.
 */
function requireGovernanceConfig(config: GovernanceConfigJson): void {
  requireCountU64(config.voting_period_epochs, "voting period epochs");
  if (config.voting_period_epochs === 0) {
    throw new Error("voting period epochs must be > 0");
  }
  requireCountU64(config.timelock_epochs, "timelock epochs");
  requireBoundedU(config.quorum_bps, "quorum bps", 10_000);
  requireCanonicalAmount(config.proposal_threshold, "proposal threshold");
  requireBoundedU(config.approval_threshold_bps, "approval threshold bps", 10_000);
}

/**
 * Canonicalizes a mandate counterparty policy: validates each entry, then sorts
 * and deduplicates the allowlist to match Rust's `BTreeSet<MandateCounterparty>`
 * iteration order (Category before Recipient, each by its 32 raw bytes). Rust
 * additionally rejects an EMPTY allowlist (`Mandate::validate`), so this does too.
 */
function canonicalCounterpartyPolicy(
  policy: MandateCounterpartyPolicyJson,
): MandateCounterpartyPolicyJson {
  if (policy === "Open") {
    return "Open";
  }
  if (
    typeof policy !== "object" ||
    policy === null ||
    !("Allowlist" in policy) ||
    !Array.isArray(policy.Allowlist)
  ) {
    throw new Error("invalid mandate counterparty policy");
  }
  if (policy.Allowlist.length === 0) {
    throw new Error("mandate allowlist must not be empty");
  }
  const sortable = policy.Allowlist.map((entry) => {
    if ("Category" in entry) {
      requireHash256Hex(entry.Category, "mandate category tag");
      return { entry, variant: 0, bytes: hexToBytes(entry.Category) };
    }
    if ("Recipient" in entry) {
      return { entry, variant: 1, bytes: addressToBytes(entry.Recipient) };
    }
    throw new Error("invalid mandate counterparty entry");
  });
  sortable.sort((a, b) => a.variant - b.variant || compareBytes(a.bytes, b.bytes));
  const sorted: MandateCounterpartyJson[] = [];
  for (const item of sortable) {
    // Deduplicate structurally, matching set semantics.
    if (!sorted.some((existing) => sameCounterparty(existing, item.entry))) {
      sorted.push(item.entry);
    }
  }
  return { Allowlist: sorted };
}

/** Lexicographic comparison of two equal-length byte arrays. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    if (a[i] !== b[i]) {
      return a[i] - b[i];
    }
  }
  return a.length - b.length;
}

/** Structural equality of two counterparty entries. */
function sameCounterparty(
  a: MandateCounterpartyJson,
  b: MandateCounterpartyJson,
): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** Validates a governance action, mirroring Rust `GovernanceAction`. */
function requireGovernanceAction(action: GovernanceActionJson): void {
  if (action === "Signaling") {
    return;
  }
  if (
    typeof action !== "object" ||
    action === null ||
    !("TreasuryTransfer" in action)
  ) {
    throw new Error("invalid governance action");
  }
  requireCanonicalAmount(
    action.TreasuryTransfer.amount,
    "treasury transfer amount",
  );
}

/**
 * Canonicalizes a service category set: validates each 32-byte hex tag, then
 * sorts and deduplicates to match Rust's `BTreeSet<Hash256>` order (fixed-length
 * lowercase hex sorts identically to the raw bytes). Rejects more than
 * `MAX_SERVICE_CATEGORIES` entries.
 */
function canonicalServiceCategories(categories: HexString[]): HexString[] {
  if (!Array.isArray(categories)) {
    throw new Error("service categories must be an array");
  }
  for (const category of categories) {
    requireHash256Hex(category, "service category");
  }
  const sorted = [...new Set(categories)].sort();
  if (sorted.length > 8) {
    throw new Error("service categories exceed the maximum of 8");
  }
  return sorted;
}

/** Validates one `ServicePrice`, mirroring the Rust bounds. */
function requireServicePrice(price: ServicePriceJson): void {
  requireHash256Hex(price.operation, "service price operation");
  requireCanonicalAmount(price.price, "service price");
  // The unit label may be empty (only its ≤ 32-byte length is bounded in Rust).
  requireBoundedHex(price.unit, "service price unit", 32, false);
}

/**
 * Validates the service's variable-length fields, mirroring
 * `ServiceEntry::validate` and the `bounded_*_hex` codecs: non-empty title
 * (≤ 64 bytes), non-empty endpoint (≤ 256 bytes), ≤ 16 pricing entries.
 */
function requireServiceFields(args: {
  title: HexString;
  endpoint: HexString;
  interface: HexString;
  pricing: ServicePriceJson[];
  paymentFlags: ServicePaymentFlagsJson;
}): void {
  requireBoundedHex(args.title, "service title", 64, true);
  requireBoundedHex(args.endpoint, "service endpoint", 256, true);
  requireHash256Hex(args.interface, "service interface");
  if (!Array.isArray(args.pricing) || args.pricing.length > 16) {
    throw new Error("service pricing exceeds the maximum of 16 entries");
  }
  for (const price of args.pricing) {
    requireServicePrice(price);
  }
  const flags = args.paymentFlags;
  if (
    typeof flags !== "object" ||
    flags === null ||
    typeof flags.on_chain_direct !== "boolean" ||
    typeof flags.http_402 !== "boolean" ||
    typeof flags.subscription !== "boolean"
  ) {
    throw new Error("invalid service payment flags");
  }
}

/** Largest value Rust's `u128` amount encoding can represent. */
const AMOUNT_U128_MAX = (1n << 128n) - 1n;

/**
 * Rejects any amount string Rust's `u128` decimal encoding would never produce.
 *
 * Rust serializes an `Amount` as a canonical unsigned decimal (no sign, no
 * leading zero, within `u128`). Signing a non-canonical string (`"01"`, `"-5"`,
 * `"1_000"`, an over-`u128` value) would silently diverge from Rust's
 * re-serialization during verification, so fail closed in the constructor. The
 * length guard also bounds work before the `BigInt` parse.
 */
function requireCanonicalAmount(value: string, label: string): void {
  if (typeof value !== "string" || value.length > 39 || !/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`invalid canonical amount for ${label}`);
  }
  if (BigInt(value) > AMOUNT_U128_MAX) {
    throw new Error(`amount for ${label} exceeds the u128 range`);
  }
}

/** Bounds for Rust's signed `i128` oracle `FeedValue`. */
const I128_MAX = (1n << 127n) - 1n;
const I128_MIN = -(1n << 127n);

/**
 * Rejects any string Rust's `i128` decimal encoding (`FeedValue`) would never
 * produce: a canonical SIGNED decimal with an optional leading `-`, no leading
 * zeros, within the `i128` range. Signing a non-canonical value would diverge
 * from Rust's re-serialization during verification, so fail closed here.
 */
function requireCanonicalSignedI128(value: string, label: string): void {
  if (
    typeof value !== "string" ||
    value.length > 40 ||
    !/^(0|-?[1-9][0-9]*)$/u.test(value)
  ) {
    throw new Error(`invalid canonical signed integer for ${label}`);
  }
  const parsed = BigInt(value);
  if (parsed < I128_MIN || parsed > I128_MAX) {
    throw new Error(`value for ${label} exceeds the i128 range`);
  }
}

/** Validates a post-quantum root reveal's scheme and hex fields. */
function requireValidReveal(reveal: PostQuantumRootRevealJson): void {
  if (reveal.scheme !== "MlDsa65") {
    throw new Error("unsupported post-quantum scheme");
  }
  if (reveal.public_key.length === 0 || reveal.signature.length === 0) {
    throw new Error("post-quantum reveal must carry a key and signature");
  }
  requireLowercaseHex(reveal.public_key, "reveal public key");
  requireLowercaseHex(reveal.signature, "reveal signature");
}

/** Validates a committed post-quantum root's scheme and non-zero hash. */
function requireValidRoot(root: PostQuantumRootJson): void {
  if (
    root.scheme !== "MlDsa65" ||
    root.public_key_hash.length !== 64 ||
    root.public_key_hash !== root.public_key_hash.toLowerCase() ||
    root.public_key_hash === "00".repeat(32)
  ) {
    throw new Error("invalid post-quantum root commitment");
  }
  hexToBytes(root.public_key_hash);
}

/**
 * Installs a constrained session key. Critical action: the node requires the
 * default lane, an installed policy, and a valid post-quantum root signature
 * over this exact install. Build `postQuantumRootReveal` with the account's
 * recovery root; this SDK does not hold or sign with that root.
 */
export function installSessionKey(args: {
  sessionPublicKey: HexString;
  constraints: SessionKeyConstraintsJson;
  postQuantumRootReveal: PostQuantumRootRevealJson;
}): OperationJson {
  requireLowercaseHex(args.sessionPublicKey, "session public key");
  requireCanonicalAmount(args.constraints.max_amount_per_use, "session max amount per use");
  requireCanonicalAmount(args.constraints.total_amount_budget, "session total amount budget");
  requireCanonicalAmount(args.constraints.max_fee_per_use, "session max fee per use");
  requireCanonicalAmount(args.constraints.total_fee_budget, "session total fee budget");
  requireValidReveal(args.postQuantumRootReveal);
  return {
    InstallSessionKey: {
      session_public_key: args.sessionPublicKey,
      constraints: args.constraints,
      post_quantum_root_reveal: args.postQuantumRootReveal,
    },
  };
}

/** Revokes an installed session key immediately (critical action). */
export function revokeSessionKey(args: {
  sessionKey: SessionKeyIdJson;
  postQuantumRootReveal: PostQuantumRootRevealJson;
}): OperationJson {
  requireLowercaseHex(args.sessionKey, "session key id");
  requireValidReveal(args.postQuantumRootReveal);
  return {
    RevokeSessionKey: {
      session_key: args.sessionKey,
      post_quantum_root_reveal: args.postQuantumRootReveal,
    },
  };
}

/**
 * Rotates the account's active Ed25519 transaction key (recovery/rotation). The
 * envelope may be signed by the new key; the real authority is the root
 * signature. Advances the policy revision, invalidating session keys.
 */
export function rotateActiveTransactionKey(args: {
  newActiveTransactionKey: HexString;
  postQuantumRootReveal: PostQuantumRootRevealJson;
}): OperationJson {
  requireLowercaseHex(args.newActiveTransactionKey, "new active transaction key");
  requireValidReveal(args.postQuantumRootReveal);
  return {
    RotateActiveTransactionKey: {
      new_active_transaction_key: args.newActiveTransactionKey,
      post_quantum_root_reveal: args.postQuantumRootReveal,
    },
  };
}

/**
 * Rotates the account's post-quantum recovery root, preserving the active key.
 * The reveal must be a signature by the CURRENT root over the new commitment.
 */
export function rotatePostQuantumRoot(args: {
  newPostQuantumRoot: PostQuantumRootJson;
  postQuantumRootReveal: PostQuantumRootRevealJson;
}): OperationJson {
  requireValidRoot(args.newPostQuantumRoot);
  requireValidReveal(args.postQuantumRootReveal);
  return {
    RotatePostQuantumRoot: {
      new_post_quantum_root: {
        scheme: args.newPostQuantumRoot.scheme,
        public_key_hash: args.newPostQuantumRoot.public_key_hash,
      },
      post_quantum_root_reveal: args.postQuantumRootReveal,
    },
  };
}

// ---------------------------------------------------------------------------
// Native token operations (Phase 13a, §15).
//
// Field names, order-independent (canonical JSON sorts keys), and value encodings
// mirror the Rust `Operation` serde output pinned by
// `token_operations_have_stable_wire_vectors`. Ids/hashes are 32-byte lowercase
// hex; amounts are canonical decimal strings; addresses are `webc1...`; an absent
// authority is JSON `null`.
// ---------------------------------------------------------------------------

/**
 * Creates a native token. `metadata.name`/`metadata.symbol` are the LOWERCASE HEX
 * of their UTF-8 bytes (use `bytesToHex(new TextEncoder().encode(text))`). The
 * token id is derived on-chain from `(namespace, creator, createNonce)`; use
 * `deriveTokenIdHex` to precompute it for follow-up operations.
 */
export function createToken(args: {
  namespace: HexString;
  createNonce: number;
  metadata: TokenMetadataJson;
  mintAuthority: WebcAddress | null;
  freezeAuthority: WebcAddress | null;
  initialSupply: string;
  initialRecipient: WebcAddress;
}): OperationJson {
  requireHash256Hex(args.namespace, "token namespace");
  requireCountU64(args.createNonce, "token create nonce");
  requireTokenMetadata(args.metadata);
  requireCanonicalAmount(args.initialSupply, "token initial supply");
  return {
    CreateToken: {
      namespace: args.namespace,
      create_nonce: args.createNonce,
      metadata: args.metadata,
      mint_authority: args.mintAuthority,
      freeze_authority: args.freezeAuthority,
      initial_supply: args.initialSupply,
      initial_recipient: args.initialRecipient,
    },
  };
}

/** Mints `amount` units of a token to `recipient`. */
export function mintToken(
  tokenId: HexString,
  recipient: WebcAddress,
  amount: string,
): OperationJson {
  requireHash256Hex(tokenId, "token id");
  requireCanonicalAmount(amount, "mint token amount");
  return { MintToken: { token_id: tokenId, recipient, amount } };
}

/** Burns `amount` units of a token from the signer's balance. */
export function burnToken(tokenId: HexString, amount: string): OperationJson {
  requireHash256Hex(tokenId, "token id");
  requireCanonicalAmount(amount, "burn token amount");
  return { BurnToken: { token_id: tokenId, amount } };
}

/** Transfers `amount` token units from the signer to `recipient`. */
export function transferToken(
  tokenId: HexString,
  recipient: WebcAddress,
  amount: string,
): OperationJson {
  requireHash256Hex(tokenId, "token id");
  requireCanonicalAmount(amount, "transfer token amount");
  return { TransferToken: { token_id: tokenId, recipient, amount } };
}

/** Pauses or unpauses all transfers of a token (mint-authority controlled). */
export function setTokenPaused(
  tokenId: HexString,
  paused: boolean,
): OperationJson {
  requireHash256Hex(tokenId, "token id");
  return { SetTokenPaused: { token_id: tokenId, paused } };
}

/** Freezes one account's balance of a token (freeze-authority controlled). */
export function freezeTokenAccount(
  tokenId: HexString,
  account: WebcAddress,
): OperationJson {
  requireHash256Hex(tokenId, "token id");
  return { FreezeTokenAccount: { token_id: tokenId, account } };
}

/** Thaws (unfreezes) one account's balance of a token. */
export function thawTokenAccount(
  tokenId: HexString,
  account: WebcAddress,
): OperationJson {
  requireHash256Hex(tokenId, "token id");
  return { ThawTokenAccount: { token_id: tokenId, account } };
}

/**
 * Transfers (`newAuthority` = address) or permanently renounces (`newAuthority`
 * = `null`) one of a token's authorities.
 */
export function setTokenAuthority(
  tokenId: HexString,
  authorityKind: TokenAuthorityKindJson,
  newAuthority: WebcAddress | null,
): OperationJson {
  requireHash256Hex(tokenId, "token id");
  return {
    SetTokenAuthority: {
      token_id: tokenId,
      authority_kind: authorityKind,
      new_authority: newAuthority,
    },
  };
}

// ---------------------------------------------------------------------------
// Native NFT operations (Phase 13b, §15).
//
// Field names and value encodings mirror the Rust `Operation` serde output pinned
// by `nft_operations_have_stable_wire_vectors`. Serials are plain JSON numbers
// (u64); ids/hashes are 32-byte lowercase hex; an absent authority/cap is `null`.
// ---------------------------------------------------------------------------

/**
 * Creates an NFT collection. `metadata.name`/`metadata.symbol` are LOWERCASE HEX
 * of their UTF-8 bytes. `maxSupply` is an optional hard cap (`null` = no cap);
 * `royaltyBps` is a recorded-only royalty commitment (≤ 10000). The collection id
 * is derived on-chain from `(namespace, creator, createNonce)`; use
 * `deriveNftCollectionIdHex` to precompute it.
 */
export function createNftCollection(args: {
  namespace: HexString;
  createNonce: number;
  metadata: NftMetadataJson;
  mintAuthority: WebcAddress | null;
  freezeAuthority: WebcAddress | null;
  maxSupply: number | null;
  royaltyBps: number;
}): OperationJson {
  requireHash256Hex(args.namespace, "nft namespace");
  requireCountU64(args.createNonce, "nft create nonce");
  requireNftMetadata(args.metadata);
  if (args.maxSupply !== null) {
    requireCountU64(args.maxSupply, "nft max supply");
  }
  requireBoundedU(args.royaltyBps, "nft royalty bps", 10_000);
  return {
    CreateNftCollection: {
      namespace: args.namespace,
      create_nonce: args.createNonce,
      metadata: args.metadata,
      mint_authority: args.mintAuthority,
      freeze_authority: args.freezeAuthority,
      max_supply: args.maxSupply,
      royalty_bps: args.royaltyBps,
    },
  };
}

/** Mints a new item of a collection to `recipient`. */
export function mintNft(
  collectionId: HexString,
  recipient: WebcAddress,
  itemMetadataHash: HexString,
): OperationJson {
  requireHash256Hex(collectionId, "collection id");
  requireHash256Hex(itemMetadataHash, "nft item metadata hash");
  return {
    MintNft: {
      collection_id: collectionId,
      recipient,
      item_metadata_hash: itemMetadataHash,
    },
  };
}

/** Transfers one NFT item (by serial) to `recipient`. */
export function transferNft(
  collectionId: HexString,
  serial: number,
  recipient: WebcAddress,
): OperationJson {
  requireHash256Hex(collectionId, "collection id");
  requireCountU64(serial, "nft serial");
  return { TransferNft: { collection_id: collectionId, serial, recipient } };
}

/** Burns one NFT item (by serial) held by the signer. */
export function burnNft(collectionId: HexString, serial: number): OperationJson {
  requireHash256Hex(collectionId, "collection id");
  requireCountU64(serial, "nft serial");
  return { BurnNft: { collection_id: collectionId, serial } };
}

/** Pauses or unpauses minting of a collection (mint-authority controlled). */
export function setNftCollectionPaused(
  collectionId: HexString,
  paused: boolean,
): OperationJson {
  requireHash256Hex(collectionId, "collection id");
  return { SetNftCollectionPaused: { collection_id: collectionId, paused } };
}

/** Freezes one NFT item (freeze-authority controlled). */
export function freezeNftItem(
  collectionId: HexString,
  serial: number,
): OperationJson {
  requireHash256Hex(collectionId, "collection id");
  requireCountU64(serial, "nft serial");
  return { FreezeNftItem: { collection_id: collectionId, serial } };
}

/** Thaws (unfreezes) one NFT item. */
export function thawNftItem(
  collectionId: HexString,
  serial: number,
): OperationJson {
  requireHash256Hex(collectionId, "collection id");
  requireCountU64(serial, "nft serial");
  return { ThawNftItem: { collection_id: collectionId, serial } };
}

/**
 * Transfers (`newAuthority` = address) or permanently renounces (`newAuthority`
 * = `null`) one of a collection's authorities.
 */
export function setNftAuthority(
  collectionId: HexString,
  authorityKind: NftAuthorityKindJson,
  newAuthority: WebcAddress | null,
): OperationJson {
  requireHash256Hex(collectionId, "collection id");
  return {
    SetNftAuthority: {
      collection_id: collectionId,
      authority_kind: authorityKind,
      new_authority: newAuthority,
    },
  };
}

// ---------------------------------------------------------------------------
// Native governance operations (Phase 13c, §15).
//
// Field names and value encodings mirror the Rust `Operation` serde output pinned
// by `governance_operations_have_stable_wire_vectors`. Amounts are decimal
// strings; ids/tokens are 32-byte lowercase hex; the choice/action enums tag by
// variant name.
//
// NOTE: OpenProposal / CastVote / ResolveProposal / ExecuteProposal / ReclaimVote
// touch a key derived from ON-CHAIN state (the instance's weight token, or a
// proposal payout) that the SDK cannot see. Their operation JSON is complete, but
// their access list is not — build it with the matching `accessListFor*` helper,
// passing the resolved value, exactly like the Rust `Transaction::for_*`
// constructors. `signTransaction` refuses to auto-derive their access list.
// ---------------------------------------------------------------------------

/**
 * Creates a governance instance bound to `weightToken` under `config`. The
 * instance id is derived on-chain from `(namespace, creator, createNonce)`; use
 * `deriveGovernanceInstanceIdHex` to precompute it.
 */
export function createGovernanceInstance(args: {
  namespace: HexString;
  createNonce: number;
  weightToken: HexString;
  config: GovernanceConfigJson;
}): OperationJson {
  requireHash256Hex(args.namespace, "governance namespace");
  requireCountU64(args.createNonce, "governance create nonce");
  requireHash256Hex(args.weightToken, "governance weight token");
  requireGovernanceConfig(args.config);
  return {
    CreateGovernanceInstance: {
      namespace: args.namespace,
      create_nonce: args.createNonce,
      weight_token: args.weightToken,
      config: args.config,
    },
  };
}

/** Deposits native WEBC into an instance's treasury. */
export function fundGovernanceTreasury(
  instanceId: HexString,
  amount: string,
): OperationJson {
  requireHash256Hex(instanceId, "governance instance id");
  requireCanonicalAmount(amount, "fund governance treasury amount");
  return { FundGovernanceTreasury: { instance_id: instanceId, amount } };
}

/** Opens a proposal carrying one typed `action` on an instance. */
export function openProposal(
  instanceId: HexString,
  action: GovernanceActionJson,
): OperationJson {
  requireHash256Hex(instanceId, "governance instance id");
  requireGovernanceAction(action);
  return { OpenProposal: { instance_id: instanceId, action } };
}

/** Casts a lock-to-vote ballot; `weightAmount` weight-token units are locked. */
export function castVote(
  proposalId: HexString,
  choice: VoteChoiceJson,
  weightAmount: string,
): OperationJson {
  requireHash256Hex(proposalId, "governance proposal id");
  requireCanonicalAmount(weightAmount, "cast vote weight amount");
  return { CastVote: { proposal_id: proposalId, choice, weight_amount: weightAmount } };
}

/** Resolves a proposal after its voting period ends (permissionless). */
export function resolveProposal(proposalId: HexString): OperationJson {
  requireHash256Hex(proposalId, "governance proposal id");
  return { ResolveProposal: { proposal_id: proposalId } };
}

/** Executes (or expires) a passed proposal within its execution window. */
export function executeProposal(proposalId: HexString): OperationJson {
  requireHash256Hex(proposalId, "governance proposal id");
  return { ExecuteProposal: { proposal_id: proposalId } };
}

/** Reclaims the caller's locked weight after a proposal resolves. */
export function reclaimVote(proposalId: HexString): OperationJson {
  requireHash256Hex(proposalId, "governance proposal id");
  return { ReclaimVote: { proposal_id: proposalId } };
}

// ---------------------------------------------------------------------------
// State-derived access-list builders (Phase 13c/9b, §15).
//
// These mirror the Rust `Transaction::for_*` constructors: they take the base
// access list and append the key(s) derived from ON-CHAIN state the operation
// does not itself carry (an instance's weight token, a proposal's payout, a
// service's owner). Resolve the value from the node, pass it here, and hand the
// result to `signTransaction` as its explicit `accessList` argument. A stale
// value fails closed on the node's access-list check.
// ---------------------------------------------------------------------------

/** Full access list for `OpenProposal` (adds the proposer's weight balance read). */
export function accessListForOpenProposal(args: {
  sender: WebcAddress;
  instanceId: HexString;
  action: GovernanceActionJson;
  weightToken: HexString;
  authorizationLane?: AuthorizationLaneIdJson;
}): StateAccessListJson {
  requireHash256Hex(args.weightToken, "governance weight token");
  const list = defaultAccessList(
    args.sender,
    openProposal(args.instanceId, args.action),
    args.authorizationLane ?? DEFAULT_AUTHORIZATION_LANE,
  );
  pushUniqueKey(list.read_only, tokenBalanceKey(args.weightToken, args.sender));
  return list;
}

/**
 * Full access list for `CastVote`. The lock moves weight-token units from the
 * voter to the proposal's deterministic escrow, so this adds the token record
 * (paused read), both freeze markers (voter + escrow), and both balance keys.
 */
export async function accessListForCastVote(args: {
  sender: WebcAddress;
  proposalId: HexString;
  choice: VoteChoiceJson;
  weightAmount: string;
  weightToken: HexString;
  authorizationLane?: AuthorizationLaneIdJson;
}): Promise<StateAccessListJson> {
  requireHash256Hex(args.weightToken, "governance weight token");
  const list = defaultAccessList(
    args.sender,
    castVote(args.proposalId, args.choice, args.weightAmount),
    args.authorizationLane ?? DEFAULT_AUTHORIZATION_LANE,
  );
  const escrow = await deriveGovVoteEscrowAddress(args.proposalId);
  pushUniqueKey(list.read_only, tokenKey(args.weightToken));
  pushUniqueKey(list.read_only, tokenFreezeKey(args.weightToken, args.sender));
  pushUniqueKey(list.read_only, tokenFreezeKey(args.weightToken, escrow));
  pushUniqueKey(list.read_write, tokenBalanceKey(args.weightToken, args.sender));
  pushUniqueKey(list.read_write, tokenBalanceKey(args.weightToken, escrow));
  return list;
}

/** Full access list for `ResolveProposal` (adds the weight-token supply read). */
export function accessListForResolveProposal(args: {
  sender: WebcAddress;
  proposalId: HexString;
  weightToken: HexString;
  authorizationLane?: AuthorizationLaneIdJson;
}): StateAccessListJson {
  requireHash256Hex(args.weightToken, "governance weight token");
  const list = defaultAccessList(
    args.sender,
    resolveProposal(args.proposalId),
    args.authorizationLane ?? DEFAULT_AUTHORIZATION_LANE,
  );
  pushUniqueKey(list.read_only, tokenKey(args.weightToken));
  return list;
}

/**
 * Full access list for `ExecuteProposal`. A `TreasuryTransfer` payout writes the
 * instance treasury and credits the recipient — pass `payout` resolved from the
 * stored proposal; a `Signaling` proposal needs no extra keys (`payout = null`).
 */
export function accessListForExecuteProposal(args: {
  sender: WebcAddress;
  proposalId: HexString;
  payout: { instanceId: HexString; recipient: WebcAddress } | null;
  authorizationLane?: AuthorizationLaneIdJson;
}): StateAccessListJson {
  const list = defaultAccessList(
    args.sender,
    executeProposal(args.proposalId),
    args.authorizationLane ?? DEFAULT_AUTHORIZATION_LANE,
  );
  if (args.payout !== null) {
    requireHash256Hex(args.payout.instanceId, "governance instance id");
    pushUniqueKey(list.read_write, governanceInstanceKey(args.payout.instanceId));
    pushUniqueKey(list.read_write, accountKey(args.payout.recipient));
  }
  return list;
}

/** Full access list for `ReclaimVote` (adds both weight-token balance keys). */
export async function accessListForReclaimVote(args: {
  sender: WebcAddress;
  proposalId: HexString;
  weightToken: HexString;
  authorizationLane?: AuthorizationLaneIdJson;
}): Promise<StateAccessListJson> {
  requireHash256Hex(args.weightToken, "governance weight token");
  const list = defaultAccessList(
    args.sender,
    reclaimVote(args.proposalId),
    args.authorizationLane ?? DEFAULT_AUTHORIZATION_LANE,
  );
  const escrow = await deriveGovVoteEscrowAddress(args.proposalId);
  pushUniqueKey(list.read_write, tokenBalanceKey(args.weightToken, escrow));
  pushUniqueKey(list.read_write, tokenBalanceKey(args.weightToken, args.sender));
  return list;
}

// ---------------------------------------------------------------------------
// Agent mandate operations (Phase 9a, §15.32).
//
// Field names and value encodings mirror the Rust `Operation` serde output pinned
// by `mandate_operations_have_stable_wire_vectors`. Amounts are decimal strings;
// ids/keys are 32-byte lowercase hex; the epoch is a plain JSON number; the
// counterparty policy tags by variant name.
// ---------------------------------------------------------------------------

/**
 * Grants a spending mandate to `agentKey` (a 32-byte Ed25519 public key, lowercase
 * hex). The mandate id is derived on-chain from `(principal, agentKey, grantNonce)`
 * where the principal is the signer; use `deriveMandateIdHex` to precompute it.
 */
export function grantMandate(args: {
  agentKey: HexString;
  grantNonce: number;
  budgetTotal: string;
  expiryEpoch: number;
  perTxMax: string;
  rateLimitPerDay: number;
  counterpartyPolicy: MandateCounterpartyPolicyJson;
}): OperationJson {
  requireHash256Hex(args.agentKey, "mandate agent key");
  requireCountU64(args.grantNonce, "mandate grant nonce");
  requireCanonicalAmount(args.budgetTotal, "mandate budget total");
  requireCountU64(args.expiryEpoch, "mandate expiry epoch");
  requireCanonicalAmount(args.perTxMax, "mandate per-tx max");
  requireBoundedU(args.rateLimitPerDay, "mandate rate limit per day", 0xffffffff);
  return {
    GrantMandate: {
      agent_key: args.agentKey,
      grant_nonce: args.grantNonce,
      budget_total: args.budgetTotal,
      expiry_epoch: args.expiryEpoch,
      per_tx_max: args.perTxMax,
      rate_limit_per_day: args.rateLimitPerDay,
      counterparty_policy: canonicalCounterpartyPolicy(args.counterpartyPolicy),
    },
  };
}

/** Adds native base units to an existing mandate's budget (principal-signed). */
export function topUpMandate(
  mandateId: HexString,
  amount: string,
): OperationJson {
  requireHash256Hex(mandateId, "mandate id");
  requireCanonicalAmount(amount, "top up mandate amount");
  return { TopUpMandate: { mandate_id: mandateId, amount } };
}

/** Spends `amount` against a mandate to `recipient` (agent-signed). */
export function spendUnderMandate(
  mandateId: HexString,
  recipient: WebcAddress,
  amount: string,
): OperationJson {
  requireHash256Hex(mandateId, "mandate id");
  requireCanonicalAmount(amount, "spend under mandate amount");
  return { SpendUnderMandate: { mandate_id: mandateId, recipient, amount } };
}

/** Revokes a mandate and returns its unspent remainder (principal-signed). */
export function revokeMandate(mandateId: HexString): OperationJson {
  requireHash256Hex(mandateId, "mandate id");
  return { RevokeMandate: { mandate_id: mandateId } };
}

// ---------------------------------------------------------------------------
// Native oracle operations (Phase 7, §15.17).
//
// Field names and value encodings mirror the Rust `Operation` serde output pinned
// by `oracle_operations_have_stable_wire_vectors`. Feed ids are 32-byte lowercase
// hex; `amount` is an unsigned decimal string; the report `value` is a SIGNED
// decimal string (Rust `FeedValue`, an `i128`), never a bare JSON number.
// ---------------------------------------------------------------------------

/** Creates a native oracle feed owned by the signer (flat, burned fee). */
export function createFeed(feedId: HexString): OperationJson {
  requireHash256Hex(feedId, "feed id");
  return { CreateFeed: { feed_id: feedId } };
}

/** Registers the signer as a bonded reporter on an existing feed. */
export function registerReporter(feedId: HexString): OperationJson {
  requireHash256Hex(feedId, "feed id");
  return { RegisterReporter: { feed_id: feedId } };
}

/** Deregisters the signer from a feed and returns its bond. */
export function deregisterReporter(feedId: HexString): OperationJson {
  requireHash256Hex(feedId, "feed id");
  return { DeregisterReporter: { feed_id: feedId } };
}

/** Submits the signer's latest signed integer value for a feed. */
export function submitReport(feedId: HexString, value: string): OperationJson {
  requireHash256Hex(feedId, "feed id");
  requireCanonicalSignedI128(value, "feed report value");
  return { SubmitReport: { feed_id: feedId, value } };
}

/** Pays a read fee into a feed's revenue pool. */
export function payFeedRead(feedId: HexString, amount: string): OperationJson {
  requireHash256Hex(feedId, "feed id");
  requireCanonicalAmount(amount, "pay feed read amount");
  return { PayFeedRead: { feed_id: feedId, amount } };
}

// ---------------------------------------------------------------------------
// Service registry operations (Phase 9b, §15.5).
//
// Field names and value encodings mirror the Rust `Operation` serde output pinned
// by `service_registry_operations_have_stable_wire_vectors`. Byte-string fields
// (title, endpoint, price unit) are LOWERCASE HEX; amounts are decimal strings;
// categories serialize as a sorted, deduplicated array (Rust `BTreeSet<Hash256>`).
// ---------------------------------------------------------------------------

/**
 * Registers a service. `title`/`endpoint` and each price `unit` are LOWERCASE HEX
 * of their bytes. The service id is derived on-chain from `(namespace, owner,
 * createNonce)`; use `deriveServiceIdHex` to precompute it.
 */
export function registerService(args: {
  namespace: HexString;
  createNonce: number;
  categories: HexString[];
  title: HexString;
  endpoint: HexString;
  interface: HexString;
  pricing: ServicePriceJson[];
  paymentFlags: ServicePaymentFlagsJson;
}): OperationJson {
  requireHash256Hex(args.namespace, "service namespace");
  requireCountU64(args.createNonce, "service create nonce");
  const categories = canonicalServiceCategories(args.categories);
  requireServiceFields(args);
  return {
    RegisterService: {
      namespace: args.namespace,
      create_nonce: args.createNonce,
      categories,
      title: args.title,
      endpoint: args.endpoint,
      interface: args.interface,
      pricing: args.pricing,
      payment_flags: args.paymentFlags,
    },
  };
}

/** Updates a registered service's mutable fields (owner-only). */
export function updateService(args: {
  serviceId: HexString;
  categories: HexString[];
  title: HexString;
  endpoint: HexString;
  interface: HexString;
  pricing: ServicePriceJson[];
  paymentFlags: ServicePaymentFlagsJson;
}): OperationJson {
  requireHash256Hex(args.serviceId, "service id");
  const categories = canonicalServiceCategories(args.categories);
  requireServiceFields(args);
  return {
    UpdateService: {
      service_id: args.serviceId,
      categories,
      title: args.title,
      endpoint: args.endpoint,
      interface: args.interface,
      pricing: args.pricing,
      payment_flags: args.paymentFlags,
    },
  };
}

/** Sets a registered service's lifecycle status (owner-only). */
export function setServiceStatus(
  serviceId: HexString,
  status: ServiceStatusJson,
): OperationJson {
  requireHash256Hex(serviceId, "service id");
  return { SetServiceStatus: { service_id: serviceId, status } };
}

/**
 * Spends against a mandate to pay a registered service (agent-signed). Its access
 * list needs the service's OWNER account, which is state-derived (resolved from
 * the registry entry) — build it with `accessListForServiceSpend`.
 */
export function spendUnderMandateToService(
  mandateId: HexString,
  serviceId: HexString,
  amount: string,
): OperationJson {
  requireHash256Hex(mandateId, "mandate id");
  requireHash256Hex(serviceId, "service id");
  requireCanonicalAmount(amount, "spend under mandate to service amount");
  return {
    SpendUnderMandateToService: {
      mandate_id: mandateId,
      service_id: serviceId,
      amount,
    },
  };
}

/**
 * Full access list for `SpendUnderMandateToService`, mirroring Rust
 * `Transaction::for_service_spend`: the base list plus the service OWNER account
 * (the registry pay-to), resolved by the caller from the service entry.
 */
export function accessListForServiceSpend(args: {
  sender: WebcAddress;
  mandateId: HexString;
  serviceId: HexString;
  serviceOwner: WebcAddress;
  authorizationLane?: AuthorizationLaneIdJson;
}): StateAccessListJson {
  const list = defaultAccessList(
    args.sender,
    spendUnderMandateToService(args.mandateId, args.serviceId, "0"),
    args.authorizationLane ?? DEFAULT_AUTHORIZATION_LANE,
  );
  pushUniqueKey(list.read_write, accountKey(args.serviceOwner));
  return list;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Default access list for an operation, mirroring Rust
 * `Operation::default_access_list`. The sender account and payer-scoped fee
 * key are always writable, while the current base fee is read-only.
 */
export function defaultAccessList(
  sender: WebcAddress,
  operation: OperationJson,
  authorizationLane: AuthorizationLaneIdJson = DEFAULT_AUTHORIZATION_LANE,
): StateAccessListJson {
  const readWrite: StateKeyJson[] = authorizationLane === DEFAULT_AUTHORIZATION_LANE
    ? [accountKey(sender)]
    : [authorizationLaneKey(sender, authorizationLane)];
  for (const key of extraReadWriteKeys(sender, operation)) {
    pushUniqueKey(readWrite, key);
  }
  // Base fee is always read; op-specific read-only keys (e.g. a token record or
  // freeze marker consulted but not mutated) are pushed in the same arm order as
  // Rust; the authorization policy is read last unless the op writes it. This
  // matches Rust `default_access_list_for_lane`'s insertion order, which the
  // access list preserves (it is NOT re-sorted before signing).
  const readOnly: StateKeyJson[] = [protocolKey("BaseFee")];
  for (const key of extraReadOnlyKeys(sender, operation)) {
    pushUniqueKey(readOnly, key);
  }
  if (!writesAuthorizationPolicy(operation)) {
    pushUniqueKey(readOnly, authorizationPolicyKey(sender));
  }
  pushUniqueKey(readWrite, feeAccumulatorKey(sender, authorizationLane));
  return { read_only: readOnly, read_write: readWrite };
}

/** Pushes `key` onto `keys` only if no structurally equal key is present. */
function pushUniqueKey(keys: StateKeyJson[], key: StateKeyJson): void {
  if (!keys.some((candidate) => canonicalKey(candidate) === canonicalKey(key))) {
    keys.push(key);
  }
}

/**
 * Op-specific READ-ONLY access-list keys, mirroring the read-only pushes inside
 * the Rust `default_access_list_for_lane` arms. Existing operations declare no
 * op-specific read-only key (the authorization policy is added by the caller), so
 * this returns an empty list for them, keeping their signed bytes unchanged.
 */
function extraReadOnlyKeys(
  sender: WebcAddress,
  operation: OperationJson,
): StateKeyJson[] {
  if (typeof operation !== "object" || operation === null) {
    return [];
  }
  // --- Native tokens ------------------------------------------------------
  if ("TransferToken" in operation) {
    const { token_id, recipient } = operation.TransferToken;
    // Both parties' freeze markers are declared READS so the parallel scheduler
    // serializes this transfer against a Freeze/Thaw of either account. Omitting
    // them was a real Rust bug; do not drop them.
    return [
      tokenKey(token_id),
      tokenFreezeKey(token_id, sender),
      tokenFreezeKey(token_id, recipient),
    ];
  }
  if ("FreezeTokenAccount" in operation) {
    return [tokenKey(operation.FreezeTokenAccount.token_id)];
  }
  if ("ThawTokenAccount" in operation) {
    return [tokenKey(operation.ThawTokenAccount.token_id)];
  }
  // --- Native NFTs --------------------------------------------------------
  if ("TransferNft" in operation) {
    // The collection record is read-only (paused flag); the item key carries the
    // owner/frozen reads and the ownership write.
    return [nftCollectionKey(operation.TransferNft.collection_id)];
  }
  if ("FreezeNftItem" in operation) {
    return [nftCollectionKey(operation.FreezeNftItem.collection_id)];
  }
  if ("ThawNftItem" in operation) {
    return [nftCollectionKey(operation.ThawNftItem.collection_id)];
  }
  // --- Native governance --------------------------------------------------
  if ("ReclaimVote" in operation) {
    // Reclaim READS the resolved proposal and writes only the voter's lock.
    return [governanceProposalKey(operation.ReclaimVote.proposal_id)];
  }
  // --- Service registry ---------------------------------------------------
  if ("SpendUnderMandateToService" in operation) {
    // The service entry is READ to resolve the pay-to owner.
    return [serviceKey(operation.SpendUnderMandateToService.service_id)];
  }
  // --- Native oracle ------------------------------------------------------
  if ("RegisterReporter" in operation) {
    return [oracleFeedKey(operation.RegisterReporter.feed_id)];
  }
  if ("DeregisterReporter" in operation) {
    return [oracleFeedKey(operation.DeregisterReporter.feed_id)];
  }
  if ("SubmitReport" in operation) {
    return [oracleFeedKey(operation.SubmitReport.feed_id)];
  }
  return [];
}

/**
 * Operations that WRITE the authorization policy key, so it must not also appear
 * as a read-only key. Mirrors the Rust exclusion in `default_access_list_for_lane`:
 * policy installation and both rotations replace the policy record; session-key
 * install/revoke only read it.
 */
function writesAuthorizationPolicy(operation: OperationJson): boolean {
  return (
    typeof operation === "object" &&
    operation !== null &&
    ("InstallAuthorizationPolicy" in operation ||
      "RotateActiveTransactionKey" in operation ||
      "RotatePostQuantumRoot" in operation)
  );
}

/**
 * Builds defaults for operations whose replay keys require SHA-256 hashing.
 *
 * Slashing remains excluded because its complete writable set depends on live
 * delegation and cooling owners. A wallet must query that state and supply an
 * explicit signed list; guessing would create transactions that fail closed.
 */
export async function defaultAccessListAsync(
  sender: WebcAddress,
  operation: OperationJson,
  authorizationLane: AuthorizationLaneIdJson = DEFAULT_AUTHORIZATION_LANE,
): Promise<StateAccessListJson> {
  if (typeof operation === "object" && operation !== null) {
    if ("BridgeMint" in operation || "BridgeRelease" in operation) {
      const message = "BridgeMint" in operation
        ? operation.BridgeMint.message
        : operation.BridgeRelease.message;
      const recipient = addressFromBytes(hexToBytes(message.recipient));
      const recipientKey = message.asset === "NativeWebc"
        ? accountKey(recipient)
        : assetBalanceKey(message.asset, recipient);
      return assembleAccessList(sender, authorizationLane, [
        recipientKey,
        bridgeMessageKey(await bridgeMessageHashHex(message)),
        ...(message.asset === "NativeWebc"
          ? [bridgeEscrowKey(message.source_chain)]
          : []),
      ]);
    }
    if ("InstallSessionKey" in operation) {
      // The writable session-key record is keyed by the derived id.
      const sessionKeyId = await deriveSessionKeyIdHex(
        operation.InstallSessionKey.session_public_key,
      );
      return assembleAccessList(sender, authorizationLane, [
        accountKey(sender),
        sessionKeyKey(sender, sessionKeyId),
      ]);
    }
    if ("SubmitSlashingEvidence" in operation) {
      throw new Error(
        "slashing evidence requires an explicit state-derived access list",
      );
    }
    if ("CreateToken" in operation) {
      const { namespace, create_nonce, initial_supply, initial_recipient } =
        operation.CreateToken;
      const tokenId = await deriveTokenIdHex(namespace, sender, create_nonce);
      const extra: StateKeyJson[] = [accountKey(sender), tokenKey(tokenId)];
      // The initial mint writes the recipient's per-account balance only when the
      // supply is non-zero, exactly like the Rust arm.
      if (initial_supply !== "0") {
        extra.push(tokenBalanceKey(tokenId, initial_recipient));
      }
      return assembleAccessList(sender, authorizationLane, extra);
    }
    if ("CreateNftCollection" in operation) {
      const { namespace, create_nonce } = operation.CreateNftCollection;
      const collectionId = await deriveNftCollectionIdHex(
        namespace,
        sender,
        create_nonce,
      );
      // Creation writes only the account and the new collection record; it mints
      // no item, so no item key is declared.
      return assembleAccessList(sender, authorizationLane, [
        accountKey(sender),
        nftCollectionKey(collectionId),
      ]);
    }
    if ("GrantMandate" in operation) {
      const { agent_key, grant_nonce } = operation.GrantMandate;
      const mandateId = await deriveMandateIdHex(sender, agent_key, grant_nonce);
      // A grant locks the budget from the principal and writes the new mandate
      // record.
      return assembleAccessList(sender, authorizationLane, [
        accountKey(sender),
        mandateKey(mandateId),
      ]);
    }
    if ("RegisterService" in operation) {
      const { namespace, create_nonce } = operation.RegisterService;
      const serviceId = await deriveServiceIdHex(namespace, sender, create_nonce);
      // Registration records only the entry (it moves no native units beyond the
      // fee lane), so only the derived service key is added.
      return assembleAccessList(sender, authorizationLane, [
        serviceKey(serviceId),
      ]);
    }
    if ("CreateGovernanceInstance" in operation) {
      const { namespace, create_nonce, weight_token } =
        operation.CreateGovernanceInstance;
      const instanceId = await deriveGovernanceInstanceIdHex(
        namespace,
        sender,
        create_nonce,
      );
      // Creation writes the account and the new instance record; the weight token
      // is READ to confirm it exists.
      return assembleAccessList(
        sender,
        authorizationLane,
        [accountKey(sender), governanceInstanceKey(instanceId)],
        [tokenKey(weight_token)],
      );
    }
    if (STATE_DERIVED_ACCESS_LIST_OPS.some((variant) => variant in operation)) {
      throw new Error(
        stateDerivedAccessListMessage(operation),
      );
    }
  }
  return defaultAccessList(sender, operation, authorizationLane);
}

/**
 * Operations whose complete access list needs a key derived from ON-CHAIN state
 * the SDK cannot see (a service owner, a weight token, a proposal payout). Their
 * base list is signable but INCOMPLETE, so `defaultAccessListAsync` refuses to
 * auto-build one; callers use the dedicated `accessListFor*` helper, passing the
 * resolved value, exactly like the Rust `Transaction::for_*` constructors.
 */
const STATE_DERIVED_ACCESS_LIST_OPS = [
  "SpendUnderMandateToService",
  "OpenProposal",
  "CastVote",
  "ResolveProposal",
  "ExecuteProposal",
  "ReclaimVote",
] as const;

function stateDerivedAccessListMessage(operation: OperationJson): string {
  const variant = STATE_DERIVED_ACCESS_LIST_OPS.find(
    (candidate) =>
      typeof operation === "object" && operation !== null && candidate in operation,
  );
  return (
    `${variant ?? "operation"} needs a state-derived access-list key; use the ` +
    `accessListFor${variant ?? "Operation"} helper with the resolved key(s) and ` +
    `pass the result as an explicit access list`
  );
}

/**
 * Builds the exact canonical payload shape hashed and signed by Rust and the SDK.
 *
 * This helper exposes no secret material. It exists so shared byte fixtures can
 * verify field naming, versioned access keys, and fee conversion without
 * requiring a browser private key.
 */
export function transactionSigningPayload(
  protocolVersion: number,
  chainId: string,
  sender: WebcAddress,
  publicKeyHex: string,
  nonce: number,
  operation: OperationJson,
  accessList: StateAccessListJson,
  fee: FeeBid,
  authorizationLane: AuthorizationLaneIdJson = DEFAULT_AUTHORIZATION_LANE,
  authorizationPolicyRevision = 0,
  sponsor?: HexString,
): Record<string, unknown> {
  validateTransactionContext(protocolVersion, chainId);
  validateAuthorizationPolicyRevision(authorizationPolicyRevision);
  if (sponsor !== undefined) {
    validateSponsor(sponsor);
  }
  return transactionSigningPayloadWire(
    protocolVersion,
    chainId,
    sender,
    publicKeyHex,
    authorizationLane,
    authorizationPolicyRevision,
    nonce,
    operation,
    accessList,
    feeWireJson(fee),
    sponsor,
  );
}

function transactionSigningPayloadWire(
  protocolVersion: number,
  chainId: string,
  sender: WebcAddress,
  publicKeyHex: string,
  authorizationLane: AuthorizationLaneIdJson,
  authorizationPolicyRevision: number,
  nonce: number,
  operation: OperationJson,
  accessList: StateAccessListJson,
  fee: FeeBidJson,
  sponsor?: HexString,
): Record<string, unknown> {
  return {
    domain: TRANSACTION_SIGNING_DOMAIN,
    protocol_version: protocolVersion,
    chain_id: chainId,
    sender,
    public_key: publicKeyHex,
    authorization_lane: authorizationLane,
    authorization_policy_revision: authorizationPolicyRevision,
    nonce,
    operation,
    access_list: accessList,
    fee,
    // Included only when set. Canonical JSON sorts keys, so it lands last (after
    // `sender`), exactly where Rust's `#[serde(skip_serializing_if)]` sponsor
    // field sorts. Omitted when absent → byte-identical to the frozen V4 vectors.
    ...(sponsor !== undefined ? { sponsor } : {}),
  };
}

/** Validates the only protocol version and canonical chain-ID grammar supported. */
export function validateTransactionContext(
  protocolVersion: number,
  chainId: string,
): void {
  if (protocolVersion !== CURRENT_TRANSACTION_PROTOCOL_VERSION) {
    throw new Error("unsupported transaction protocol version");
  }
  if (
    chainId.length < 3 ||
    chainId.length > 64 ||
    !/^[a-z][a-z0-9-]*$/u.test(chainId)
  ) {
    throw new Error("invalid transaction chain ID");
  }
}

/** Rejects inexact or negative policy revisions before canonical encoding. */
export function validateAuthorizationPolicyRevision(revision: number): void {
  if (!Number.isSafeInteger(revision) || revision < 0) {
    throw new Error("invalid authorization policy revision");
  }
}

/**
 * Rejects a sponsor namespace that Rust's `Hash256` JSON encoding would never
 * reproduce. A sponsor is a 32-byte app-namespace hash, serialized by Rust as a
 * lowercase 64-char hex string (`hex::encode`). A mixed-case, wrong-length, or
 * non-hex value would sign bytes the node never re-derives, so fail closed here
 * exactly like the other Hash256-typed fields.
 */
export function validateSponsor(sponsor: HexString): void {
  if (typeof sponsor !== "string" || !/^[0-9a-f]{64}$/u.test(sponsor)) {
    throw new Error("invalid sponsor namespace (expected 32-byte lowercase hex)");
  }
}

function extraReadWriteKeys(
  sender: WebcAddress,
  operation: OperationJson,
): StateKeyJson[] {
  if (operation === "ClaimValidatorRewards") {
    return [accountKey(sender), validatorKey(sender)];
  }
  if ("InstallAuthorizationPolicy" in operation) {
    return [accountKey(sender), authorizationPolicyKey(sender)];
  }
  if ("OpenAuthorizationLane" in operation) {
    return [
      accountKey(sender),
      authorizationLaneKey(sender, operation.OpenAuthorizationLane.lane),
    ];
  }
  if ("FundAuthorizationLane" in operation) {
    return [
      accountKey(sender),
      authorizationLaneKey(sender, operation.FundAuthorizationLane.lane),
    ];
  }
  if (
    "CreateObject" in operation ||
    "MutateObject" in operation ||
    "TransferObject" in operation
  ) {
    const payload = "CreateObject" in operation
      ? operation.CreateObject
      : "MutateObject" in operation
        ? operation.MutateObject
        : operation.TransferObject;
    return [
      objectKey(payload.object_id),
      applicationKey(payload.namespace, payload.object_id),
    ];
  }
  if ("RevokeSessionKey" in operation) {
    return [
      accountKey(sender),
      sessionKeyKey(sender, operation.RevokeSessionKey.session_key),
    ];
  }
  if (
    "RotateActiveTransactionKey" in operation ||
    "RotatePostQuantumRoot" in operation
  ) {
    // Both rotations write the account (nonce/fees) and the policy record.
    return [accountKey(sender), authorizationPolicyKey(sender)];
  }
  if ("InstallSessionKey" in operation) {
    // The writable session-key id is a SHA-256 of the session public key, so the
    // access list needs an async hash. Callers must use defaultAccessListAsync.
    throw new Error(
      "InstallSessionKey requires defaultAccessListAsync (session-key id derivation)",
    );
  }
  if ("Transfer" in operation) {
    return [accountKey(sender), accountKey(operation.Transfer.to)];
  }
  if ("RegisterValidator" in operation) {
    return [accountKey(sender), validatorKey(sender)];
  }
  if ("Delegate" in operation) {
    return [
      accountKey(sender),
      validatorKey(operation.Delegate.validator),
      delegationKey(sender, operation.Delegate.validator),
      // Execution consults pending operator exits before accepting stake.
      unbondingQueueKey(operation.Delegate.validator),
    ];
  }
  if ("Undelegate" in operation) {
    return [
      delegationKey(sender, operation.Undelegate.validator),
      unbondingQueueKey(operation.Undelegate.validator),
    ];
  }
  if ("ClaimUnbonded" in operation) {
    return [
      accountKey(sender),
      unbondingQueueKey(operation.ClaimUnbonded.validator),
    ];
  }
  if ("UnstakeValidator" in operation) {
    return [validatorKey(sender), unbondingQueueKey(sender)];
  }
  if ("ClaimDelegatorRewards" in operation) {
    return [
      accountKey(sender),
      delegationKey(sender, operation.ClaimDelegatorRewards.validator),
    ];
  }
  if ("BridgeLock" in operation || "BridgeBurn" in operation) {
    const payload = "BridgeLock" in operation
      ? operation.BridgeLock
      : operation.BridgeBurn;
    const keys: StateKeyJson[] = [];
    if (payload.asset !== "NativeWebc") {
      keys.push(assetBalanceKey(payload.asset, sender));
    } else if ("BridgeLock" in operation) {
      keys.push(accountKey(sender));
      keys.push(bridgeEscrowKey(payload.destination_chain));
    }
    keys.push(protocolKey("BridgeNonce"));
    return keys;
  }
  // --- Native tokens (Phase 13a, §15) -------------------------------------
  if ("MintToken" in operation) {
    const { token_id, recipient } = operation.MintToken;
    return [tokenKey(token_id), tokenBalanceKey(token_id, recipient)];
  }
  if ("BurnToken" in operation) {
    const { token_id } = operation.BurnToken;
    return [tokenKey(token_id), tokenBalanceKey(token_id, sender)];
  }
  if ("TransferToken" in operation) {
    const { token_id, recipient } = operation.TransferToken;
    // The token record itself is READ-ONLY (see extraReadOnlyKeys); only the two
    // per-account balance keys are written, so an ordinary transfer never writes a
    // global per-token object.
    return [
      tokenBalanceKey(token_id, sender),
      tokenBalanceKey(token_id, recipient),
    ];
  }
  if ("SetTokenPaused" in operation) {
    return [tokenKey(operation.SetTokenPaused.token_id)];
  }
  if ("SetTokenAuthority" in operation) {
    return [tokenKey(operation.SetTokenAuthority.token_id)];
  }
  if ("FreezeTokenAccount" in operation) {
    const { token_id, account } = operation.FreezeTokenAccount;
    return [tokenFreezeKey(token_id, account)];
  }
  if ("ThawTokenAccount" in operation) {
    const { token_id, account } = operation.ThawTokenAccount;
    return [tokenFreezeKey(token_id, account)];
  }
  // --- Native NFTs (Phase 13b, §15) ---------------------------------------
  if ("MintNft" in operation) {
    // Only the collection record is written; the fresh item's serial is chain
    // assigned (unknown at signing) and created under the collection's write scope.
    return [nftCollectionKey(operation.MintNft.collection_id)];
  }
  if ("TransferNft" in operation) {
    const { collection_id, serial } = operation.TransferNft;
    return [nftItemKey(collection_id, serial)];
  }
  if ("BurnNft" in operation) {
    const { collection_id, serial } = operation.BurnNft;
    return [nftCollectionKey(collection_id), nftItemKey(collection_id, serial)];
  }
  if ("SetNftCollectionPaused" in operation) {
    return [nftCollectionKey(operation.SetNftCollectionPaused.collection_id)];
  }
  if ("SetNftAuthority" in operation) {
    return [nftCollectionKey(operation.SetNftAuthority.collection_id)];
  }
  if ("FreezeNftItem" in operation) {
    const { collection_id, serial } = operation.FreezeNftItem;
    return [nftItemKey(collection_id, serial)];
  }
  if ("ThawNftItem" in operation) {
    const { collection_id, serial } = operation.ThawNftItem;
    return [nftItemKey(collection_id, serial)];
  }
  // --- Native governance (Phase 13c, §15) — BASE lists --------------------
  // The state-derived extras (weight token, payout, escrow) are added by the
  // `accessListFor*` helpers; these are the base pushes from the Rust arms.
  if ("FundGovernanceTreasury" in operation) {
    const { instance_id } = operation.FundGovernanceTreasury;
    return [accountKey(sender), governanceInstanceKey(instance_id)];
  }
  if ("OpenProposal" in operation) {
    // The fresh proposal id is chain-assigned, created under the instance's write
    // scope; only the instance record is declared here.
    return [governanceInstanceKey(operation.OpenProposal.instance_id)];
  }
  if ("CastVote" in operation) {
    const { proposal_id } = operation.CastVote;
    return [
      governanceProposalKey(proposal_id),
      governanceVoteKey(proposal_id, sender),
    ];
  }
  if ("ResolveProposal" in operation) {
    return [governanceProposalKey(operation.ResolveProposal.proposal_id)];
  }
  if ("ExecuteProposal" in operation) {
    return [governanceProposalKey(operation.ExecuteProposal.proposal_id)];
  }
  if ("ReclaimVote" in operation) {
    return [governanceVoteKey(operation.ReclaimVote.proposal_id, sender)];
  }
  // --- Agent mandates (Phase 9a, §15.32) ----------------------------------
  if ("TopUpMandate" in operation) {
    return [accountKey(sender), mandateKey(operation.TopUpMandate.mandate_id)];
  }
  if ("RevokeMandate" in operation) {
    return [accountKey(sender), mandateKey(operation.RevokeMandate.mandate_id)];
  }
  if ("SpendUnderMandate" in operation) {
    const { mandate_id, recipient } = operation.SpendUnderMandate;
    return [accountKey(sender), mandateKey(mandate_id), accountKey(recipient)];
  }
  // --- Service registry (Phase 9b, §15.5) ---------------------------------
  if ("UpdateService" in operation) {
    return [serviceKey(operation.UpdateService.service_id)];
  }
  if ("SetServiceStatus" in operation) {
    return [serviceKey(operation.SetServiceStatus.service_id)];
  }
  if ("SpendUnderMandateToService" in operation) {
    // BASE list; the service OWNER account is added by accessListForServiceSpend.
    const { mandate_id } = operation.SpendUnderMandateToService;
    return [accountKey(sender), mandateKey(mandate_id)];
  }
  // --- Native oracle (Phase 7, §15.17) ------------------------------------
  if ("CreateFeed" in operation) {
    return [accountKey(sender), oracleFeedKey(operation.CreateFeed.feed_id)];
  }
  if ("RegisterReporter" in operation) {
    const { feed_id } = operation.RegisterReporter;
    return [accountKey(sender), oracleReporterKey(feed_id, sender)];
  }
  if ("DeregisterReporter" in operation) {
    const { feed_id } = operation.DeregisterReporter;
    return [accountKey(sender), oracleReporterKey(feed_id, sender)];
  }
  if ("SubmitReport" in operation) {
    // Reporting moves no native units: only the reporter record is written.
    return [oracleReporterKey(operation.SubmitReport.feed_id, sender)];
  }
  if ("PayFeedRead" in operation) {
    return [accountKey(sender), oracleFeedKey(operation.PayFeedRead.feed_id)];
  }
  // Incoming bridge messages need an asynchronous replay hash. Slashing also
  // needs live delegation/cooling owners, so the synchronous builder fails.
  // `CreateToken` needs an async token-id derivation, so it also lands here.
  throw new Error(
    "this operation requires defaultAccessListAsync or an explicit access list",
  );
}

function assembleAccessList(
  sender: WebcAddress,
  authorizationLane: AuthorizationLaneIdJson,
  extra: StateKeyJson[],
  extraReadOnly: StateKeyJson[] = [],
): StateAccessListJson {
  const readWrite = authorizationLane === DEFAULT_AUTHORIZATION_LANE
    ? [accountKey(sender)]
    : [authorizationLaneKey(sender, authorizationLane)];
  for (const key of extra) {
    pushUniqueKey(readWrite, key);
  }
  readWrite.push(feeAccumulatorKey(sender, authorizationLane));
  // Op-specific read-only keys (e.g. CreateGovernanceInstance's weight-token
  // existence read) sit between the base fee and the authorization policy, in the
  // Rust arm's insertion order.
  const readOnly: StateKeyJson[] = [protocolKey("BaseFee")];
  for (const key of extraReadOnly) {
    pushUniqueKey(readOnly, key);
  }
  pushUniqueKey(readOnly, authorizationPolicyKey(sender));
  return { read_only: readOnly, read_write: readWrite };
}

/** Returns the current state key for one native account. */
export function accountKey(address: WebcAddress): StateKeyJson {
  return { version: 1, kind: { Account: { address } } };
}

/** Returns the versioned signing/recovery policy key for one account. */
export function authorizationPolicyKey(owner: WebcAddress): StateKeyJson {
  return { version: 1, kind: { AuthorizationPolicy: { owner } } };
}

/** Returns the state key for one session key under an owning account. */
export function sessionKeyKey(
  owner: WebcAddress,
  sessionKey: SessionKeyIdJson,
): StateKeyJson {
  return { version: 1, kind: { SessionKey: { owner, session_key: sessionKey } } };
}

/**
 * Derives the opaque session-key id committing to a session public key:
 * `SHA-256("WEBC_SESSION_KEY_ID_V1" || session_public_key)`, lowercase hex. This
 * must match Rust `SessionKeyId::derive` so state keys agree across languages.
 */
export async function deriveSessionKeyIdHex(
  sessionPublicKeyHex: string,
): Promise<string> {
  const payload = concatBytes([
    SESSION_KEY_ID_DOMAIN,
    hexToBytes(sessionPublicKeyHex),
  ]);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toArrayBuffer(payload)),
  );
  return bytesToHex(digest);
}

/** Domains for id derivations — must match the Rust `*_ID_DOMAIN` constants. */
const TOKEN_ID_DOMAIN = new TextEncoder().encode("WEBC_TOKEN_ID_V1");
const NFT_COLLECTION_ID_DOMAIN = new TextEncoder().encode(
  "WEBC_NFT_COLLECTION_ID_V1",
);
const GOVERNANCE_INSTANCE_ID_DOMAIN = new TextEncoder().encode(
  "WEBC_GOV_INSTANCE_ID_V1",
);
const GOV_VOTE_ESCROW_DOMAIN = new TextEncoder().encode(
  "WEBC_GOV_VOTE_ESCROW_V1",
);
const MANDATE_ID_DOMAIN = new TextEncoder().encode("WEBC_MANDATE_ID_V1");
const SERVICE_ID_DOMAIN = new TextEncoder().encode("WEBC_SERVICE_ID_V1");

/** SHA-256 of concatenated byte parts, lowercase hex (Rust `Hash256::digest_many`). */
async function digestManyHex(parts: Uint8Array[]): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toArrayBuffer(concatBytes(parts))),
  );
  return bytesToHex(digest);
}

/**
 * Big-endian 8-byte encoding of a u64 nonce, matching Rust `u64::to_be_bytes`.
 * Rejects a nonce outside the JS safe-integer range before encoding.
 */
function nonceBe(nonce: number, label: string): Uint8Array {
  requireCountU64(nonce, label);
  return u64ToBytes(BigInt(nonce));
}

/**
 * Derives a `(namespace, creator, create_nonce)` id, mirroring the Rust
 * `TokenId`/`NftCollectionId`/`GovernanceInstanceId`/`ServiceId::derive`:
 * `SHA-256(domain || namespace || creator || create_nonce_be)`, lowercase hex.
 */
async function deriveNamespaceCreatorId(
  domain: Uint8Array,
  namespace: HexString,
  creator: WebcAddress,
  createNonce: number,
): Promise<string> {
  requireHash256Hex(namespace, "namespace");
  return digestManyHex([
    domain,
    hexToBytes(namespace),
    addressToBytes(creator),
    nonceBe(createNonce, "create nonce"),
  ]);
}

/** Derives a token id from `(namespace, creator, createNonce)`. */
export function deriveTokenIdHex(
  namespace: HexString,
  creator: WebcAddress,
  createNonce: number,
): Promise<string> {
  return deriveNamespaceCreatorId(
    TOKEN_ID_DOMAIN,
    namespace,
    creator,
    createNonce,
  );
}

/** Derives an NFT collection id from `(namespace, creator, createNonce)`. */
export function deriveNftCollectionIdHex(
  namespace: HexString,
  creator: WebcAddress,
  createNonce: number,
): Promise<string> {
  return deriveNamespaceCreatorId(
    NFT_COLLECTION_ID_DOMAIN,
    namespace,
    creator,
    createNonce,
  );
}

/** Derives a governance instance id from `(namespace, creator, createNonce)`. */
export function deriveGovernanceInstanceIdHex(
  namespace: HexString,
  creator: WebcAddress,
  createNonce: number,
): Promise<string> {
  return deriveNamespaceCreatorId(
    GOVERNANCE_INSTANCE_ID_DOMAIN,
    namespace,
    creator,
    createNonce,
  );
}

/**
 * Derives the deterministic per-proposal vote-lock escrow address, mirroring Rust
 * `gov_vote_escrow_address`: `Address(SHA-256("WEBC_GOV_VOTE_ESCROW_V1" ||
 * proposal_id))`, rendered `webc1...`. No keypair maps to it; the locked weight
 * moves only via the reclaim transition.
 */
export async function deriveGovVoteEscrowAddress(
  proposalId: HexString,
): Promise<WebcAddress> {
  requireHash256Hex(proposalId, "governance proposal id");
  const digestHex = await digestManyHex([
    GOV_VOTE_ESCROW_DOMAIN,
    hexToBytes(proposalId),
  ]);
  return addressFromBytes(hexToBytes(digestHex));
}

/**
 * Derives a mandate id from `(principal, agentKey, grantNonce)`, mirroring Rust
 * `MandateId::derive`: `SHA-256("WEBC_MANDATE_ID_V1" || principal || agent_key ||
 * grant_nonce_be)`, lowercase hex. The principal is the granting signer.
 */
export async function deriveMandateIdHex(
  principal: WebcAddress,
  agentKey: HexString,
  grantNonce: number,
): Promise<string> {
  requireHash256Hex(agentKey, "mandate agent key");
  return digestManyHex([
    MANDATE_ID_DOMAIN,
    addressToBytes(principal),
    hexToBytes(agentKey),
    nonceBe(grantNonce, "grant nonce"),
  ]);
}

/** Derives a service id from `(namespace, owner, createNonce)`. */
export function deriveServiceIdHex(
  namespace: HexString,
  owner: WebcAddress,
  createNonce: number,
): Promise<string> {
  return deriveNamespaceCreatorId(
    SERVICE_ID_DOMAIN,
    namespace,
    owner,
    createNonce,
  );
}

/**
 * Derives the fixed `key_hash` addressing an application's sponsor record:
 * `SHA-256("WEBC_SPONSOR_STATE_KEY_V1")`, lowercase hex. Must match Rust
 * `sponsorship::sponsor_state_key_hash`, so the sponsor state key agrees across
 * languages. The full key is `applicationKey(namespace, <this hash>)`.
 */
export async function sponsorStateKeyHashHex(): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      toArrayBuffer(SPONSOR_STATE_KEY_DISCRIMINANT),
    ),
  );
  return bytesToHex(digest);
}

/** Returns the application state key holding one app namespace's sponsor record. */
export async function sponsorStateKey(
  namespace: HexString,
): Promise<StateKeyJson> {
  validateSponsor(namespace);
  return applicationKey(namespace, await sponsorStateKeyHashHex());
}

/**
 * Builds the access list for a sponsored transaction, mirroring Rust
 * `Transaction::for_sponsored_operation`: the operation's default access list
 * plus the app's sponsor state key appended (deduplicated) to `read_write`. The
 * result is a superset covering both the sponsored and the self-pay fail-open
 * paths, so neither can trigger an undeclared-key failure.
 */
export async function sponsoredAccessListAsync(
  sender: WebcAddress,
  operation: OperationJson,
  sponsorNamespace: HexString,
  authorizationLane: AuthorizationLaneIdJson = DEFAULT_AUTHORIZATION_LANE,
): Promise<StateAccessListJson> {
  validateSponsor(sponsorNamespace);
  const base = await defaultAccessListAsync(sender, operation, authorizationLane);
  const sponsorKey = applicationKey(
    sponsorNamespace,
    await sponsorStateKeyHashHex(),
  );
  if (
    !base.read_write.some(
      (candidate) => canonicalKey(candidate) === canonicalKey(sponsorKey),
    )
  ) {
    base.read_write.push(sponsorKey);
  }
  return base;
}

/** Returns the current state key for one validator pool. */
export function validatorKey(operator: WebcAddress): StateKeyJson {
  return { version: 1, kind: { Validator: { operator } } };
}

/** Returns the current state key for one delegation position. */
export function delegationKey(
  delegator: WebcAddress,
  validator: WebcAddress,
): StateKeyJson {
  return { version: 1, kind: { Delegation: { delegator, validator } } };
}

/** Returns one non-native asset balance owned by an account. */
export function assetBalanceKey(
  asset: AssetIdJson,
  owner: WebcAddress,
): StateKeyJson {
  return { version: 1, kind: { AssetBalance: { asset, owner } } };
}

/** Returns the payer-scoped fee delta key. */
export function authorizationLaneKey(
  owner: WebcAddress,
  lane: AuthorizationLaneIdJson,
): StateKeyJson {
  return { version: 1, kind: { AuthorizationLane: { owner, lane } } };
}

/** Returns the lane-scoped fee delta key. */
export function feeAccumulatorKey(
  payer: WebcAddress,
  lane: AuthorizationLaneIdJson = DEFAULT_AUTHORIZATION_LANE,
): StateKeyJson {
  return { version: 1, kind: { FeeAccumulator: { payer, lane } } };
}

/** Returns the logical queue key for one validator's exit requests. */
export function unbondingQueueKey(validator: WebcAddress): StateKeyJson {
  return { version: 1, kind: { UnbondingQueue: { validator } } };
}

/** Returns the replay marker for one canonical bridge-message hash. */
export function bridgeMessageKey(messageHash: string): StateKeyJson {
  return {
    version: 1,
    kind: { BridgeMessage: { message_hash: messageHash } },
  };
}

/** Returns native WEBC escrow isolated to one external bridge domain. */
export function bridgeEscrowKey(domain: ExternalChainJson): StateKeyJson {
  return { version: 1, kind: { BridgeEscrow: { domain } } };
}

/** Returns one persistent object state key. */
export function objectKey(objectId: string): StateKeyJson {
  return { version: 1, kind: { Object: { object_id: objectId } } };
}

/** Returns one application-local key under its namespace. */
export function applicationKey(namespace: string, keyHash: string): StateKeyJson {
  return {
    version: 1,
    kind: { Application: { namespace, key_hash: keyHash } },
  };
}

// --- Native token state keys (Phase 13a, §15) ------------------------------

/** Returns the authority/supply record key for one token. */
export function tokenKey(tokenId: HexString): StateKeyJson {
  return { version: 1, kind: { Token: { token_id: tokenId } } };
}

/** Returns the per-`(token, owner)` balance key. */
export function tokenBalanceKey(
  tokenId: HexString,
  owner: WebcAddress,
): StateKeyJson {
  return { version: 1, kind: { TokenBalance: { token_id: tokenId, owner } } };
}

/** Returns the per-`(token, account)` freeze marker key. */
export function tokenFreezeKey(
  tokenId: HexString,
  account: WebcAddress,
): StateKeyJson {
  return { version: 1, kind: { TokenFreeze: { token_id: tokenId, account } } };
}

// --- Native NFT state keys (Phase 13b, §15) --------------------------------

/** Returns the authority/supply record key for one collection. */
export function nftCollectionKey(collectionId: HexString): StateKeyJson {
  return {
    version: 1,
    kind: { NftCollection: { collection_id: collectionId } },
  };
}

/** Returns the per-`(collection, serial)` item key. */
export function nftItemKey(
  collectionId: HexString,
  serial: number,
): StateKeyJson {
  return {
    version: 1,
    kind: { NftItem: { collection_id: collectionId, serial } },
  };
}

// --- Native governance state keys (Phase 13c, §15) -------------------------

/** Returns the authority/treasury record key for one instance. */
export function governanceInstanceKey(instanceId: HexString): StateKeyJson {
  return {
    version: 1,
    kind: { GovernanceInstance: { instance_id: instanceId } },
  };
}

/** Returns the tally/status record key for one proposal. */
export function governanceProposalKey(proposalId: HexString): StateKeyJson {
  return {
    version: 1,
    kind: { GovernanceProposal: { proposal_id: proposalId } },
  };
}

/** Returns the per-`(proposal, voter)` vote-lock key. */
export function governanceVoteKey(
  proposalId: HexString,
  voter: WebcAddress,
): StateKeyJson {
  return {
    version: 1,
    kind: { GovernanceVote: { proposal_id: proposalId, voter } },
  };
}

// --- Agent mandate state key (Phase 9a, §15.32) ----------------------------

/** Returns the record key for one agent mandate. */
export function mandateKey(mandateId: HexString): StateKeyJson {
  return { version: 1, kind: { Mandate: { mandate_id: mandateId } } };
}

// --- Service registry state key (Phase 9b, §15.5) --------------------------

/** Returns the registry-entry key for one service. */
export function serviceKey(serviceId: HexString): StateKeyJson {
  return { version: 1, kind: { Service: { service_id: serviceId } } };
}

// --- Native oracle state keys (Phase 7, §15.17) ----------------------------

/** Returns the feed-registry record key for one feed. */
export function oracleFeedKey(feedId: HexString): StateKeyJson {
  return { version: 1, kind: { OracleFeed: { feed_id: feedId } } };
}

/** Returns the per-`(feed, reporter)` bonded-reporter record key. */
export function oracleReporterKey(
  feedId: HexString,
  reporter: WebcAddress,
): StateKeyJson {
  return {
    version: 1,
    kind: { OracleReporter: { feed_id: feedId, reporter } },
  };
}

/** Returns a protocol singleton key in schema version 1. */
export function protocolKey(
  field: "BaseFee" | "BridgeNonce",
): StateKeyJson {
  return { version: 1, kind: { Protocol: { field } } };
}

function canonicalKey(key: StateKeyJson): string {
  return JSON.stringify(key);
}

function feeWireJson(fee: FeeBid): FeeBidJson {
  return {
    gas_limit: fee.gasLimit,
    max_fee_per_unit: fee.maxFeePerUnit,
    priority_fee_per_unit: fee.priorityFeePerUnit,
  };
}
