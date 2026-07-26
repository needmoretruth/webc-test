/**
 * Protocol-version-2 transaction wire construction and verification.
 *
 * This module mirrors Rust `webc_chain::transaction_v5`. It owns the immutable
 * V5 JSON shapes, exact decimal-u64 validation, sender/sponsor signing payloads,
 * transaction identifiers, and hostile-input byte/count limits. It does not
 * submit transactions, decide mempool policy, validate on-chain authorization,
 * or activate protocol version 2. Existing V4 APIs remain unchanged.
 *
 * Security boundary: every signature/hash uses an explicit domain, all new u64
 * fields are canonical decimal strings, and a transaction is bounded to 32
 * actions and 256 KiB before parsing/signature work.
 */

import { addressToBytes } from "./address.js";
import { canonicalJsonBytes, canonicalJsonHashHex } from "./canonical.js";
import { bytesToHex, hexToBytes } from "./hex.js";
import type {
  FeeBid,
  OperationJson,
  PostQuantumRootRevealJson,
  StateAccessListJson,
  StateKeyJson,
  WebcAddress,
} from "./types.js";
import { deriveSessionKeyIdHex, sessionKeyKey } from "./transaction.js";
import type { WebcWallet } from "./wallet.js";
import { signWithWallet, verifyEd25519 } from "./wallet.js";

/** Protocol configuration that interprets V5 transactions. */
export const TRANSACTION_V5_PROTOCOL_VERSION = 2;
/** Sender-signature domain matching Rust. */
export const TRANSACTION_V5_SIGNING_DOMAIN = "WEBC_SIGNED_TRANSACTION_V5";
/** Complete signed-transaction identifier domain matching Rust. */
export const TRANSACTION_ID_V1_DOMAIN = "WEBC_TRANSACTION_ID_V1";
/** Ordered action/cancellation digest domain matching Rust. */
export const ACTION_PROGRAM_V1_DOMAIN = "WEBC_ACTION_PROGRAM_V1";
/** Exact fee-bid digest domain matching Rust. */
export const FEE_BID_V1_DOMAIN = "WEBC_FEE_BID_V1";
/** Immutable sponsor-grant signature/digest domain matching Rust. */
export const SPONSOR_GRANT_V1_DOMAIN = "WEBC_SPONSOR_GRANT_V1";
/** Replay-bounded sponsor-use digest domain matching Rust. */
export const SPONSOR_USE_V1_DOMAIN = "WEBC_SPONSOR_USE_V1";
/** Post-quantum root-signature domain for one exact staking-control action. */
export const STAKING_CONTROL_AUTHORIZATION_V1_DOMAIN =
  "WEBC_STAKING_CONTROL_AUTHORIZATION_V1";

/** Maximum ordered actions in one V1 action program. */
export const MAX_ACTIONS_V1 = 32;
/** Maximum decoded bytes stored in one native object payload. */
export const MAX_OBJECT_DATA_BYTES_V1 = 64 * 1024;
/** Maximum UTF-8 bytes accepted for a complete V5 transaction. */
export const MAX_TRANSACTION_V5_CANONICAL_BYTES = 256 * 1024;
/** Maximum block heights covered by the inclusive validity range. */
export const MAX_TRANSACTION_VALIDITY_BLOCKS = 4096n;
/** Fixed Rust-parity units for a V5 cancellation. */
export const CANCEL_V1_REQUIRED_UNITS = 50n;
/** Fixed Rust-parity units for an ID-only materialized grant revocation. */
export const REVOKE_SPONSOR_GRANT_V1_REQUIRED_UNITS = 5_000n;
/** Conservative units for a complete signed-grant revocation. */
export const REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS = 100_000n;
/** Conservative bookkeeping units added to every sponsored transaction. */
export const SPONSOR_GRANT_USE_V1_REQUIRED_UNITS = 100_000n;
/** Conservative units for one post-quantum staking authorization verification. */
export const STAKING_CONTROL_AUTHORIZATION_V1_REQUIRED_UNITS = 100_000n;
/** Hostile-input ceiling for each post-quantum reveal component. */
export const MAX_POST_QUANTUM_REVEAL_COMPONENT_BYTES_V1 = 4_096;

const U64_MAX = (1n << 64n) - 1n;
const U128_MAX = (1n << 128n) - 1n;
const MAX_TRANSACTION_STATE_KEYS = 256;
const SUPPORTED_NATIVE_ACTIONS_V1 = new Set([
  "Transfer",
  "InstallAuthorizationPolicy",
  "OpenAuthorizationLane",
  "FundAuthorizationLane",
  "ClaimDelegatorRewards",
  "ClaimUnbonded",
  "CreateObject",
  "MutateObject",
  "TransferObject",
  "DeleteObject",
]);

/** Canonical unsigned decimal string whose value is within Rust `u64`. */
export type DecimalU64 = string;

/** Exact fee-bid wire object; every field is a decimal string. */
export interface FeeBidV5Json {
  /** Maximum execution units authorized by the sender. */
  gas_limit: DecimalU64;
  /** Maximum native base units paid per execution unit. */
  max_fee_per_unit: DecimalU64;
  /** Optional validator priority rate per execution unit. */
  priority_fee_per_unit: DecimalU64;
}

/** Inclusive signed block-height range. */
export interface ValidityWindowV1Json {
  /** First block height at which the artifact may be included. */
  valid_from_height: DecimalU64;
  /** Last block height at which the artifact may be included. */
  valid_until_height: DecimalU64;
}

/** Sender authorization coordinates in one V5 transaction. */
export interface TransactionAuthorizationV1Json {
  /** Lowercase 32-byte authorization lane. */
  lane: string;
  /** Account-policy revision, encoded exactly as decimal u64. */
  policy_revision: DecimalU64;
  /** Replay nonce in `lane`, encoded exactly as decimal u64. */
  nonce: DecimalU64;
}

/** Critical staking payload authorized separately by the post-quantum root. */
export type StakingActionV1Json =
  | {
      RegisterValidator: {
        /** Ed25519 consensus public key, lowercase hex. */
        consensus_key: string;
        /** Operator collateral in native base units. */
        self_stake: string;
        /** Commission in basis points, from 0 through 10,000. */
        commission_bps: number;
      };
    }
  | { Delegate: { validator: WebcAddress; amount: string } }
  | { Undelegate: { validator: WebcAddress; amount: string } }
  | { UnstakeValidator: { amount: string } };

/** Inputs bound into one root-signature message for ordered staking control. */
export interface StakingControlAuthorizationRequestV1 {
  /** Canonical network identifier. */
  chainId: string;
  /** Account whose stake is controlled. */
  owner: WebcAddress;
  /** Current installed account-policy revision. */
  policyRevision: DecimalU64;
  /** Must be the all-zero default authorization lane. */
  lane: string;
  /** Default-lane transaction nonce. */
  nonce: DecimalU64;
  /** Zero-based position in the containing action program. */
  actionIndex: number;
  /** Exact staking transition being authorized. */
  action: StakingActionV1Json;
}

/** One ordered V1 action wrapping an existing native operation. */
export type ActionV1Json =
  | { Native: { operation: OperationJson } }
  | {
      StakingControl: {
        /** Exact staking payload bound into the root signature. */
        action: StakingActionV1Json;
        /** Current installed root's bounded public-key reveal and signature. */
        post_quantum_root_reveal: PostQuantumRootRevealJson;
      };
    }
  | { RevokeSponsorGrant: { grant_id: string } }
  | { RevokeSignedSponsorGrant: { grant: SponsorGrantV1Json } };

/** Non-empty bounded ordered action program. */
export interface ActionProgramV1Json {
  /** One through 32 atomic native actions. */
  actions: ActionV1Json[];
}

/** Top-level action or no-effect cancellation form. */
export type TransactionKindV1Json =
  | { Actions: ActionProgramV1Json }
  | { Cancel: Record<string, never> };

/** Returns the exact static units used by Rust V5 preparation and receipts. */
export function transactionV5RequiredUnits(
  kind: TransactionKindV1Json,
  feePayment: FeePaymentV1Json,
): bigint {
  validateKind(kind);
  validateFeePaymentShape(feePayment);
  if (feePayment !== "SenderLane" && !transactionKindV1IsSponsorable(kind)) {
    throw new Error("V5 sponsorship permits exactly one native transfer action");
  }
  let units = "Cancel" in kind
    ? CANCEL_V1_REQUIRED_UNITS
    : kind.Actions.actions.reduce((total, action) => {
        if ("RevokeSponsorGrant" in action) {
          return total + REVOKE_SPONSOR_GRANT_V1_REQUIRED_UNITS;
        }
        if ("RevokeSignedSponsorGrant" in action) {
          return total + REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS;
        }
        if ("StakingControl" in action) {
          return total + STAKING_CONTROL_AUTHORIZATION_V1_REQUIRED_UNITS
            + stakingTransitionRequiredUnits(action.StakingControl.action);
        }
        return total + nativeActionRequiredUnits(action.Native.operation);
      }, 0n);
  if (feePayment !== "SenderLane") units += SPONSOR_GRANT_USE_V1_REQUIRED_UNITS;
  return units;
}

/** Exact action/cancellation digest authorized by a sponsor. */
export interface ActionScopeV1Json {
  /** SHA-256 digest under `ACTION_PROGRAM_V1_DOMAIN`. */
  exact_action_digest: string;
}

/** Immutable grant signed independently by the sponsor. */
export interface SponsorGrantV1Json {
  /** Exactly protocol version 2. */
  protocol_version: 2;
  /** Canonical lowercase WEBC chain identifier. */
  chain_id: string;
  /** Non-zero lowercase 32-byte grant identity. */
  grant_id: string;
  /** Fee-paying account. */
  sponsor: WebcAddress;
  /** Lowercase Ed25519 key checked against sponsor policy by state. */
  sponsor_public_key: string;
  /** Sponsor-owned lowercase 32-byte fee lane. */
  payer_lane: string;
  /** Sole sender permitted to consume the grant. */
  sender: WebcAddress;
  /** Optional 32-byte hash of a wallet-validated site origin. */
  site_namespace: string | null;
  /** Optional on-chain application namespace hash. */
  application_namespace: string | null;
  /** Exact action scope permitted by the grant. */
  action_scope: ActionScopeV1Json;
  /** Inclusive consensus-height grant lifetime. */
  validity: ValidityWindowV1Json;
  /** Maximum native base units charged by one use, decimal u128. */
  max_fee_per_transaction: string;
  /** Maximum cumulative native base units charged, decimal u128. */
  max_cumulative_fee: string;
  /** Maximum grant uses, decimal u64. */
  max_uses: DecimalU64;
  /** Lowercase Ed25519 signature, or null before sponsor signing. */
  sponsor_signature: string | null;
}

/** One exact replay-bounded use of a sponsor grant. */
export interface SponsorUseV1Json {
  /** Complete immutable signed grant. */
  grant: SponsorGrantV1Json;
  /** Digest of the complete signed grant. */
  grant_digest: string;
  /** Strictly increasing durable use nonce, decimal u64. */
  use_nonce: DecimalU64;
  /** Exact action/cancellation digest being sponsored. */
  action_digest: string;
  /** Exact fee-bid digest being sponsored. */
  fee_bid_digest: string;
}

/** Fee-paying authority for one V5 transaction. */
export type FeePaymentV1Json =
  | "SenderLane"
  | { Sponsored: SponsorUseV1Json };

/** Unsigned V5 envelope used only inside a trusted wallet. */
export interface UnsignedTransactionV5Json {
  /** Exactly protocol version 2. */
  protocol_version: 2;
  /** Canonical lowercase WEBC chain identifier. */
  chain_id: string;
  /** Sender account whose nonce/actions are authorized. */
  sender: WebcAddress;
  /** Lowercase Ed25519 public key used for this signature. */
  sender_public_key: string;
  /** Authorization lane, policy revision, and nonce. */
  authorization: TransactionAuthorizationV1Json;
  /** Inclusive consensus-height validity. */
  validity: ValidityWindowV1Json;
  /** Ordered actions or cancellation. */
  kind: TransactionKindV1Json;
  /** Exact logical state declaration. */
  access_list: StateAccessListJson;
  /** Exact string-encoded fee bid. */
  fee_bid: FeeBidV5Json;
  /** Sender lane or scoped sponsor payment. */
  fee_payment: FeePaymentV1Json;
  /** Always null before signing. */
  sender_signature: null;
}

/** Complete signed V5 transaction accepted by Rust's V5 decoder. */
export interface SignedTransactionV5Json
  extends Omit<UnsignedTransactionV5Json, "sender_signature"> {
  /** Lowercase 64-byte Ed25519 signature over the V5 signing payload. */
  sender_signature: string;
}

/** Fields a trusted wallet needs to construct/sign one V5 transaction. */
export interface TransactionV5SignRequest {
  /** Canonical lowercase WEBC chain identifier. */
  chainId: string;
  /** Sender authorization coordinates. */
  authorization: TransactionAuthorizationV1Json;
  /** Inclusive consensus-height validity. */
  validity: ValidityWindowV1Json;
  /** Ordered actions or cancellation. */
  kind: TransactionKindV1Json;
  /** Exact declared state access derived by the wallet/node builder. */
  accessList: StateAccessListJson;
  /** Exact string fee bid. */
  feeBid: FeeBidV5Json;
  /** Sender or sponsor fee authority. */
  feePayment: FeePaymentV1Json;
}

/** Wraps one through 32 existing native operations as ordered V1 actions. */
export function actionProgramV1(operations: OperationJson[]): TransactionKindV1Json {
  if (operations.length === 0 || operations.length > MAX_ACTIONS_V1) {
    throw new Error("V5 action program must contain between 1 and 32 actions");
  }
  for (const operation of operations) validateNativeActionV1(operation);
  return {
    Actions: {
      actions: operations.map((operation) => ({ Native: { operation } })),
    },
  };
}

/** Returns whether protocol sponsorship may pay for this exact V5 form. */
export function transactionKindV1IsSponsorable(kind: TransactionKindV1Json): boolean {
  validateKind(kind);
  if (!("Actions" in kind) || kind.Actions.actions.length !== 1) return false;
  const action = kind.Actions.actions[0];
  if (action === undefined || !("Native" in action)) return false;
  const operation = action.Native.operation;
  return typeof operation === "object"
    && operation !== null
    && Object.keys(operation).length === 1
    && "Transfer" in operation;
}

/**
 * Returns the canonical bytes the current post-quantum root must sign for one
 * exact staking-control action.
 *
 * The root signature is bound to the chain, owner, current policy revision,
 * default lane, transaction nonce, ordered action index, and complete payload.
 * The SDK only constructs these bytes; ML-DSA signing stays in a dedicated
 * recovery signer and stateful verification stays in the Rust node.
 */
export function stakingControlAuthorizationMessageV1(
  request: StakingControlAuthorizationRequestV1,
): Uint8Array {
  requireChainId(request.chainId);
  requireAddress(request.owner, "staking-control owner");
  requireU64(request.policyRevision, "staking-control policy revision");
  requireHex(request.lane, 32, "staking-control lane", false);
  if (request.lane !== "00".repeat(32)) {
    throw new Error("V5 staking control requires the default authorization lane");
  }
  requireU64(request.nonce, "staking-control nonce");
  if (!Number.isSafeInteger(request.actionIndex)
    || request.actionIndex < 0
    || request.actionIndex >= MAX_ACTIONS_V1) {
    throw new Error("V5 staking-control action index is outside the action program");
  }
  validateStakingActionV1(request.action);
  return canonicalJsonBytes({
    domain: STAKING_CONTROL_AUTHORIZATION_V1_DOMAIN,
    protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
    chain_id: request.chainId,
    owner: request.owner,
    policy_revision: request.policyRevision,
    lane: request.lane,
    nonce: request.nonce,
    action_index: request.actionIndex,
    action: request.action,
  });
}

/** Constructs one V5 critical staking action with its exact root reveal. */
export function stakingControlActionV1(
  action: StakingActionV1Json,
  postQuantumRootReveal: PostQuantumRootRevealJson,
): ActionV1Json {
  validateStakingActionV1(action);
  validatePostQuantumRootRevealV1(postQuantumRootReveal);
  return {
    StakingControl: {
      action,
      post_quantum_root_reveal: postQuantumRootReveal,
    },
  };
}

/** Constructs a protocol-2 action that permanently revokes one sponsor grant. */
export function revokeSponsorGrantActionV1(grantId: string): ActionV1Json {
  requireHex(grantId, 32, "sponsor grant id", true);
  return { RevokeSponsorGrant: { grant_id: grantId } };
}

/** Constructs a pre-use revocation carrying authenticated grant lifetime. */
export function revokeSignedSponsorGrantActionV1(
  grant: SponsorGrantV1Json,
): ActionV1Json {
  validateSponsorGrant(grant, true);
  return { RevokeSignedSponsorGrant: { grant } };
}

/** Constructs the signed no-effect cancellation form. */
export function cancelV1(): TransactionKindV1Json {
  return { Cancel: {} };
}

/** Converts the legacy ergonomic number bid into exact V5 decimal strings. */
export function feeBidV5(fee: FeeBid): FeeBidV5Json {
  for (const [label, value] of Object.entries(fee)) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative safe integer`);
    }
  }
  const wire = {
    gas_limit: fee.gasLimit.toString(),
    max_fee_per_unit: fee.maxFeePerUnit.toString(),
    priority_fee_per_unit: fee.priorityFeePerUnit.toString(),
  };
  validateFeeBid(wire);
  return wire;
}

/** Adds the writable cumulative-budget key required by V5 session authorization.
 *
 * `baseAccess` must already be the exact account-key or sponsored action union
 * for a transfer-only action program. The helper preserves its reviewed Rust
 * ordering and inserts `SessionKey` between fee-accumulator and later protocol
 * variants, matching Rust `StateKeyKind` discriminants. Supplying an existing
 * session key fails closed instead of silently signing ambiguous authority.
 */
export async function sessionAuthorizationAccessListV1(
  baseAccess: StateAccessListJson,
  sender: WebcAddress,
  sessionPublicKey: string,
): Promise<StateAccessListJson> {
  validateAccessList(baseAccess);
  requireAddress(sender, "session owner");
  requireHex(sessionPublicKey, 32, "session public key", false);
  const sessionId = await deriveSessionKeyIdHex(sessionPublicKey);
  const sessionState = sessionKeyKey(sender, sessionId);
  const allKeys = [...baseAccess.read_only, ...baseAccess.read_write];
  if (allKeys.some((key) => stateKeyVariantName(key) === "SessionKey")) {
    throw new Error("V5 base access already contains session-key state");
  }

  const readWrite = [...baseAccess.read_write];
  const sessionRank = stateKeyVariantRank(sessionState);
  const insertion = readWrite.findIndex(
    (key) => stateKeyVariantRank(key) > sessionRank,
  );
  if (insertion === -1) readWrite.push(sessionState);
  else readWrite.splice(insertion, 0, sessionState);
  const result = { read_only: [...baseAccess.read_only], read_write: readWrite };
  validateAccessList(result);
  return result;
}

/** Builds an unsigned V5 transaction and validates every stateless bound. */
export function createUnsignedTransactionV5(
  wallet: WebcWallet,
  request: TransactionV5SignRequest,
): UnsignedTransactionV5Json {
  const transaction: UnsignedTransactionV5Json = {
    protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
    chain_id: request.chainId,
    sender: wallet.address,
    sender_public_key: bytesToHex(wallet.publicKey),
    authorization: request.authorization,
    validity: request.validity,
    kind: request.kind,
    access_list: request.accessList,
    fee_bid: request.feeBid,
    fee_payment: request.feePayment,
    sender_signature: null,
  };
  validateTransactionV5Structure(transaction);
  return transaction;
}

/** Constructs and signs one V5 transaction with the trusted wallet key. */
export async function signTransactionV5(
  wallet: WebcWallet,
  request: TransactionV5SignRequest,
): Promise<SignedTransactionV5Json> {
  const unsigned = createUnsignedTransactionV5(wallet, request);
  // Wallets must never approve an envelope containing an invalid nested grant.
  // This preflight happens before the trusted key is invoked, matching Rust.
  if (!(await validateSponsorIntentConsistency(unsigned))) {
    throw new Error("conflicting V5 sponsor grant identities");
  }
  if (!(await validateFeePaymentBinding(unsigned))) {
    throw new Error("invalid V5 sponsor fee-payment binding");
  }
  if (!(await validateSignedRevocationBindings(unsigned))) {
    throw new Error("invalid V5 nested sponsor revocation");
  }
  const signature = await signWithWallet(
    wallet,
    transactionV5SigningBytes(unsigned),
  );
  const signed: SignedTransactionV5Json = {
    ...unsigned,
    sender_signature: bytesToHex(signature),
  };
  validateTransactionV5Structure(signed);
  return signed;
}

/** Returns canonical sender-signing bytes matching Rust byte-for-byte. */
export function transactionV5SigningBytes(
  transaction: UnsignedTransactionV5Json | SignedTransactionV5Json,
): Uint8Array {
  return canonicalJsonBytes({
    domain: TRANSACTION_V5_SIGNING_DOMAIN,
    protocol_version: transaction.protocol_version,
    chain_id: transaction.chain_id,
    sender: transaction.sender,
    sender_public_key: transaction.sender_public_key,
    authorization: transaction.authorization,
    validity: transaction.validity,
    kind: transaction.kind,
    access_list: transaction.access_list,
    fee_bid: transaction.fee_bid,
    fee_payment: transaction.fee_payment,
  });
}

/** Computes the domain-separated ID of a complete signed V5 transaction. */
export function transactionV5IdHex(
  transaction: SignedTransactionV5Json,
): Promise<string> {
  return canonicalJsonHashHex({
    domain: TRANSACTION_ID_V1_DOMAIN,
    transaction,
  });
}

/** Computes the exact ordered action/cancellation digest. */
export function transactionKindV1DigestHex(
  kind: TransactionKindV1Json,
): Promise<string> {
  validateKind(kind);
  return canonicalJsonHashHex({ domain: ACTION_PROGRAM_V1_DOMAIN, kind });
}

/** Computes the exact string-encoded V5 fee-bid digest. */
export function feeBidV1DigestHex(feeBid: FeeBidV5Json): Promise<string> {
  validateFeeBid(feeBid);
  return canonicalJsonHashHex({ domain: FEE_BID_V1_DOMAIN, fee_bid: feeBid });
}

/** Signs an immutable sponsor grant with an address-derived wallet key. */
export async function signSponsorGrantV1(
  wallet: WebcWallet,
  grant: Omit<
    SponsorGrantV1Json,
    "protocol_version" | "sponsor" | "sponsor_public_key" | "sponsor_signature"
  >,
): Promise<SponsorGrantV1Json> {
  const unsigned: SponsorGrantV1Json = {
    protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
    ...grant,
    sponsor: wallet.address,
    sponsor_public_key: bytesToHex(wallet.publicKey),
    sponsor_signature: null,
  };
  validateSponsorGrant(unsigned, false);
  const signature = await signWithWallet(wallet, sponsorGrantSigningBytes(unsigned));
  return { ...unsigned, sponsor_signature: bytesToHex(signature) };
}

/** Returns sponsor-signing bytes matching Rust byte-for-byte. */
export function sponsorGrantSigningBytes(grant: SponsorGrantV1Json): Uint8Array {
  return canonicalJsonBytes({
    domain: SPONSOR_GRANT_V1_DOMAIN,
    protocol_version: grant.protocol_version,
    chain_id: grant.chain_id,
    grant_id: grant.grant_id,
    sponsor: grant.sponsor,
    sponsor_public_key: grant.sponsor_public_key,
    payer_lane: grant.payer_lane,
    sender: grant.sender,
    site_namespace: grant.site_namespace,
    application_namespace: grant.application_namespace,
    action_scope: grant.action_scope,
    validity: grant.validity,
    max_fee_per_transaction: grant.max_fee_per_transaction,
    max_cumulative_fee: grant.max_cumulative_fee,
    max_uses: grant.max_uses,
  });
}

/** Verifies an immutable sponsor grant's structure and Ed25519 signature. */
export async function verifySponsorGrantV1(
  grant: SponsorGrantV1Json,
): Promise<boolean> {
  try {
    validateSponsorGrant(grant, true);
    return verifyEd25519(
      hexToBytes(grant.sponsor_public_key),
      sponsorGrantSigningBytes(grant),
      hexToBytes(grant.sponsor_signature as string),
    );
  } catch {
    return false;
  }
}

/** Returns the domain-separated digest of a complete signed sponsor grant. */
export function sponsorGrantV1DigestHex(
  grant: SponsorGrantV1Json,
): Promise<string> {
  validateSponsorGrant(grant, true);
  return canonicalJsonHashHex({ domain: SPONSOR_GRANT_V1_DOMAIN, grant });
}

/** Binds a signed grant and one use nonce to exact actions and fee bid. */
export async function createSponsorUseV1(
  grant: SponsorGrantV1Json,
  useNonce: DecimalU64,
  kind: TransactionKindV1Json,
  feeBid: FeeBidV5Json,
): Promise<SponsorUseV1Json> {
  validateSponsorGrant(grant, true);
  requireU64(useNonce, "sponsor use nonce");
  if (!transactionKindV1IsSponsorable(kind)) {
    throw new Error("V5 sponsorship permits exactly one native transfer action");
  }
  return {
    grant,
    grant_digest: await sponsorGrantV1DigestHex(grant),
    use_nonce: useNonce,
    action_digest: await transactionKindV1DigestHex(kind),
    fee_bid_digest: await feeBidV1DigestHex(feeBid),
  };
}

/** Computes the domain-separated digest of one replay-bounded sponsor use. */
export function sponsorUseV1DigestHex(use: SponsorUseV1Json): Promise<string> {
  return canonicalJsonHashHex({ domain: SPONSOR_USE_V1_DOMAIN, sponsor_use: use });
}

/**
 * Verifies structure, expected chain, sponsor binding/signature, and sender signature.
 *
 * Stateful account-policy, nonce, balance, grant-budget, and revocation checks
 * remain the node's responsibility. Any malformed or cryptographic failure
 * returns `false` without exposing internal details.
 */
export async function verifySignedTransactionV5(
  transaction: SignedTransactionV5Json,
  expectedChainId = transaction.chain_id,
): Promise<boolean> {
  try {
    validateTransactionV5Structure(transaction);
    if (transaction.chain_id !== expectedChainId) return false;
    // Authenticate the cheap outer sender signature before up to 32 nested
    // sponsor signatures, preventing invalid-envelope CPU amplification.
    if (!(await verifyEd25519(
      hexToBytes(transaction.sender_public_key),
      transactionV5SigningBytes(transaction),
      hexToBytes(transaction.sender_signature),
    ))) return false;
    if (!(await validateSponsorIntentConsistency(transaction))) return false;
    if (!(await validateFeePaymentBinding(transaction))) return false;
    if (!(await validateSignedRevocationBindings(transaction))) return false;
    return true;
  } catch {
    return false;
  }
}

/** Parses a bounded UTF-8 JSON body and validates its strict V5 structure. */
export function parseTransactionV5Json(bytes: Uint8Array): SignedTransactionV5Json {
  if (bytes.byteLength > MAX_TRANSACTION_V5_CANONICAL_BYTES) {
    throw new Error("V5 transaction exceeds the 256 KiB limit");
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const value = JSON.parse(text) as unknown;
  validateTransactionV5Structure(value);
  const transaction = value as SignedTransactionV5Json;
  if (transaction.sender_signature === null) {
    throw new Error("V5 signed transaction is missing its sender signature");
  }
  return transaction;
}

/** Validates strict V5 shape/count/integer/size bounds and throws on failure. */
export function validateTransactionV5Structure(
  value: unknown,
): asserts value is UnsignedTransactionV5Json | SignedTransactionV5Json {
  requireRecord(value, "V5 transaction");
  requireExactKeys(value, [
    "protocol_version",
    "chain_id",
    "sender",
    "sender_public_key",
    "authorization",
    "validity",
    "kind",
    "access_list",
    "fee_bid",
    "fee_payment",
    "sender_signature",
  ], "V5 transaction");
  if (value.protocol_version !== TRANSACTION_V5_PROTOCOL_VERSION) {
    throw new Error("unsupported V5 protocol version");
  }
  requireChainId(value.chain_id);
  requireAddress(value.sender, "sender");
  requireHex(value.sender_public_key, 32, "sender public key", false);
  validateAuthorization(value.authorization);
  validateValidity(value.validity);
  validateKind(value.kind);
  if (kindContainsStakingControl(value.kind)
    && value.authorization.lane !== "00".repeat(32)) {
    throw new Error("V5 staking control requires the default authorization lane");
  }
  validateAccessList(value.access_list);
  validateFeeBid(value.fee_bid);
  validateFeePaymentShape(value.fee_payment);
  if (value.fee_payment !== "SenderLane"
    && !transactionKindV1IsSponsorable(value.kind)) {
    throw new Error("V5 sponsorship permits exactly one native transfer action");
  }
  if (value.fee_payment !== "SenderLane"
    && value.fee_payment.Sponsored.grant.application_namespace !== null
    && !kindMatchesApplicationNamespace(
      value.kind,
      value.fee_payment.Sponsored.grant.application_namespace,
    )) {
    throw new Error("sponsor application namespace does not match V5 object actions");
  }
  if (value.sender_signature !== null) {
    requireHex(value.sender_signature, 64, "sender signature", false);
  }
  if (canonicalJsonBytes(value).byteLength > MAX_TRANSACTION_V5_CANONICAL_BYTES) {
    throw new Error("V5 transaction exceeds the 256 KiB limit");
  }
}

async function validateFeePaymentBinding(
  transaction: UnsignedTransactionV5Json | SignedTransactionV5Json,
): Promise<boolean> {
  if (transaction.fee_payment === "SenderLane") return true;
  if (!transactionKindV1IsSponsorable(transaction.kind)) return false;
  const use = transaction.fee_payment.Sponsored;
  if (!(await verifySponsorGrantV1(use.grant))) return false;
  if (
    use.grant.chain_id !== transaction.chain_id ||
    use.grant.sender !== transaction.sender ||
    !(await digestEquals(use.grant_digest, sponsorGrantV1DigestHex(use.grant))) ||
    !(await digestEquals(use.action_digest, transactionKindV1DigestHex(transaction.kind))) ||
    use.grant.action_scope.exact_action_digest !== use.action_digest ||
    !(await digestEquals(use.fee_bid_digest, feeBidV1DigestHex(transaction.fee_bid))) ||
    !validityCovers(use.grant.validity, transaction.validity) ||
    (use.grant.application_namespace !== null
      && !kindMatchesApplicationNamespace(transaction.kind, use.grant.application_namespace))
  ) {
    return false;
  }
  const reserve = BigInt(transaction.fee_bid.gas_limit) * BigInt(transaction.fee_bid.max_fee_per_unit);
  return reserve <= BigInt(use.grant.max_fee_per_transaction);
}

function kindMatchesApplicationNamespace(
  kind: TransactionKindV1Json,
  expected: string,
): boolean {
  if (!("Actions" in kind)) return false;
  let observed = false;
  for (const action of kind.Actions.actions) {
    if (!("Native" in action) || typeof action.Native.operation !== "object") continue;
    const operation = action.Native.operation;
    const namespace = "CreateObject" in operation
      ? operation.CreateObject.namespace
      : "MutateObject" in operation
        ? operation.MutateObject.namespace
        : "TransferObject" in operation
          ? operation.TransferObject.namespace
          : "DeleteObject" in operation
            ? operation.DeleteObject.namespace
            : null;
    if (namespace === null) continue;
    if (namespace !== expected) return false;
    observed = true;
  }
  return observed;
}

async function digestEquals(expected: string, actual: Promise<string>): Promise<boolean> {
  return expected === (await actual);
}

function validateAuthorization(value: unknown): asserts value is TransactionAuthorizationV1Json {
  requireRecord(value, "V5 authorization");
  requireExactKeys(value, ["lane", "policy_revision", "nonce"], "V5 authorization");
  // The all-zero lane is the legitimate DEFAULT lane (Rust
  // `AuthorizationLaneId::DEFAULT = Hash256::ZERO`), backed directly by the
  // account balance and nonce; Rust's V5 structure validation accepts it, so a
  // faithful verifier must too. Rejecting zero here would refuse the most common
  // (default-lane) transaction and diverge from the Rust reference verifier.
  requireHex(value.lane, 32, "authorization lane", false);
  requireU64(value.policy_revision, "authorization policy revision");
  requireU64(value.nonce, "authorization nonce");
}

function validateValidity(value: unknown): asserts value is ValidityWindowV1Json {
  requireRecord(value, "V5 validity");
  requireExactKeys(value, ["valid_from_height", "valid_until_height"], "V5 validity");
  const from = requireU64(value.valid_from_height, "valid-from height");
  const until = requireU64(value.valid_until_height, "valid-until height");
  if (until < from || until - from + 1n > MAX_TRANSACTION_VALIDITY_BLOCKS) {
    throw new Error("invalid or oversized V5 validity range");
  }
}

function validityCovers(outer: ValidityWindowV1Json, inner: ValidityWindowV1Json): boolean {
  return BigInt(outer.valid_from_height) <= BigInt(inner.valid_from_height)
    && BigInt(inner.valid_until_height) <= BigInt(outer.valid_until_height);
}

function validateKind(value: unknown): asserts value is TransactionKindV1Json {
  requireRecord(value, "V5 transaction kind");
  const keys = Object.keys(value);
  if (keys.length !== 1) throw new Error("V5 transaction kind must have one variant");
  if ("Actions" in value) {
    requireRecord(value.Actions, "V5 action program");
    requireExactKeys(value.Actions, ["actions"], "V5 action program");
    if (!Array.isArray(value.Actions.actions)
      || value.Actions.actions.length === 0
      || value.Actions.actions.length > MAX_ACTIONS_V1) {
      throw new Error("V5 action program must contain between 1 and 32 actions");
    }
    for (const action of value.Actions.actions) {
      requireRecord(action, "V5 action");
      if ("Native" in action) {
        requireExactKeys(action, ["Native"], "V5 action");
        requireRecord(action.Native, "V5 native action");
        requireExactKeys(action.Native, ["operation"], "V5 native action");
        if (action.Native.operation === null || action.Native.operation === undefined) {
          throw new Error("V5 native action is missing its operation");
        }
        validateNativeActionV1(action.Native.operation);
      } else if ("RevokeSponsorGrant" in action) {
        requireExactKeys(action, ["RevokeSponsorGrant"], "V5 action");
        requireRecord(action.RevokeSponsorGrant, "V5 sponsor revocation action");
        requireExactKeys(action.RevokeSponsorGrant, ["grant_id"], "V5 sponsor revocation action");
        requireHex(action.RevokeSponsorGrant.grant_id, 32, "sponsor grant id", true);
      } else if ("RevokeSignedSponsorGrant" in action) {
        requireExactKeys(action, ["RevokeSignedSponsorGrant"], "V5 action");
        requireRecord(action.RevokeSignedSponsorGrant, "V5 signed sponsor revocation action");
        requireExactKeys(
          action.RevokeSignedSponsorGrant,
          ["grant"],
          "V5 signed sponsor revocation action",
        );
        validateSponsorGrant(action.RevokeSignedSponsorGrant.grant, true);
      } else if ("StakingControl" in action) {
        requireExactKeys(action, ["StakingControl"], "V5 action");
        requireRecord(action.StakingControl, "V5 staking-control action");
        requireExactKeys(
          action.StakingControl,
          ["action", "post_quantum_root_reveal"],
          "V5 staking-control action",
        );
        validateStakingActionV1(action.StakingControl.action);
        validatePostQuantumRootRevealV1(action.StakingControl.post_quantum_root_reveal);
      } else {
        throw new Error("unsupported V5 action");
      }
    }
    return;
  }
  if ("Cancel" in value) {
    requireRecord(value.Cancel, "V5 cancellation");
    requireExactKeys(value.Cancel, [], "V5 cancellation");
    return;
  }
  throw new Error("unsupported V5 transaction kind");
}

async function validateSignedRevocationBindings(
  transaction: UnsignedTransactionV5Json | SignedTransactionV5Json,
): Promise<boolean> {
  if (!("Actions" in transaction.kind)) return true;
  const verified = new Set<string>();
  for (const action of transaction.kind.Actions.actions) {
    if (!("RevokeSignedSponsorGrant" in action)) continue;
    const grant = action.RevokeSignedSponsorGrant.grant;
    if (
      grant.sponsor !== transaction.sender
      || grant.chain_id !== transaction.chain_id
      || grant.protocol_version !== transaction.protocol_version
    ) {
      return false;
    }
    const digest = await sponsorGrantV1DigestHex(grant);
    if (!verified.has(digest)) {
      if (!(await verifySponsorGrantV1(grant))) return false;
      verified.add(digest);
    }
  }
  return true;
}

/** Rejects two immutable grants sharing one `(sponsor, grant_id)` replay key. */
async function validateSponsorIntentConsistency(
  transaction: UnsignedTransactionV5Json | SignedTransactionV5Json,
): Promise<boolean> {
  const identities = new Map<string, string>();
  const observe = (grant: SponsorGrantV1Json, digest: string): boolean => {
    const key = `${grant.sponsor}:${grant.grant_id}`;
    const identity = `${digest}:${grant.validity.valid_until_height}`;
    const previous = identities.get(key);
    if (previous !== undefined && previous !== identity) return false;
    identities.set(key, identity);
    return true;
  };

  if (transaction.fee_payment !== "SenderLane") {
    const use = transaction.fee_payment.Sponsored;
    if (!observe(use.grant, use.grant_digest)) return false;
  }
  if (!("Actions" in transaction.kind)) return true;
  for (const action of transaction.kind.Actions.actions) {
    if (!("RevokeSignedSponsorGrant" in action)) continue;
    const grant = action.RevokeSignedSponsorGrant.grant;
    if (!observe(grant, await sponsorGrantV1DigestHex(grant))) return false;
  }
  return true;
}

/** Validates the exact bounded staking payload shared with the Rust signer. */
function validateStakingActionV1(value: unknown): asserts value is StakingActionV1Json {
  requireRecord(value, "V5 staking action");
  const variants = Object.keys(value);
  if (variants.length !== 1) {
    throw new Error("V5 staking action must have one variant");
  }
  const variant = variants[0];
  if (variant === "RegisterValidator") {
    const payload = value[variant];
    requireRecord(payload, "V5 validator registration");
    requireExactKeys(
      payload,
      ["consensus_key", "self_stake", "commission_bps"],
      "V5 validator registration",
    );
    requireHex(payload.consensus_key, 32, "V5 validator consensus key", false);
    if (requireU128(payload.self_stake, "V5 validator self stake") === 0n
      || typeof payload.commission_bps !== "number"
      || !Number.isInteger(payload.commission_bps)
      || payload.commission_bps < 0
      || payload.commission_bps > 10_000) {
      throw new Error("invalid V5 validator registration parameters");
    }
    return;
  }
  if (variant === "Delegate" || variant === "Undelegate") {
    const payload = value[variant];
    requireRecord(payload, `V5 ${variant} action`);
    requireExactKeys(payload, ["validator", "amount"], `V5 ${variant} action`);
    requireAddress(payload.validator, `V5 ${variant} validator`);
    if (requireU128(payload.amount, `V5 ${variant} amount`) === 0n) {
      throw new Error(`V5 ${variant} amount must be positive`);
    }
    return;
  }
  if (variant === "UnstakeValidator") {
    const payload = value[variant];
    requireRecord(payload, "V5 validator unstake action");
    requireExactKeys(payload, ["amount"], "V5 validator unstake action");
    if (requireU128(payload.amount, "V5 validator unstake amount") === 0n) {
      throw new Error("V5 validator unstake amount must be positive");
    }
    return;
  }
  throw new Error("unsupported V5 staking action");
}

/** Validates only bounded wire shape; Rust performs exact ML-DSA verification. */
function validatePostQuantumRootRevealV1(
  value: unknown,
): asserts value is PostQuantumRootRevealJson {
  requireRecord(value, "V5 post-quantum root reveal");
  requireExactKeys(
    value,
    ["scheme", "public_key", "signature"],
    "V5 post-quantum root reveal",
  );
  if (value.scheme !== "MlDsa65") {
    throw new Error("unsupported V5 post-quantum root scheme");
  }
  requireBoundedHex(
    value.public_key,
    MAX_POST_QUANTUM_REVEAL_COMPONENT_BYTES_V1,
    "V5 post-quantum public key",
  );
  requireBoundedHex(
    value.signature,
    MAX_POST_QUANTUM_REVEAL_COMPONENT_BYTES_V1,
    "V5 post-quantum signature",
  );
  if (value.public_key.length === 0 || value.signature.length === 0) {
    throw new Error("V5 post-quantum root reveal components must be non-empty");
  }
}

function kindContainsStakingControl(kind: TransactionKindV1Json): boolean {
  return "Actions" in kind
    && kind.Actions.actions.some((action) => "StakingControl" in action);
}

function stakingTransitionRequiredUnits(action: StakingActionV1Json): bigint {
  return "RegisterValidator" in action ? 25_000n : 10_000n;
}

/**
 * Enforces the executable's current V5 native-action capability boundary.
 *
 * This mirrors Rust admission so a browser cannot sign an inactive operation
 * that would occupy a queue and later invalidate a proposed block. Checks here
 * are deliberately limited to facts that do not require chain state.
 */
function validateNativeActionV1(operation: unknown): asserts operation is OperationJson {
  if (operation === "ClaimValidatorRewards") return;
  requireRecord(operation, "V5 native operation");
  const variants = Object.keys(operation);
  if (variants.length !== 1) {
    throw new Error("V5 native operation must have one variant");
  }
  const variant = variants[0];
  if (variant === undefined) throw new Error("V5 native operation is missing its variant");
  if (!SUPPORTED_NATIVE_ACTIONS_V1.has(variant)) {
    throw new Error("V5 native action is not supported by this executable");
  }

  if (variant === "InstallAuthorizationPolicy") {
    requireRecord(operation[variant], "V5 policy-install operation");
    requireExactKeys(operation[variant], ["post_quantum_root"], "V5 policy-install operation");
    const root = operation[variant].post_quantum_root;
    requireRecord(root, "V5 post-quantum root");
    requireExactKeys(root, ["scheme", "public_key_hash"], "V5 post-quantum root");
    if (root.scheme !== "MlDsa65") throw new Error("invalid V5 post-quantum root");
    requireHex(root.public_key_hash, 32, "V5 post-quantum root", true);
    return;
  }

  if (variant === "OpenAuthorizationLane" || variant === "FundAuthorizationLane") {
    requireRecord(operation[variant], "V5 authorization-lane operation");
    requireExactKeys(
      operation[variant],
      ["lane", "fee_deposit"],
      "V5 authorization-lane operation",
    );
    requireHex(operation[variant].lane, 32, "V5 target authorization lane", true);
    if (requireU128(operation[variant].fee_deposit, "V5 lane fee deposit") === 0n) {
      throw new Error("V5 lane fee deposit must be positive");
    }
    return;
  }

  if (variant === "CreateObject" || variant === "MutateObject") {
    requireRecord(operation[variant], "V5 object-data operation");
    requireBoundedHex(
      operation[variant].data,
      MAX_OBJECT_DATA_BYTES_V1,
      "V5 object data",
    );
  }
}

/** Mirrors `webc_chain::Operation::required_units` for active V5 actions. */
function nativeActionRequiredUnits(operation: OperationJson): bigint {
  if (operation === "ClaimValidatorRewards") return 5_000n;
  const variant = Object.keys(operation)[0];
  switch (variant) {
    case "Transfer":
      return 500n;
    case "InstallAuthorizationPolicy":
      return 25_000n;
    case "OpenAuthorizationLane":
    case "FundAuthorizationLane":
    case "ClaimUnbonded":
      return 10_000n;
    case "ClaimDelegatorRewards":
      return 5_000n;
    case "CreateObject":
    case "MutateObject":
    case "TransferObject":
    case "DeleteObject":
      return 20_000n;
    default:
      throw new Error("native action is not supported by V5 execution");
  }
}

function validateAccessList(value: unknown): asserts value is StateAccessListJson {
  requireRecord(value, "V5 access list");
  requireExactKeys(value, ["read_only", "read_write"], "V5 access list");
  if (!Array.isArray(value.read_only) || !Array.isArray(value.read_write)) {
    throw new Error("V5 access list entries must be arrays");
  }
  if (value.read_only.length + value.read_write.length > MAX_TRANSACTION_STATE_KEYS) {
    throw new Error("V5 access list exceeds 256 keys");
  }
  const identities = new Set<string>();
  for (const key of [...value.read_only, ...value.read_write]) {
    const identity = new TextDecoder().decode(canonicalJsonBytes(key));
    if (identities.has(identity)) throw new Error("duplicate V5 state access key");
    identities.add(identity);
  }
}

const STATE_KEY_VARIANTS = [
  "Account",
  "AuthorizationPolicy",
  "AssetBalance",
  "Validator",
  "Delegation",
  "AuthorizationLane",
  "FeeAccumulator",
  "SessionKey",
  "BridgeMessage",
  "BridgeEscrow",
  "SlashingEvidence",
  "UnbondingQueue",
  "Object",
  "Module",
  "Application",
  "Protocol",
  "SponsorGrant",
] as const;

function stateKeyVariantName(key: StateKeyJson): string {
  if (key.version !== 1 || typeof key.kind !== "object" || key.kind === null) {
    throw new Error("unsupported V5 state-key version or shape");
  }
  const variants = Object.keys(key.kind);
  if (variants.length !== 1 || !STATE_KEY_VARIANTS.includes(
    variants[0] as (typeof STATE_KEY_VARIANTS)[number],
  )) {
    throw new Error("unsupported V5 state-key variant");
  }
  return variants[0] as string;
}

function stateKeyVariantRank(key: StateKeyJson): number {
  return STATE_KEY_VARIANTS.indexOf(
    stateKeyVariantName(key) as (typeof STATE_KEY_VARIANTS)[number],
  );
}

function validateFeeBid(value: unknown): asserts value is FeeBidV5Json {
  requireRecord(value, "V5 fee bid");
  requireExactKeys(value, ["gas_limit", "max_fee_per_unit", "priority_fee_per_unit"], "V5 fee bid");
  const gas = requireU64(value.gas_limit, "gas limit");
  const maximum = requireU64(value.max_fee_per_unit, "maximum fee rate");
  const priority = requireU64(value.priority_fee_per_unit, "priority fee rate");
  if (gas === 0n || maximum === 0n || priority > maximum || gas * maximum > U128_MAX) {
    throw new Error("invalid V5 fee bid");
  }
}

function validateFeePaymentShape(value: unknown): asserts value is FeePaymentV1Json {
  if (value === "SenderLane") return;
  requireRecord(value, "V5 fee payment");
  requireExactKeys(value, ["Sponsored"], "V5 fee payment");
  validateSponsorUse(value.Sponsored);
}

function validateSponsorUse(value: unknown): asserts value is SponsorUseV1Json {
  requireRecord(value, "V5 sponsor use");
  requireExactKeys(value, ["grant", "grant_digest", "use_nonce", "action_digest", "fee_bid_digest"], "V5 sponsor use");
  validateSponsorGrant(value.grant, true);
  requireHex(value.grant_digest, 32, "sponsor grant digest", true);
  requireU64(value.use_nonce, "sponsor use nonce");
  requireHex(value.action_digest, 32, "sponsor action digest", true);
  requireHex(value.fee_bid_digest, 32, "sponsor fee-bid digest", true);
}

function validateSponsorGrant(value: unknown, requireSignature: boolean): asserts value is SponsorGrantV1Json {
  requireRecord(value, "V5 sponsor grant");
  requireExactKeys(value, [
    "protocol_version", "chain_id", "grant_id", "sponsor", "sponsor_public_key",
    "payer_lane", "sender", "site_namespace", "application_namespace", "action_scope",
    "validity", "max_fee_per_transaction", "max_cumulative_fee", "max_uses",
    "sponsor_signature",
  ], "V5 sponsor grant");
  if (value.protocol_version !== TRANSACTION_V5_PROTOCOL_VERSION) {
    throw new Error("unsupported sponsor grant version");
  }
  requireChainId(value.chain_id);
  requireHex(value.grant_id, 32, "sponsor grant id", true);
  requireAddress(value.sponsor, "sponsor");
  requireHex(value.sponsor_public_key, 32, "sponsor public key", false);
  // The all-zero lane is the sponsor's legitimate default account lane, just
  // as it is for sender-paid V5 transactions and the Rust reference validator.
  requireHex(value.payer_lane, 32, "sponsor payer lane", false);
  requireAddress(value.sender, "sponsor-bound sender");
  requireOptionalHash(value.site_namespace, "site namespace");
  requireOptionalHash(value.application_namespace, "application namespace");
  requireRecord(value.action_scope, "sponsor action scope");
  requireExactKeys(value.action_scope, ["exact_action_digest"], "sponsor action scope");
  requireHex(value.action_scope.exact_action_digest, 32, "sponsor action digest", true);
  validateValidity(value.validity);
  const perTransaction = requireU128(value.max_fee_per_transaction, "sponsor per-transaction fee");
  const cumulative = requireU128(value.max_cumulative_fee, "sponsor cumulative fee");
  if (perTransaction === 0n || cumulative < perTransaction) {
    throw new Error("invalid sponsor fee budget");
  }
  if (requireU64(value.max_uses, "sponsor max uses") === 0n) {
    throw new Error("sponsor max uses must be positive");
  }
  if (value.sponsor_signature === null) {
    if (requireSignature) throw new Error("missing sponsor signature");
  } else {
    requireHex(value.sponsor_signature, 64, "sponsor signature", false);
  }
}

function requireRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
}

function requireExactKeys(value: Record<string, unknown>, expected: string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} has an unexpected field set`);
  }
}

function requireChainId(value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length < 3 || value.length > 64
    || !/^[a-z][a-z0-9-]*$/u.test(value)) {
    throw new Error("invalid WEBC chain ID");
  }
}

function requireAddress(value: unknown, label: string): asserts value is WebcAddress {
  if (typeof value !== "string") throw new Error(`${label} must be an address`);
  addressToBytes(value);
}

function requireHex(value: unknown, bytes: number, label: string, nonZero: boolean): asserts value is string {
  if (typeof value !== "string" || value.length !== bytes * 2
    || value !== value.toLowerCase() || !/^[0-9a-f]+$/u.test(value)
    || (nonZero && value === "00".repeat(bytes))) {
    throw new Error(`invalid ${label}`);
  }
  hexToBytes(value);
}

function requireBoundedHex(
  value: unknown,
  maximumBytes: number,
  label: string,
): asserts value is string {
  if (typeof value !== "string" || value.length % 2 !== 0
    || value.length > maximumBytes * 2 || value !== value.toLowerCase()
    || (value.length > 0 && !/^[0-9a-f]+$/u.test(value))) {
    throw new Error(`invalid or oversized ${label}`);
  }
}

function requireOptionalHash(value: unknown, label: string): void {
  if (value !== null) requireHex(value, 32, label, true);
}

function requireU64(value: unknown, label: string): bigint {
  if (typeof value !== "string" || value.length === 0 || value.length > 20
    || !/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${label} must be a canonical decimal u64 string`);
  }
  const parsed = BigInt(value);
  if (parsed > U64_MAX) throw new Error(`${label} exceeds u64`);
  return parsed;
}

function requireU128(value: unknown, label: string): bigint {
  if (typeof value !== "string" || value.length === 0 || value.length > 39
    || !/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${label} must be a canonical decimal u128 string`);
  }
  const parsed = BigInt(value);
  if (parsed > U128_MAX) throw new Error(`${label} exceeds u128`);
  return parsed;
}
