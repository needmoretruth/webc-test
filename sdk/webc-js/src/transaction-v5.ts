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

/** Maximum ordered actions in one V1 action program. */
export const MAX_ACTIONS_V1 = 32;
/** Maximum decoded bytes stored in one native object payload. */
export const MAX_OBJECT_DATA_BYTES_V1 = 64 * 1024;
/** Maximum UTF-8 bytes accepted for a complete V5 transaction. */
export const MAX_TRANSACTION_V5_CANONICAL_BYTES = 256 * 1024;
/** Maximum block heights covered by the inclusive validity range. */
export const MAX_TRANSACTION_VALIDITY_BLOCKS = 4096n;

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

/** One ordered V1 action wrapping an existing native operation. */
export type ActionV1Json =
  | { Native: { operation: OperationJson } }
  | { RevokeSponsorGrant: { grant_id: string } };

/** Non-empty bounded ordered action program. */
export interface ActionProgramV1Json {
  /** One through 32 atomic native actions. */
  actions: ActionV1Json[];
}

/** Top-level action or no-effect cancellation form. */
export type TransactionKindV1Json =
  | { Actions: ActionProgramV1Json }
  | { Cancel: Record<string, never> };

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

/** Constructs a protocol-2 action that permanently revokes one sponsor grant. */
export function revokeSponsorGrantActionV1(grantId: string): ActionV1Json {
  requireHex(grantId, 32, "sponsor grant id", true);
  return { RevokeSponsorGrant: { grant_id: grantId } };
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
    if (!(await validateFeePaymentBinding(transaction))) return false;
    return verifyEd25519(
      hexToBytes(transaction.sender_public_key),
      transactionV5SigningBytes(transaction),
      hexToBytes(transaction.sender_signature),
    );
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
  validateAccessList(value.access_list);
  validateFeeBid(value.fee_bid);
  validateFeePaymentShape(value.fee_payment);
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
  transaction: SignedTransactionV5Json,
): Promise<boolean> {
  if (transaction.fee_payment === "SenderLane") return true;
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
