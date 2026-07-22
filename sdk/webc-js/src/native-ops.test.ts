/**
 * Cross-language wire-vector fixtures for the native operations added in Phase 7
 * onward (tokens, NFTs, governance, mandate, service registry, oracle, DEX).
 *
 * Each assertion pins the EXACT canonical JSON string (or state-key hash) that the
 * corresponding Rust wire-vector test asserts in
 * `crates/webc-chain/src/transaction.rs` and `state_key.rs`. Addresses are derived
 * from the SAME `Keypair::from_seed` seeds the Rust tests use, so a byte for byte
 * match confirms field names, sorted-key order, and scalar encodings agree across
 * languages. If the SDK output drifts from Rust, these fail.
 */

import { describe, expect, it } from "vitest";
import { canonicalJson } from "./canonical";
import { bytesToHex } from "./hex";
import { createWalletFromSeed } from "./wallet";
import {
  accessListForCastVote,
  accessListForExecuteProposal,
  accessListForOpenProposal,
  accessListForReclaimVote,
  accessListForResolveProposal,
  accountKey,
  authorizationPolicyKey,
  burnNft,
  burnToken,
  castVote,
  assetBalanceKey,
  cancelOrder,
  createFeed,
  createGovernanceInstance,
  createNftCollection,
  createToken,
  defaultAccessList,
  deregisterReporter,
  dexOrderKey,
  oracleFeedKey,
  oracleReporterKey,
  payFeedRead,
  registerReporter,
  submitOrder,
  submitReport,
  defaultAccessListAsync,
  deriveGovernanceInstanceIdHex,
  deriveGovVoteEscrowAddress,
  deriveMandateIdHex,
  deriveNftCollectionIdHex,
  deriveTokenIdHex,
  executeProposal,
  feeAccumulatorKey,
  freezeNftItem,
  freezeTokenAccount,
  fundGovernanceTreasury,
  governanceInstanceKey,
  governanceProposalKey,
  governanceVoteKey,
  grantMandate,
  mandateKey,
  mintNft,
  mintToken,
  nftCollectionKey,
  nftItemKey,
  openProposal,
  protocolKey,
  accessListForServiceSpend,
  deriveServiceIdHex,
  reclaimVote,
  registerService,
  resolveProposal,
  revokeMandate,
  serviceKey,
  setServiceStatus,
  spendUnderMandate,
  spendUnderMandateToService,
  topUpMandate,
  updateService,
  setNftAuthority,
  setNftCollectionPaused,
  setTokenAuthority,
  setTokenPaused,
  signTransaction,
  thawNftItem,
  thawTokenAccount,
  tokenBalanceKey,
  tokenFreezeKey,
  tokenKey,
  transferNft,
  transferToken,
} from "./transaction";
import type {
  AssetIdJson,
  GovernanceConfigJson,
  NftMetadataJson,
  ServicePriceJson,
  TokenMetadataJson,
} from "./types";

const DEFAULT_LANE = "00".repeat(32);

/** Reproduces `Keypair::from_seed([byte; 32]).address()` from the Rust fixtures. */
async function addressFromSeedByte(byte: number): Promise<string> {
  const wallet = await createWalletFromSeed(new Uint8Array(32).fill(byte));
  return wallet.address;
}

/** Lowercase hex of a UTF-8 string, matching Rust `hex::encode(text)`. */
function hexOfText(text: string): string {
  return bytesToHex(new TextEncoder().encode(text));
}

const ID_88 = "88".repeat(32);
const ID_99 = "99".repeat(32);
const ID_77 = "77".repeat(32);

describe("native token operation wire vectors", () => {
  it("pins CreateToken canonical JSON (nested metadata, Some/None authorities)", async () => {
    const recipient = await addressFromSeedByte(9);
    const metadata: TokenMetadataJson = {
      name: hexOfText("Acme Dollar"),
      symbol: hexOfText("ACME"),
      decimals: 6,
      metadata_hash: "1f".repeat(32),
    };
    const op = createToken({
      namespace: "55".repeat(32),
      createNonce: 7,
      metadata,
      mintAuthority: recipient,
      freezeAuthority: null,
      initialSupply: "1000",
      initialRecipient: recipient,
    });
    expect(canonicalJson(op)).toBe(
      `{"CreateToken":{"create_nonce":7,"freeze_authority":null,"initial_recipient":"${recipient}",` +
        `"initial_supply":"1000","metadata":{"decimals":6,"metadata_hash":"${"1f".repeat(32)}",` +
        `"name":"${hexOfText("Acme Dollar")}","symbol":"${hexOfText("ACME")}"},` +
        `"mint_authority":"${recipient}","namespace":"${"55".repeat(32)}"}}`,
    );
  });

  it("pins MintToken / BurnToken / TransferToken canonical JSON", async () => {
    const recipient = await addressFromSeedByte(9);
    expect(canonicalJson(mintToken(ID_88, recipient, "7"))).toBe(
      `{"MintToken":{"amount":"7","recipient":"${recipient}","token_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(burnToken(ID_88, "3"))).toBe(
      `{"BurnToken":{"amount":"3","token_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(transferToken(ID_88, recipient, "5"))).toBe(
      `{"TransferToken":{"amount":"5","recipient":"${recipient}","token_id":"${ID_88}"}}`,
    );
  });

  it("pins SetTokenPaused / Freeze / Thaw canonical JSON", async () => {
    const account = await addressFromSeedByte(10);
    expect(canonicalJson(setTokenPaused(ID_88, true))).toBe(
      `{"SetTokenPaused":{"paused":true,"token_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(freezeTokenAccount(ID_88, account))).toBe(
      `{"FreezeTokenAccount":{"account":"${account}","token_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(thawTokenAccount(ID_88, account))).toBe(
      `{"ThawTokenAccount":{"account":"${account}","token_id":"${ID_88}"}}`,
    );
  });

  it("pins SetTokenAuthority for both transfer (Some) and renounce (null)", async () => {
    const recipient = await addressFromSeedByte(9);
    expect(canonicalJson(setTokenAuthority(ID_88, "Mint", recipient))).toBe(
      `{"SetTokenAuthority":{"authority_kind":"Mint","new_authority":"${recipient}","token_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(setTokenAuthority(ID_88, "Freeze", null))).toBe(
      `{"SetTokenAuthority":{"authority_kind":"Freeze","new_authority":null,"token_id":"${ID_88}"}}`,
    );
  });

  it("rejects a non-canonical amount and non-lowercase-hex token id", () => {
    const recipient = "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3";
    expect(() => mintToken(ID_88, recipient, "01")).toThrow();
    expect(() => mintToken(ID_88, recipient, "-5")).toThrow();
    expect(() => mintToken("AB".repeat(32), recipient, "7")).toThrow();
    expect(() => burnToken("88", "3")).toThrow(); // not 32 bytes
  });
});

describe("native token access lists", () => {
  it("declares BOTH parties' freeze markers as reads on TransferToken", async () => {
    const sender = await addressFromSeedByte(1);
    const recipient = await addressFromSeedByte(9);
    const list = defaultAccessList(sender, transferToken(ID_88, recipient, "5"));
    // Exact order mirrors Rust `default_access_list_for_lane` insertion order.
    expect(list.read_only).toEqual([
      protocolKey("BaseFee"),
      tokenKey(ID_88),
      tokenFreezeKey(ID_88, sender),
      tokenFreezeKey(ID_88, recipient),
      authorizationPolicyKey(sender),
    ]);
    expect(list.read_write).toEqual([
      accountKey(sender),
      tokenBalanceKey(ID_88, sender),
      tokenBalanceKey(ID_88, recipient),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });

  it("names the derived token record (and initial balance) on CreateToken", async () => {
    const sender = await addressFromSeedByte(1);
    const recipient = await addressFromSeedByte(9);
    const metadata: TokenMetadataJson = {
      name: hexOfText("Acme"),
      symbol: hexOfText("ACME"),
      decimals: 6,
      metadata_hash: "1f".repeat(32),
    };
    const tokenId = await deriveTokenIdHex("55".repeat(32), sender, 7);
    const withSupply = await defaultAccessListAsync(
      sender,
      createToken({
        namespace: "55".repeat(32),
        createNonce: 7,
        metadata,
        mintAuthority: recipient,
        freezeAuthority: null,
        initialSupply: "1000",
        initialRecipient: recipient,
      }),
    );
    expect(withSupply.read_write).toEqual([
      accountKey(sender),
      tokenKey(tokenId),
      tokenBalanceKey(tokenId, recipient),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
    // A zero initial supply mints nothing, so the balance key is omitted.
    const zeroSupply = await defaultAccessListAsync(
      sender,
      createToken({
        namespace: "55".repeat(32),
        createNonce: 7,
        metadata,
        mintAuthority: recipient,
        freezeAuthority: null,
        initialSupply: "0",
        initialRecipient: recipient,
      }),
    );
    expect(zeroSupply.read_write).toEqual([
      accountKey(sender),
      tokenKey(tokenId),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });
});

describe("native token state-key wire vectors", () => {
  it("pins Token / TokenBalance / TokenFreeze canonical JSON", async () => {
    const holder = await addressFromSeedByte(9);
    expect(canonicalJson(tokenKey(ID_88))).toBe(
      `{"kind":{"Token":{"token_id":"${ID_88}"}},"version":1}`,
    );
    expect(canonicalJson(tokenBalanceKey(ID_88, holder))).toBe(
      `{"kind":{"TokenBalance":{"owner":"${holder}","token_id":"${ID_88}"}},"version":1}`,
    );
    expect(canonicalJson(tokenFreezeKey(ID_88, holder))).toBe(
      `{"kind":{"TokenFreeze":{"account":"${holder}","token_id":"${ID_88}"}},"version":1}`,
    );
  });
});

describe("native NFT operation wire vectors", () => {
  const ITEM_HEX = "3a".repeat(32);

  it("pins CreateNftCollection canonical JSON (Some/None authorities, Some cap)", async () => {
    const recipient = await addressFromSeedByte(9);
    const metadata: NftMetadataJson = {
      name: hexOfText("Acme Apes"),
      symbol: hexOfText("APE"),
      metadata_hash: "1f".repeat(32),
    };
    const op = createNftCollection({
      namespace: "55".repeat(32),
      createNonce: 7,
      metadata,
      mintAuthority: recipient,
      freezeAuthority: null,
      maxSupply: 10_000,
      royaltyBps: 500,
    });
    expect(canonicalJson(op)).toBe(
      `{"CreateNftCollection":{"create_nonce":7,"freeze_authority":null,"max_supply":10000,` +
        `"metadata":{"metadata_hash":"${"1f".repeat(32)}","name":"${hexOfText("Acme Apes")}",` +
        `"symbol":"${hexOfText("APE")}"},"mint_authority":"${recipient}","namespace":"${"55".repeat(32)}",` +
        `"royalty_bps":500}}`,
    );
  });

  it("pins MintNft / TransferNft / BurnNft canonical JSON", async () => {
    const recipient = await addressFromSeedByte(9);
    expect(canonicalJson(mintNft(ID_88, recipient, ITEM_HEX))).toBe(
      `{"MintNft":{"collection_id":"${ID_88}","item_metadata_hash":"${ITEM_HEX}","recipient":"${recipient}"}}`,
    );
    expect(canonicalJson(transferNft(ID_88, 3, recipient))).toBe(
      `{"TransferNft":{"collection_id":"${ID_88}","recipient":"${recipient}","serial":3}}`,
    );
    expect(canonicalJson(burnNft(ID_88, 3))).toBe(
      `{"BurnNft":{"collection_id":"${ID_88}","serial":3}}`,
    );
  });

  it("pins pause / freeze / thaw / authority canonical JSON", async () => {
    const recipient = await addressFromSeedByte(9);
    expect(canonicalJson(setNftCollectionPaused(ID_88, true))).toBe(
      `{"SetNftCollectionPaused":{"collection_id":"${ID_88}","paused":true}}`,
    );
    expect(canonicalJson(freezeNftItem(ID_88, 3))).toBe(
      `{"FreezeNftItem":{"collection_id":"${ID_88}","serial":3}}`,
    );
    expect(canonicalJson(thawNftItem(ID_88, 3))).toBe(
      `{"ThawNftItem":{"collection_id":"${ID_88}","serial":3}}`,
    );
    expect(canonicalJson(setNftAuthority(ID_88, "Mint", recipient))).toBe(
      `{"SetNftAuthority":{"authority_kind":"Mint","collection_id":"${ID_88}","new_authority":"${recipient}"}}`,
    );
    expect(canonicalJson(setNftAuthority(ID_88, "Freeze", null))).toBe(
      `{"SetNftAuthority":{"authority_kind":"Freeze","collection_id":"${ID_88}","new_authority":null}}`,
    );
  });
});

describe("native NFT state keys and access lists", () => {
  it("pins NftCollection / NftItem canonical JSON", () => {
    expect(canonicalJson(nftCollectionKey(ID_88))).toBe(
      `{"kind":{"NftCollection":{"collection_id":"${ID_88}"}},"version":1}`,
    );
    expect(canonicalJson(nftItemKey(ID_88, 7))).toBe(
      `{"kind":{"NftItem":{"collection_id":"${ID_88}","serial":7}},"version":1}`,
    );
  });

  it("declares the collection read-only and the item read-write on TransferNft", async () => {
    const sender = await addressFromSeedByte(1);
    const recipient = await addressFromSeedByte(9);
    const list = defaultAccessList(sender, transferNft(ID_88, 3, recipient));
    expect(list.read_only).toEqual([
      protocolKey("BaseFee"),
      nftCollectionKey(ID_88),
      authorizationPolicyKey(sender),
    ]);
    expect(list.read_write).toEqual([
      accountKey(sender),
      nftItemKey(ID_88, 3),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });

  it("names the derived collection record on CreateNftCollection", async () => {
    const sender = await addressFromSeedByte(1);
    const recipient = await addressFromSeedByte(9);
    const metadata: NftMetadataJson = {
      name: hexOfText("Acme Apes"),
      symbol: hexOfText("APE"),
      metadata_hash: "1f".repeat(32),
    };
    const collectionId = await deriveNftCollectionIdHex("55".repeat(32), sender, 7);
    const list = await defaultAccessListAsync(
      sender,
      createNftCollection({
        namespace: "55".repeat(32),
        createNonce: 7,
        metadata,
        mintAuthority: recipient,
        freezeAuthority: null,
        maxSupply: null,
        royaltyBps: 500,
      }),
    );
    expect(list.read_write).toEqual([
      accountKey(sender),
      nftCollectionKey(collectionId),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });
});

describe("native governance operation wire vectors", () => {
  it("pins CreateGovernanceInstance canonical JSON (nested config)", () => {
    const config: GovernanceConfigJson = {
      voting_period_epochs: 10,
      timelock_epochs: 3,
      quorum_bps: 3_000,
      proposal_threshold: "10",
      approval_threshold_bps: 5_000,
    };
    const op = createGovernanceInstance({
      namespace: "55".repeat(32),
      createNonce: 7,
      weightToken: ID_77,
      config,
    });
    expect(canonicalJson(op)).toBe(
      `{"CreateGovernanceInstance":{"config":{"approval_threshold_bps":5000,"proposal_threshold":"10",` +
        `"quorum_bps":3000,"timelock_epochs":3,"voting_period_epochs":10},"create_nonce":7,` +
        `"namespace":"${"55".repeat(32)}","weight_token":"${ID_77}"}}`,
    );
  });

  it("pins Fund / OpenProposal / CastVote / Resolve / Execute / Reclaim JSON", async () => {
    const recipient = await addressFromSeedByte(9);
    expect(canonicalJson(fundGovernanceTreasury(ID_88, "100"))).toBe(
      `{"FundGovernanceTreasury":{"amount":"100","instance_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(openProposal(ID_88, "Signaling"))).toBe(
      `{"OpenProposal":{"action":"Signaling","instance_id":"${ID_88}"}}`,
    );
    expect(
      canonicalJson(
        openProposal(ID_88, {
          TreasuryTransfer: { recipient, amount: "42" },
        }),
      ),
    ).toBe(
      `{"OpenProposal":{"action":{"TreasuryTransfer":{"amount":"42","recipient":"${recipient}"}},` +
        `"instance_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(castVote(ID_99, "Yes", "5"))).toBe(
      `{"CastVote":{"choice":"Yes","proposal_id":"${ID_99}","weight_amount":"5"}}`,
    );
    expect(canonicalJson(resolveProposal(ID_99))).toBe(
      `{"ResolveProposal":{"proposal_id":"${ID_99}"}}`,
    );
    expect(canonicalJson(executeProposal(ID_99))).toBe(
      `{"ExecuteProposal":{"proposal_id":"${ID_99}"}}`,
    );
    expect(canonicalJson(reclaimVote(ID_99))).toBe(
      `{"ReclaimVote":{"proposal_id":"${ID_99}"}}`,
    );
  });
});

describe("native governance state keys and access lists", () => {
  it("pins GovernanceInstance / Proposal / Vote canonical JSON", async () => {
    const voter = await addressFromSeedByte(9);
    expect(canonicalJson(governanceInstanceKey(ID_88))).toBe(
      `{"kind":{"GovernanceInstance":{"instance_id":"${ID_88}"}},"version":1}`,
    );
    expect(canonicalJson(governanceProposalKey(ID_99))).toBe(
      `{"kind":{"GovernanceProposal":{"proposal_id":"${ID_99}"}},"version":1}`,
    );
    expect(canonicalJson(governanceVoteKey(ID_99, voter))).toBe(
      `{"kind":{"GovernanceVote":{"proposal_id":"${ID_99}","voter":"${voter}"}},"version":1}`,
    );
  });

  it("names the derived instance record and weight-token read on create", async () => {
    const sender = await addressFromSeedByte(1);
    const config: GovernanceConfigJson = {
      voting_period_epochs: 10,
      timelock_epochs: 3,
      quorum_bps: 3_000,
      proposal_threshold: "10",
      approval_threshold_bps: 5_000,
    };
    const instanceId = await deriveGovernanceInstanceIdHex("55".repeat(32), sender, 7);
    const list = await defaultAccessListAsync(
      sender,
      createGovernanceInstance({
        namespace: "55".repeat(32),
        createNonce: 7,
        weightToken: ID_77,
        config,
      }),
    );
    expect(list.read_only).toEqual([
      protocolKey("BaseFee"),
      tokenKey(ID_77),
      authorizationPolicyKey(sender),
    ]);
    expect(list.read_write).toEqual([
      accountKey(sender),
      governanceInstanceKey(instanceId),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });

  it("refuses to auto-build a state-derived access list for CastVote", async () => {
    const sender = await addressFromSeedByte(1);
    await expect(
      defaultAccessListAsync(sender, castVote(ID_99, "Yes", "5")),
    ).rejects.toThrow();
  });

  it("builds the full CastVote access list including escrow token keys", async () => {
    const sender = await addressFromSeedByte(1);
    const escrow = await deriveGovVoteEscrowAddress(ID_99);
    const list = await accessListForCastVote({
      sender,
      proposalId: ID_99,
      choice: "Yes",
      weightAmount: "5",
      weightToken: ID_77,
    });
    expect(list.read_only).toEqual([
      protocolKey("BaseFee"),
      authorizationPolicyKey(sender),
      tokenKey(ID_77),
      tokenFreezeKey(ID_77, sender),
      tokenFreezeKey(ID_77, escrow),
    ]);
    expect(list.read_write).toEqual([
      accountKey(sender),
      governanceProposalKey(ID_99),
      governanceVoteKey(ID_99, sender),
      feeAccumulatorKey(sender, DEFAULT_LANE),
      tokenBalanceKey(ID_77, sender),
      tokenBalanceKey(ID_77, escrow),
    ]);
    // The full list signs cleanly as an explicit access list.
    const wallet = await createWalletFromSeed(new Uint8Array(32).fill(1));
    const tx = await signTransaction(
      wallet,
      "webc-devnet-1",
      0,
      castVote(ID_99, "Yes", "5"),
      { gasLimit: 1000, maxFeePerUnit: 1, priorityFeePerUnit: 0 },
      list,
    );
    expect(tx.access_list).toEqual(list);
  });

  it("builds the full ExecuteProposal treasury-payout access list", async () => {
    const sender = await addressFromSeedByte(1);
    const recipient = await addressFromSeedByte(9);
    const list = accessListForExecuteProposal({
      sender,
      proposalId: ID_99,
      payout: { instanceId: ID_88, recipient },
    });
    expect(list.read_write).toEqual([
      accountKey(sender),
      governanceProposalKey(ID_99),
      feeAccumulatorKey(sender, DEFAULT_LANE),
      governanceInstanceKey(ID_88),
      accountKey(recipient),
    ]);
  });

  it("builds the full ReclaimVote access list (proposal read, escrow balances)", async () => {
    const sender = await addressFromSeedByte(1);
    const escrow = await deriveGovVoteEscrowAddress(ID_99);
    const list = await accessListForReclaimVote({
      sender,
      proposalId: ID_99,
      weightToken: ID_77,
    });
    expect(list.read_only).toEqual([
      protocolKey("BaseFee"),
      governanceProposalKey(ID_99),
      authorizationPolicyKey(sender),
    ]);
    expect(list.read_write).toEqual([
      accountKey(sender),
      governanceVoteKey(ID_99, sender),
      feeAccumulatorKey(sender, DEFAULT_LANE),
      tokenBalanceKey(ID_77, escrow),
      tokenBalanceKey(ID_77, sender),
    ]);
  });

  it("builds OpenProposal and ResolveProposal weight-token access lists", async () => {
    const sender = await addressFromSeedByte(1);
    const openList = accessListForOpenProposal({
      sender,
      instanceId: ID_88,
      action: "Signaling",
      weightToken: ID_77,
    });
    expect(openList.read_only).toEqual([
      protocolKey("BaseFee"),
      authorizationPolicyKey(sender),
      tokenBalanceKey(ID_77, sender),
    ]);
    expect(openList.read_write).toEqual([
      accountKey(sender),
      governanceInstanceKey(ID_88),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
    const resolveList = accessListForResolveProposal({
      sender,
      proposalId: ID_99,
      weightToken: ID_77,
    });
    expect(resolveList.read_only).toEqual([
      protocolKey("BaseFee"),
      authorizationPolicyKey(sender),
      tokenKey(ID_77),
    ]);
    expect(resolveList.read_write).toEqual([
      accountKey(sender),
      governanceProposalKey(ID_99),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });
});

describe("agent mandate operation wire vectors", () => {
  it("pins TopUp / SpendUnderMandate / Revoke canonical JSON", async () => {
    const recipient = await addressFromSeedByte(2);
    expect(canonicalJson(topUpMandate(ID_88, "5"))).toBe(
      `{"TopUpMandate":{"amount":"5","mandate_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(spendUnderMandate(ID_88, recipient, "7"))).toBe(
      `{"SpendUnderMandate":{"amount":"7","mandate_id":"${ID_88}","recipient":"${recipient}"}}`,
    );
    expect(canonicalJson(revokeMandate(ID_88))).toBe(
      `{"RevokeMandate":{"mandate_id":"${ID_88}"}}`,
    );
  });

  it("pins GrantMandate canonical JSON (Open policy)", async () => {
    const agentWallet = await createWalletFromSeed(new Uint8Array(32).fill(9));
    const agentKey = bytesToHex(agentWallet.publicKey);
    const op = grantMandate({
      agentKey,
      grantNonce: 3,
      budgetTotal: "1000",
      expiryEpoch: 100,
      perTxMax: "100",
      rateLimitPerDay: 5,
      counterpartyPolicy: "Open",
    });
    expect(canonicalJson(op)).toBe(
      `{"GrantMandate":{"agent_key":"${agentKey}","budget_total":"1000","counterparty_policy":"Open",` +
        `"expiry_epoch":100,"grant_nonce":3,"per_tx_max":"100","rate_limit_per_day":5}}`,
    );
  });

  it("sorts a mandate allowlist into Rust BTreeSet order (Category before Recipient)", async () => {
    const agentWallet = await createWalletFromSeed(new Uint8Array(32).fill(9));
    const agentKey = bytesToHex(agentWallet.publicKey);
    const recipient = await addressFromSeedByte(2);
    const op = grantMandate({
      agentKey,
      grantNonce: 1,
      budgetTotal: "1000",
      expiryEpoch: 100,
      perTxMax: "100",
      rateLimitPerDay: 0,
      // Deliberately out of order; the builder must sort Category before Recipient.
      counterpartyPolicy: {
        Allowlist: [{ Recipient: recipient }, { Category: "c1".repeat(32) }],
      },
    });
    expect(op).toEqual({
      GrantMandate: {
        agent_key: agentKey,
        grant_nonce: 1,
        budget_total: "1000",
        expiry_epoch: 100,
        per_tx_max: "100",
        rate_limit_per_day: 0,
        counterparty_policy: {
          Allowlist: [{ Category: "c1".repeat(32) }, { Recipient: recipient }],
        },
      },
    });
    expect(() =>
      grantMandate({
        agentKey,
        grantNonce: 1,
        budgetTotal: "1000",
        expiryEpoch: 100,
        perTxMax: "100",
        rateLimitPerDay: 0,
        counterpartyPolicy: { Allowlist: [] },
      }),
    ).toThrow();
  });
});

describe("agent mandate state key and access lists", () => {
  it("pins Mandate canonical JSON", () => {
    expect(canonicalJson(mandateKey(ID_88))).toBe(
      `{"kind":{"Mandate":{"mandate_id":"${ID_88}"}},"version":1}`,
    );
  });

  it("declares the recipient account on SpendUnderMandate", async () => {
    const sender = await addressFromSeedByte(1);
    const recipient = await addressFromSeedByte(2);
    const list = defaultAccessList(sender, spendUnderMandate(ID_88, recipient, "7"));
    expect(list.read_write).toEqual([
      accountKey(sender),
      mandateKey(ID_88),
      accountKey(recipient),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });

  it("names the derived mandate record on GrantMandate", async () => {
    const sender = await addressFromSeedByte(1);
    const agentWallet = await createWalletFromSeed(new Uint8Array(32).fill(9));
    const agentKey = bytesToHex(agentWallet.publicKey);
    const mandateId = await deriveMandateIdHex(sender, agentKey, 3);
    const list = await defaultAccessListAsync(
      sender,
      grantMandate({
        agentKey,
        grantNonce: 3,
        budgetTotal: "1000",
        expiryEpoch: 100,
        perTxMax: "100",
        rateLimitPerDay: 5,
        counterpartyPolicy: "Open",
      }),
    );
    expect(list.read_write).toEqual([
      accountKey(sender),
      mandateKey(mandateId),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });
});

describe("service registry operation wire vectors", () => {
  const PRICING: ServicePriceJson[] = [
    { operation: "0b".repeat(32), price: "1000", unit: hexOfText("call") },
  ];
  const PAYMENT_FLAGS = {
    on_chain_direct: true,
    http_402: false,
    subscription: false,
  };

  it("pins RegisterService canonical JSON (categories, pricing, flags)", () => {
    const op = registerService({
      namespace: "55".repeat(32),
      createNonce: 7,
      categories: ["c1".repeat(32)],
      title: hexOfText("inference"),
      endpoint: hexOfText("https://api.example/infer"),
      interface: "1f".repeat(32),
      pricing: PRICING,
      paymentFlags: PAYMENT_FLAGS,
    });
    expect(canonicalJson(op)).toBe(
      `{"RegisterService":{"categories":["${"c1".repeat(32)}"],"create_nonce":7,` +
        `"endpoint":"${hexOfText("https://api.example/infer")}","interface":"${"1f".repeat(32)}",` +
        `"namespace":"${"55".repeat(32)}","payment_flags":{"http_402":false,"on_chain_direct":true,` +
        `"subscription":false},"pricing":[{"operation":"${"0b".repeat(32)}","price":"1000",` +
        `"unit":"${hexOfText("call")}"}],"title":"${hexOfText("inference")}"}}`,
    );
  });

  it("pins SetServiceStatus and SpendUnderMandateToService canonical JSON", () => {
    expect(canonicalJson(setServiceStatus(ID_88, "Paused"))).toBe(
      `{"SetServiceStatus":{"service_id":"${ID_88}","status":"Paused"}}`,
    );
    expect(canonicalJson(spendUnderMandateToService(ID_99, ID_88, "7"))).toBe(
      `{"SpendUnderMandateToService":{"amount":"7","mandate_id":"${ID_99}","service_id":"${ID_88}"}}`,
    );
  });

  it("sorts and deduplicates service categories into BTreeSet order", () => {
    const op = updateService({
      serviceId: ID_88,
      categories: ["c2".repeat(32), "c1".repeat(32), "c2".repeat(32)],
      title: hexOfText("svc"),
      endpoint: hexOfText("https://x"),
      interface: "1f".repeat(32),
      pricing: [],
      paymentFlags: PAYMENT_FLAGS,
    });
    expect(op).toMatchObject({
      UpdateService: { categories: ["c1".repeat(32), "c2".repeat(32)] },
    });
  });
});

describe("service registry state key and access lists", () => {
  it("pins Service canonical JSON", () => {
    expect(canonicalJson(serviceKey(ID_88))).toBe(
      `{"kind":{"Service":{"service_id":"${ID_88}"}},"version":1}`,
    );
  });

  it("declares only the entry record on SetServiceStatus", async () => {
    const sender = await addressFromSeedByte(1);
    const list = defaultAccessList(sender, setServiceStatus(ID_88, "Paused"));
    expect(list.read_write).toEqual([
      accountKey(sender),
      serviceKey(ID_88),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });

  it("names the derived service record on RegisterService", async () => {
    const sender = await addressFromSeedByte(1);
    const serviceId = await deriveServiceIdHex("55".repeat(32), sender, 7);
    const list = await defaultAccessListAsync(
      sender,
      registerService({
        namespace: "55".repeat(32),
        createNonce: 7,
        categories: [],
        title: hexOfText("svc"),
        endpoint: hexOfText("https://x"),
        interface: "1f".repeat(32),
        pricing: [],
        paymentFlags: {
          on_chain_direct: true,
          http_402: false,
          subscription: false,
        },
      }),
    );
    expect(list.read_write).toEqual([
      accountKey(sender),
      serviceKey(serviceId),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });

  it("refuses to auto-build SpendUnderMandateToService, and helper adds owner", async () => {
    const sender = await addressFromSeedByte(1);
    const owner = await addressFromSeedByte(3);
    await expect(
      defaultAccessListAsync(sender, spendUnderMandateToService(ID_99, ID_88, "7")),
    ).rejects.toThrow();
    const list = accessListForServiceSpend({
      sender,
      mandateId: ID_99,
      serviceId: ID_88,
      serviceOwner: owner,
    });
    expect(list.read_only).toEqual([
      protocolKey("BaseFee"),
      serviceKey(ID_88),
      authorizationPolicyKey(sender),
    ]);
    expect(list.read_write).toEqual([
      accountKey(sender),
      mandateKey(ID_99),
      feeAccumulatorKey(sender, DEFAULT_LANE),
      accountKey(owner),
    ]);
  });
});

describe("native oracle operation wire vectors", () => {
  it("pins CreateFeed / Register / Deregister / SubmitReport / PayFeedRead JSON", () => {
    expect(canonicalJson(createFeed(ID_88))).toBe(
      `{"CreateFeed":{"feed_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(registerReporter(ID_88))).toBe(
      `{"RegisterReporter":{"feed_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(deregisterReporter(ID_88))).toBe(
      `{"DeregisterReporter":{"feed_id":"${ID_88}"}}`,
    );
    // The report value is a SIGNED decimal string, never a bare JSON number.
    expect(canonicalJson(submitReport(ID_88, "-123456789012345"))).toBe(
      `{"SubmitReport":{"feed_id":"${ID_88}","value":"-123456789012345"}}`,
    );
    expect(canonicalJson(payFeedRead(ID_88, "42"))).toBe(
      `{"PayFeedRead":{"amount":"42","feed_id":"${ID_88}"}}`,
    );
  });

  it("accepts i128 extremes and rejects a non-canonical signed value", () => {
    const I128_MAX = "170141183460469231731687303715884105727";
    const I128_MIN = "-170141183460469231731687303715884105728";
    expect(() => submitReport(ID_88, I128_MAX)).not.toThrow();
    expect(() => submitReport(ID_88, I128_MIN)).not.toThrow();
    expect(() => submitReport(ID_88, "-0")).toThrow();
    expect(() => submitReport(ID_88, "007")).toThrow();
    expect(() =>
      submitReport(ID_88, "170141183460469231731687303715884105728"),
    ).toThrow(); // i128::MAX + 1
  });
});

describe("native oracle state keys and access lists", () => {
  it("pins OracleFeed / OracleReporter canonical JSON", async () => {
    const reporter = await addressFromSeedByte(7);
    expect(canonicalJson(oracleFeedKey(ID_88))).toBe(
      `{"kind":{"OracleFeed":{"feed_id":"${ID_88}"}},"version":1}`,
    );
    expect(canonicalJson(oracleReporterKey(ID_88, reporter))).toBe(
      `{"kind":{"OracleReporter":{"feed_id":"${ID_88}","reporter":"${reporter}"}},"version":1}`,
    );
  });

  it("reads the feed and writes the reporter record on RegisterReporter", async () => {
    const sender = await addressFromSeedByte(1);
    const list = defaultAccessList(sender, registerReporter(ID_88));
    expect(list.read_only).toEqual([
      protocolKey("BaseFee"),
      oracleFeedKey(ID_88),
      authorizationPolicyKey(sender),
    ]);
    expect(list.read_write).toEqual([
      accountKey(sender),
      oracleReporterKey(ID_88, sender),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });
});

describe("native DEX operation wire vectors", () => {
  // No dedicated Rust wire-vector test exists for DEX; these fixtures are derived
  // from the serde type definitions. `amount` and `limit_price` are decimal
  // strings (Amount and the u128 Price); `deadline_height` is a JSON number; the
  // `pair` reuses the AssetId encoding already frozen by the state-key vector.
  const USDC: AssetIdJson = {
    External: {
      origin_chain: "Ethereum",
      symbol: "USDC",
      contract_or_mint: "0x1234",
    },
  };

  it("pins SubmitOrder canonical JSON (native/external pair, Sell)", () => {
    const op = submitOrder({
      orderId: ID_88,
      pair: { base: "NativeWebc", quote: USDC },
      side: "Sell",
      amount: "1000",
      limitPrice: "5",
      deadlineHeight: 0,
      fillOrCancel: false,
    });
    expect(canonicalJson(op)).toBe(
      `{"SubmitOrder":{"amount":"1000","deadline_height":0,"fill_or_cancel":false,"limit_price":"5",` +
        `"order_id":"${ID_88}","pair":{"base":"NativeWebc","quote":{"External":{"contract_or_mint":"0x1234",` +
        `"origin_chain":"Ethereum","symbol":"USDC"}}},"side":"Sell"}}`,
    );
  });

  it("pins CancelOrder and the DexOrder state key", () => {
    expect(canonicalJson(cancelOrder(ID_88))).toBe(
      `{"CancelOrder":{"order_id":"${ID_88}"}}`,
    );
    expect(canonicalJson(dexOrderKey(ID_88))).toBe(
      `{"kind":{"DexOrder":{"order_id":"${ID_88}"}},"version":1}`,
    );
  });

  it("locks the non-native leg (quote on Buy, base on Sell)", async () => {
    const sender = await addressFromSeedByte(1);
    const usdc = USDC;
    // Sell locks the base leg; base is native here, so no asset-balance key.
    const sell = defaultAccessList(
      sender,
      submitOrder({
        orderId: ID_88,
        pair: { base: "NativeWebc", quote: usdc },
        side: "Sell",
        amount: "1000",
        limitPrice: "5",
        deadlineHeight: 0,
        fillOrCancel: false,
      }),
    );
    expect(sell.read_write).toEqual([
      accountKey(sender),
      dexOrderKey(ID_88),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
    // Buy locks the quote leg; quote is USDC (non-native), so it is declared.
    const buy = defaultAccessList(
      sender,
      submitOrder({
        orderId: ID_88,
        pair: { base: "NativeWebc", quote: usdc },
        side: "Buy",
        amount: "1000",
        limitPrice: "5",
        deadlineHeight: 0,
        fillOrCancel: true,
      }),
    );
    expect(buy.read_write).toEqual([
      accountKey(sender),
      dexOrderKey(ID_88),
      assetBalanceKey(usdc, sender),
      feeAccumulatorKey(sender, DEFAULT_LANE),
    ]);
  });
});
