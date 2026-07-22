/**
 * Tests for `GovernanceClient` (`clients/governance.ts`).
 *
 * The `WebcNodeClient` is MOCKED (its read + submit methods) — no network is
 * touched — while a real `WebcWallet` signs. Each write is pinned against the EXACT
 * operation JSON the low-level `transaction.ts` builder produces AND the EXACT
 * access list the matching `accessListFor*` helper (or `defaultAccessListAsync` for
 * the non-state-derived ops) produces, so any drift from the composed primitives
 * fails the test. The state-derived proposal ops are checked to resolve their
 * on-chain value (the instance/proposal's weight token, the proposal payout) from
 * the node before signing. Reads are asserted against mocked responses, and a
 * fail-closed case (an invalid config) is rejected before any submit.
 */

import { describe, expect, it } from "vitest";

import { canonicalJson } from "../canonical.js";
import { createWalletFromSeed } from "../wallet.js";
import type { WebcWallet } from "../wallet.js";
import type { AccountView, SubmitReceipt, WebcNodeClient } from "../node-client.js";
import type {
  GovernanceActionJson,
  GovernanceConfigJson,
  GovernanceInstance,
  GovernanceProposal,
  SignedTransactionJson,
} from "../types.js";
import {
  DEFAULT_AUTHORIZATION_LANE,
  accessListForCastVote,
  accessListForExecuteProposal,
  accessListForOpenProposal,
  accessListForReclaimVote,
  accessListForResolveProposal,
  castVote,
  createGovernanceInstance,
  defaultAccessListAsync,
  deriveGovernanceInstanceIdHex,
  deriveGovernanceProposalIdHex,
  executeProposal,
  fundGovernanceTreasury,
  openProposal,
  reclaimVote,
  resolveProposal,
  transactionHashHex,
  verifySignedTransaction,
} from "../transaction.js";
import { GovernanceClient } from "./governance.js";

const INSTANCE_ID = "aa".repeat(32);
const PROPOSAL_ID = "bb".repeat(32);
const WEIGHT_TOKEN = "cc".repeat(32);
const NAMESPACE = "dd".repeat(32);
const CHAIN_ID = "webc-devnet-1";
const FEE = { gasLimit: 1000, maxFeePerUnit: 1, priorityFeePerUnit: 0 };
const NEXT_PROPOSAL_NONCE = 7;

const CONFIG: GovernanceConfigJson = {
  voting_period_epochs: 10,
  timelock_epochs: 2,
  quorum_bps: 2000,
  proposal_threshold: "100",
  approval_threshold_bps: 5000,
};

function walletFromSeedByte(byte: number): Promise<WebcWallet> {
  return createWalletFromSeed(new Uint8Array(32).fill(byte));
}

function mkInstance(creator: string): GovernanceInstance {
  return {
    creator,
    weight_token: WEIGHT_TOKEN,
    config: CONFIG,
    treasury: "0",
    next_proposal_nonce: NEXT_PROPOSAL_NONCE,
  };
}

function mkProposal(
  proposer: string,
  action: GovernanceActionJson = "Signaling",
): GovernanceProposal {
  return {
    instance_id: INSTANCE_ID,
    proposer,
    weight_token: WEIGHT_TOKEN,
    config: CONFIG,
    action,
    created_epoch: 1,
    voting_ends_epoch: 11,
    eta_epoch: null,
    status: "Active",
    yes: "0",
    no: "0",
    abstain: "0",
  };
}

interface MockHandlers {
  instances?: Record<string, GovernanceInstance>;
  proposals?: Record<string, GovernanceProposal>;
  proposalPage?: { items: readonly unknown[]; nextCursor: string | null };
  chainId?: string;
  accountNonce?: number;
}

interface MockNode {
  node: WebcNodeClient;
  submitted: SignedTransactionJson[];
  listCalls: unknown[];
}

function makeNode(handlers: MockHandlers = {}): MockNode {
  const submitted: SignedTransactionJson[] = [];
  const listCalls: unknown[] = [];
  const node = {
    async submitTransaction(tx: unknown): Promise<SubmitReceipt> {
      submitted.push(tx as SignedTransactionJson);
      return {
        txHash: await transactionHashHex(tx as SignedTransactionJson),
        accepted: true,
        mempoolSize: 1,
      };
    },
    async getGovernanceInstance(id: string): Promise<GovernanceInstance> {
      const instance = handlers.instances?.[id];
      if (!instance) throw new Error(`no mocked instance ${id}`);
      return instance;
    },
    async getGovernanceProposal(id: string): Promise<GovernanceProposal> {
      const proposal = handlers.proposals?.[id];
      if (!proposal) throw new Error(`no mocked proposal ${id}`);
      return proposal;
    },
    async listGovernanceProposals(id: string, options: unknown) {
      listCalls.push({ id, options });
      return handlers.proposalPage ?? { items: [], nextCursor: null };
    },
    async health() {
      return {
        apiVersion: "v1",
        chainId: handlers.chainId ?? CHAIN_ID,
        height: 1,
        tipHash: null,
        stateRoot: null,
        mempoolSize: 0,
        faucetEnabled: false,
      };
    },
    async account(address: string): Promise<AccountView> {
      return { address, balance: 0n, nonce: handlers.accountNonce ?? 0 };
    },
  };
  return { node: node as unknown as WebcNodeClient, submitted, listCalls };
}

describe("GovernanceClient instance writes", () => {
  it("createInstance pins the op + default access list, signs, submits, derives the id", async () => {
    const creator = await walletFromSeedByte(1);
    const { node, submitted } = makeNode();
    const client = new GovernanceClient({ node, signer: creator, chainId: CHAIN_ID, fee: FEE });

    const args = {
      namespace: NAMESPACE,
      createNonce: 4,
      weightToken: WEIGHT_TOKEN,
      config: CONFIG,
    };
    const result = await client.createInstance(args, { nonce: 0 });

    expect(canonicalJson(result.transaction.operation)).toBe(
      canonicalJson(createGovernanceInstance(args)),
    );
    expect(result.transaction.access_list).toEqual(
      await defaultAccessListAsync(
        creator.address,
        createGovernanceInstance(args),
        DEFAULT_AUTHORIZATION_LANE,
      ),
    );
    expect(result.instanceId).toBe(
      await deriveGovernanceInstanceIdHex(NAMESPACE, creator.address, 4),
    );
    expect(await verifySignedTransaction(result.transaction)).toBe(true);
    expect(submitted).toHaveLength(1);
    expect(submitted[0]).toBe(result.transaction);
    expect(result.txHash).toBe(await transactionHashHex(result.transaction));
  });

  it("fundTreasury pins the op + default access list and returns the instance id", async () => {
    const funder = await walletFromSeedByte(1);
    const { node, submitted } = makeNode();
    const client = new GovernanceClient({ node, signer: funder, chainId: CHAIN_ID, fee: FEE });

    const result = await client.fundTreasury(INSTANCE_ID, "500", { nonce: 2 });
    expect(canonicalJson(result.transaction.operation)).toBe(
      canonicalJson(fundGovernanceTreasury(INSTANCE_ID, "500")),
    );
    expect(result.transaction.access_list).toEqual(
      await defaultAccessListAsync(
        funder.address,
        fundGovernanceTreasury(INSTANCE_ID, "500"),
        DEFAULT_AUTHORIZATION_LANE,
      ),
    );
    expect(result.instanceId).toBe(INSTANCE_ID);
    expect(submitted[0]).toBe(result.transaction);
    expect(await verifySignedTransaction(result.transaction)).toBe(true);
  });

  it("throws (and never submits) an invalid config before signing (fail-closed)", async () => {
    const creator = await walletFromSeedByte(1);
    const { node, submitted } = makeNode();
    const client = new GovernanceClient({ node, signer: creator, chainId: CHAIN_ID, fee: FEE });

    await expect(
      client.createInstance(
        {
          namespace: NAMESPACE,
          createNonce: 0,
          weightToken: WEIGHT_TOKEN,
          config: { ...CONFIG, voting_period_epochs: 0 },
        },
        { nonce: 0 },
      ),
    ).rejects.toThrow(/voting period/u);
    expect(submitted).toHaveLength(0);
  });
});

describe("GovernanceClient proposal flow (state-derived access lists)", () => {
  it("openProposal resolves the instance, pins the op + accessListForOpenProposal, derives the id", async () => {
    const proposer = await walletFromSeedByte(1);
    const { node, submitted } = makeNode({ instances: { [INSTANCE_ID]: mkInstance(proposer.address) } });
    const client = new GovernanceClient({ node, signer: proposer, chainId: CHAIN_ID, fee: FEE });

    const action: GovernanceActionJson = "Signaling";
    const result = await client.openProposal(INSTANCE_ID, action, { nonce: 0 });

    expect(canonicalJson(result.transaction.operation)).toBe(
      canonicalJson(openProposal(INSTANCE_ID, action)),
    );
    expect(result.transaction.access_list).toEqual(
      accessListForOpenProposal({
        sender: proposer.address,
        instanceId: INSTANCE_ID,
        action,
        weightToken: WEIGHT_TOKEN,
      }),
    );
    // The id is derived from the instance's read next_proposal_nonce.
    expect(result.proposalId).toBe(
      await deriveGovernanceProposalIdHex(INSTANCE_ID, NEXT_PROPOSAL_NONCE),
    );
    expect(await verifySignedTransaction(result.transaction)).toBe(true);
    expect(submitted[0]).toBe(result.transaction);
  });

  it("castVote resolves the proposal, pins the op + accessListForCastVote", async () => {
    const voter = await walletFromSeedByte(1);
    const { node, submitted } = makeNode({ proposals: { [PROPOSAL_ID]: mkProposal(voter.address) } });
    const client = new GovernanceClient({ node, signer: voter, chainId: CHAIN_ID, fee: FEE });

    const result = await client.castVote(PROPOSAL_ID, "Yes", "250", { nonce: 1 });
    expect(canonicalJson(result.transaction.operation)).toBe(
      canonicalJson(castVote(PROPOSAL_ID, "Yes", "250")),
    );
    expect(result.transaction.access_list).toEqual(
      await accessListForCastVote({
        sender: voter.address,
        proposalId: PROPOSAL_ID,
        choice: "Yes",
        weightAmount: "250",
        weightToken: WEIGHT_TOKEN,
      }),
    );
    expect(result.proposalId).toBe(PROPOSAL_ID);
    expect(submitted[0]).toBe(result.transaction);
    expect(await verifySignedTransaction(result.transaction)).toBe(true);
  });

  it("resolveProposal resolves the proposal, pins the op + accessListForResolveProposal", async () => {
    const caller = await walletFromSeedByte(1);
    const { node, submitted } = makeNode({ proposals: { [PROPOSAL_ID]: mkProposal(caller.address) } });
    const client = new GovernanceClient({ node, signer: caller, chainId: CHAIN_ID, fee: FEE });

    const result = await client.resolveProposal(PROPOSAL_ID, { nonce: 0 });
    expect(canonicalJson(result.transaction.operation)).toBe(
      canonicalJson(resolveProposal(PROPOSAL_ID)),
    );
    expect(result.transaction.access_list).toEqual(
      accessListForResolveProposal({
        sender: caller.address,
        proposalId: PROPOSAL_ID,
        weightToken: WEIGHT_TOKEN,
      }),
    );
    expect(result.proposalId).toBe(PROPOSAL_ID);
    expect(submitted[0]).toBe(result.transaction);
  });

  it("executeProposal resolves a TreasuryTransfer payout into accessListForExecuteProposal", async () => {
    const caller = await walletFromSeedByte(1);
    const recipient = (await walletFromSeedByte(5)).address;
    const action: GovernanceActionJson = { TreasuryTransfer: { recipient, amount: "500" } };
    const { node, submitted } = makeNode({
      proposals: { [PROPOSAL_ID]: mkProposal(caller.address, action) },
    });
    const client = new GovernanceClient({ node, signer: caller, chainId: CHAIN_ID, fee: FEE });

    const result = await client.executeProposal(PROPOSAL_ID, { nonce: 0 });
    expect(canonicalJson(result.transaction.operation)).toBe(
      canonicalJson(executeProposal(PROPOSAL_ID)),
    );
    // The payout keys (instance treasury + recipient account) are resolved from the
    // stored proposal action, exactly as the low-level helper expects.
    expect(result.transaction.access_list).toEqual(
      accessListForExecuteProposal({
        sender: caller.address,
        proposalId: PROPOSAL_ID,
        payout: { instanceId: INSTANCE_ID, recipient },
      }),
    );
    expect(result.proposalId).toBe(PROPOSAL_ID);
    expect(submitted[0]).toBe(result.transaction);
  });

  it("executeProposal treats a Signaling proposal as a null payout", async () => {
    const caller = await walletFromSeedByte(1);
    const { node, submitted } = makeNode({ proposals: { [PROPOSAL_ID]: mkProposal(caller.address) } });
    const client = new GovernanceClient({ node, signer: caller, chainId: CHAIN_ID, fee: FEE });

    const result = await client.executeProposal(PROPOSAL_ID, { nonce: 0 });
    expect(result.transaction.access_list).toEqual(
      accessListForExecuteProposal({
        sender: caller.address,
        proposalId: PROPOSAL_ID,
        payout: null,
      }),
    );
    expect(submitted[0]).toBe(result.transaction);
  });

  it("reclaimVote resolves the proposal, pins the op + accessListForReclaimVote", async () => {
    const voter = await walletFromSeedByte(1);
    const { node, submitted } = makeNode({ proposals: { [PROPOSAL_ID]: mkProposal(voter.address) } });
    const client = new GovernanceClient({ node, signer: voter, chainId: CHAIN_ID, fee: FEE });

    const result = await client.reclaimVote(PROPOSAL_ID, { nonce: 3 });
    expect(canonicalJson(result.transaction.operation)).toBe(
      canonicalJson(reclaimVote(PROPOSAL_ID)),
    );
    expect(result.transaction.access_list).toEqual(
      await accessListForReclaimVote({
        sender: voter.address,
        proposalId: PROPOSAL_ID,
        weightToken: WEIGHT_TOKEN,
      }),
    );
    expect(result.proposalId).toBe(PROPOSAL_ID);
    expect(submitted[0]).toBe(result.transaction);
  });
});

describe("GovernanceClient reads", () => {
  it("getInstance / getProposal wrap the node reads", async () => {
    const creator = await walletFromSeedByte(1);
    const instance = mkInstance(creator.address);
    const proposal = mkProposal(creator.address);
    const { node } = makeNode({
      instances: { [INSTANCE_ID]: instance },
      proposals: { [PROPOSAL_ID]: proposal },
    });
    const client = new GovernanceClient({ node, signer: creator, chainId: CHAIN_ID, fee: FEE });

    expect(await client.getInstance(INSTANCE_ID)).toEqual(instance);
    expect(await client.getProposal(PROPOSAL_ID)).toEqual(proposal);
  });

  it("listProposals threads the id + status filter through to the list endpoint", async () => {
    const creator = await walletFromSeedByte(1);
    const page = { items: [], nextCursor: "cursor-2" as string | null };
    const { node, listCalls } = makeNode({ proposalPage: page });
    const client = new GovernanceClient({ node, signer: creator, chainId: CHAIN_ID, fee: FEE });

    const result = await client.listProposals(INSTANCE_ID, { status: "Active" });
    expect(result).toEqual(page);
    expect(listCalls).toEqual([{ id: INSTANCE_ID, options: { status: "Active" } }]);
  });
});
