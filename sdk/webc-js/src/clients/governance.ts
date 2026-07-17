/**
 * `GovernanceClient` — the ergonomic entry point for on-chain governance on WEBC
 * (Phase 13c, §15). It COMPOSES the reviewed low-level SDK into the flows a DAO
 * participant actually performs:
 *
 *   - stand up a governance instance and fund its treasury (build -> sign -> submit);
 *   - open a proposal, cast / reclaim a lock-to-vote ballot, and resolve / execute
 *     it (each build -> sign -> submit);
 *   - read an instance / proposal and page an instance's proposals.
 *
 * It introduces no new operation, access list, or wire format: every write goes
 * through a `transaction.ts` builder, and the STATE-DERIVED proposal operations
 * (`OpenProposal` / `CastVote` / `ResolveProposal` / `ExecuteProposal` /
 * `ReclaimVote`) have their access list built by the matching `accessListFor*`
 * helper — exactly as the low-level API requires — with the on-chain value (the
 * instance's weight token, the proposal's payout) resolved from the node first.
 * The client-derived ids are computed with the SAME derivations the builders
 * document (`deriveGovernanceInstanceIdHex` / `deriveGovernanceProposalIdHex`).
 *
 * ## Signer role
 * Every method here signs an ordinary account transaction with this client's
 * `signer`: the instance creator (create), a funder (fund), the proposer (open),
 * or any account (vote / resolve / execute / reclaim). Construct the client with
 * whichever `signer` is driving the flow.
 */

import type {
  GovernanceProposalEntry,
  ListProposalsOptions,
  Page,
} from "../node-client.js";
import type {
  GovernanceActionJson,
  GovernanceConfigJson,
  GovernanceInstance,
  GovernanceProposal,
  HexString,
  VoteChoiceJson,
} from "../types.js";
import {
  accessListForCastVote,
  accessListForExecuteProposal,
  accessListForOpenProposal,
  accessListForReclaimVote,
  accessListForResolveProposal,
  castVote as castVoteOp,
  createGovernanceInstance as createGovernanceInstanceOp,
  deriveGovernanceInstanceIdHex,
  deriveGovernanceProposalIdHex,
  executeProposal as executeProposalOp,
  fundGovernanceTreasury as fundGovernanceTreasuryOp,
  openProposal as openProposalOp,
  reclaimVote as reclaimVoteOp,
  resolveProposal as resolveProposalOp,
} from "../transaction.js";
import {
  SigningClient,
  type SubmitOutcome,
  type TxOverrides,
} from "./common.js";

/**
 * Arguments for {@link GovernanceClient.createInstance}. Mirrors the low-level
 * `createGovernanceInstance` builder: the instance id is derived on-chain from
 * `(namespace, creator, createNonce)` where the creator is the signer.
 */
export interface CreateGovernanceInstanceArgs {
  /** 32-byte lowercase-hex namespace the instance is created under. */
  readonly namespace: HexString;
  /** Creator-chosen nonce; disambiguates instances under the same namespace. */
  readonly createNonce: number;
  /** 32-byte lowercase-hex token id whose balances denominate voting weight. */
  readonly weightToken: HexString;
  /** Immutable rule set (voting period, timelock, quorum, thresholds). */
  readonly config: GovernanceConfigJson;
}

/** Result of an instance write: the submit outcome plus the affected instance id. */
export interface GovernanceInstanceResult extends SubmitOutcome {
  /** The instance id the write applies to, 32-byte lowercase hex. */
  readonly instanceId: HexString;
}

/** Result of a proposal write: the submit outcome plus the affected proposal id. */
export interface GovernanceProposalResult extends SubmitOutcome {
  /** The proposal id the write applies to, 32-byte lowercase hex. */
  readonly proposalId: HexString;
}

/**
 * High-level client for on-chain governance: instance lifecycle, the proposal
 * vote/resolve/execute flow, and instance/proposal reads. Construct it with a
 * `WebcNodeClient` and a signer; every method signs with that signer.
 */
export class GovernanceClient extends SigningClient {
  /**
   * Creates a governance instance bound to `weightToken` under `config`. Builds
   * `CreateGovernanceInstance`, lets `signTransaction` derive the default access
   * list (the same list the low-level API auto-derives for this op), submits, and
   * returns the receipt plus the client-derived instance id (identical to the id
   * the chain assigns from `(namespace, creator, createNonce)`).
   */
  async createInstance(
    args: CreateGovernanceInstanceArgs,
    overrides: TxOverrides = {},
  ): Promise<GovernanceInstanceResult> {
    const operation = createGovernanceInstanceOp({
      namespace: args.namespace,
      createNonce: args.createNonce,
      weightToken: args.weightToken,
      config: args.config,
    });
    const instanceId = await deriveGovernanceInstanceIdHex(
      args.namespace,
      this.signer.address,
      args.createNonce,
    );
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, instanceId };
  }

  /**
   * Deposits `amount` native base units into an instance's treasury. Builds
   * `FundGovernanceTreasury` with the default access list and submits.
   */
  async fundTreasury(
    instanceId: HexString,
    amount: string,
    overrides: TxOverrides = {},
  ): Promise<GovernanceInstanceResult> {
    const operation = fundGovernanceTreasuryOp(instanceId, amount);
    const outcome = await this.signAndSubmit(operation, undefined, overrides);
    return { ...outcome, instanceId };
  }

  /**
   * Opens a proposal carrying `action` on an instance (signer = proposer). This op
   * is STATE-DERIVED: the access list needs the instance's weight token, so the
   * instance is read first and the list is built with `accessListForOpenProposal`.
   * The instance's monotonic `next_proposal_nonce` also fixes the returned proposal
   * id (`deriveGovernanceProposalIdHex`); if a racing proposal consumes that nonce
   * first, the derived id will not match — re-read the instance.
   */
  async openProposal(
    instanceId: HexString,
    action: GovernanceActionJson,
    overrides: TxOverrides = {},
  ): Promise<GovernanceProposalResult> {
    const operation = openProposalOp(instanceId, action);
    const instance = await this.node.getGovernanceInstance(instanceId);
    const proposalId = await deriveGovernanceProposalIdHex(
      instanceId,
      instance.next_proposal_nonce,
    );
    const accessList = accessListForOpenProposal({
      sender: this.signer.address,
      instanceId,
      action,
      weightToken: instance.weight_token,
      authorizationLane: overrides.authorizationLane,
    });
    const outcome = await this.signAndSubmit(operation, accessList, overrides);
    return { ...outcome, proposalId };
  }

  /**
   * Casts a lock-to-vote ballot on a proposal, locking `weightAmount` weight-token
   * units. STATE-DERIVED: the access list needs the proposal's weight token (and
   * the derived vote-lock escrow), so the proposal is read first and the list is
   * built with `accessListForCastVote`.
   */
  async castVote(
    proposalId: HexString,
    choice: VoteChoiceJson,
    weightAmount: string,
    overrides: TxOverrides = {},
  ): Promise<GovernanceProposalResult> {
    const operation = castVoteOp(proposalId, choice, weightAmount);
    const proposal = await this.node.getGovernanceProposal(proposalId);
    const accessList = await accessListForCastVote({
      sender: this.signer.address,
      proposalId,
      choice,
      weightAmount,
      weightToken: proposal.weight_token,
      authorizationLane: overrides.authorizationLane,
    });
    const outcome = await this.signAndSubmit(operation, accessList, overrides);
    return { ...outcome, proposalId };
  }

  /**
   * Resolves a proposal after its voting period ends (permissionless). STATE-
   * DERIVED: the access list needs the weight-token supply read, so the proposal is
   * read first and the list is built with `accessListForResolveProposal`.
   */
  async resolveProposal(
    proposalId: HexString,
    overrides: TxOverrides = {},
  ): Promise<GovernanceProposalResult> {
    const operation = resolveProposalOp(proposalId);
    const proposal = await this.node.getGovernanceProposal(proposalId);
    const accessList = accessListForResolveProposal({
      sender: this.signer.address,
      proposalId,
      weightToken: proposal.weight_token,
      authorizationLane: overrides.authorizationLane,
    });
    const outcome = await this.signAndSubmit(operation, accessList, overrides);
    return { ...outcome, proposalId };
  }

  /**
   * Executes (or expires) a passed proposal within its execution window. STATE-
   * DERIVED: a `TreasuryTransfer` payout writes the instance treasury and credits
   * the recipient, so the proposal is read first and the payout keys are resolved
   * from its stored action; a `Signaling` proposal needs no extra keys.
   */
  async executeProposal(
    proposalId: HexString,
    overrides: TxOverrides = {},
  ): Promise<GovernanceProposalResult> {
    const operation = executeProposalOp(proposalId);
    const proposal = await this.node.getGovernanceProposal(proposalId);
    const payout =
      proposal.action === "Signaling"
        ? null
        : {
            instanceId: proposal.instance_id,
            recipient: proposal.action.TreasuryTransfer.recipient,
          };
    const accessList = accessListForExecuteProposal({
      sender: this.signer.address,
      proposalId,
      payout,
      authorizationLane: overrides.authorizationLane,
    });
    const outcome = await this.signAndSubmit(operation, accessList, overrides);
    return { ...outcome, proposalId };
  }

  /**
   * Reclaims the caller's locked weight after a proposal resolves. STATE-DERIVED:
   * the access list needs both weight-token balance keys (voter + escrow), so the
   * proposal is read first and the list is built with `accessListForReclaimVote`.
   */
  async reclaimVote(
    proposalId: HexString,
    overrides: TxOverrides = {},
  ): Promise<GovernanceProposalResult> {
    const operation = reclaimVoteOp(proposalId);
    const proposal = await this.node.getGovernanceProposal(proposalId);
    const accessList = await accessListForReclaimVote({
      sender: this.signer.address,
      proposalId,
      weightToken: proposal.weight_token,
      authorizationLane: overrides.authorizationLane,
    });
    const outcome = await this.signAndSubmit(operation, accessList, overrides);
    return { ...outcome, proposalId };
  }

  /** Reads a governance instance by id. Thin wrapper over `getGovernanceInstance`. */
  async getInstance(instanceId: HexString): Promise<GovernanceInstance> {
    return this.node.getGovernanceInstance(instanceId);
  }

  /** Reads a governance proposal by id. Thin wrapper over `getGovernanceProposal`. */
  async getProposal(proposalId: HexString): Promise<GovernanceProposal> {
    return this.node.getGovernanceProposal(proposalId);
  }

  /**
   * Pages an instance's proposals (optionally filtered by `status`) via the
   * proposals list endpoint. Thin wrapper over `listGovernanceProposals`; each
   * entry carries the proposal id alongside its full record.
   */
  async listProposals(
    instanceId: HexString,
    options: ListProposalsOptions = {},
  ): Promise<Page<GovernanceProposalEntry>> {
    return this.node.listGovernanceProposals(instanceId, options);
  }
}
