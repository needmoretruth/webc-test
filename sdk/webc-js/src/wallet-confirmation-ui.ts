/**
 * Framework-free confirmation UI rendered only inside the trusted wallet origin.
 *
 * All hostile text is assigned through `textContent`; no HTML from a host site
 * is interpreted. The UI shows browser-authenticated origin and every required
 * transfer field before resolving. It does not create wallets, store secrets,
 * or communicate with the parent window itself.
 */

import type {
  WalletConfirmation,
  WalletConnectionConfirmation,
  WalletRevocationConfirmation,
  WalletTransferConfirmation,
} from "./wallet-request.js";
import type { WalletConfirmationHandler } from "./wallet-service.js";
import {
  TrustedWalletService,
  attachTrustedWalletService,
  type WalletMessageSource,
} from "./wallet-service.js";
import type { WebcWallet } from "./wallet.js";

/**
 * Milliseconds the Approve button stays inert after each render, so a
 * double-click aimed at one request cannot carry over to the next request that
 * mounts in the same position. OWASP-style "guard delay" against click-through.
 */
export const DEFAULT_APPROVE_DELAY_MS = 700;

/** Options for labels in one trusted wallet confirmation surface. */
export interface WalletConfirmationUiOptions {
  readonly root: HTMLElement;
  readonly title?: string;
  readonly approveLabel?: string;
  readonly rejectLabel?: string;
  /**
   * How long Approve is disabled after render before it can be activated, in
   * milliseconds. Defaults to {@link DEFAULT_APPROVE_DELAY_MS}. Exposed mainly so
   * tests can drive the guard deterministically.
   */
  readonly approveDelayMs?: number;
}

/** Inputs for a top-level trusted wallet popup service. */
export interface TrustedWalletWindowOptions extends WalletConfirmationUiOptions {
  /** Unlocked in-process wallet created inside this trusted origin. */
  readonly wallet: WebcWallet;
  /** Exact chain this popup is willing to sign for. */
  readonly chainId: string;
  /** Injectable window for tests; defaults to the current trusted window. */
  readonly targetWindow?: Window;
}

/**
 * Starts the complete service in a top-level trusted popup with an opener.
 *
 * Framed execution is rejected because a host page could overlay/clickjack an
 * embedded confirmation. The popup's address-bar origin remains visible, and
 * the service binds all requests to the exact `window.opener` source.
 */
export function startTrustedWalletWindow(
  options: TrustedWalletWindowOptions,
): () => void {
  const targetWindow = options.targetWindow ?? window;
  if (targetWindow.top !== targetWindow || !targetWindow.opener) {
    throw new Error("trusted wallet must run in a top-level popup with an opener");
  }
  const confirm = createWalletConfirmationUi(options);
  const service = new TrustedWalletService({
    wallet: options.wallet,
    chainId: options.chainId,
    expectedSource: targetWindow.opener as unknown as WalletMessageSource,
    confirm,
  });
  return attachTrustedWalletService(service, targetWindow);
}

/**
 * Creates a handler that blocks until the user approves or rejects each request.
 *
 * The caller must mount `root` in a wallet-controlled HTTPS document, not in
 * the host site's DOM. Removing the root externally does not auto-approve; the
 * returned promise stays pending until one explicit button event occurs.
 */
export function createWalletConfirmationUi(
  options: WalletConfirmationUiOptions,
): WalletConfirmationHandler {
  return (confirmation) =>
    new Promise<boolean>((resolve) => {
      renderConfirmation(options, confirmation, resolve);
    });
}

function renderConfirmation(
  options: WalletConfirmationUiOptions,
  confirmation: WalletConfirmation,
  resolve: (approved: boolean) => void,
): void {
  const root = options.root;
  root.replaceChildren();

  const panel = document.createElement("section");
  panel.setAttribute("role", "dialog");
  panel.setAttribute("aria-modal", "true");
  panel.style.border = "2px solid currentColor";
  panel.style.borderRadius = "12px";
  panel.style.padding = "16px";
  panel.style.maxWidth = "520px";
  panel.style.fontFamily = "system-ui, sans-serif";

  const heading = document.createElement("h1");
  heading.textContent = options.title ?? "WEBC Wallet Confirmation";
  heading.style.marginTop = "0";
  panel.append(heading);

  appendField(panel, "Requesting site", confirmation.origin, true);
  if (confirmation.kind === "connect") {
    renderConnection(panel, confirmation);
  } else if (confirmation.kind === "revoke") {
    renderRevocation(panel, confirmation);
  } else {
    renderTransfer(panel, confirmation);
  }

  const warning = document.createElement("p");
  warning.textContent =
    confirmation.kind === "revoke"
      ? "Approving clears this site's permission and its recorded spend history."
      : "Approve only if the site, recipient, amount, asset, and maximum fee are correct.";
  panel.append(warning);

  const actions = document.createElement("div");
  actions.style.display = "flex";
  actions.style.gap = "12px";
  const reject = document.createElement("button");
  reject.type = "button";
  reject.textContent = options.rejectLabel ?? "Reject";
  const approve = document.createElement("button");
  approve.type = "button";
  approve.textContent = options.approveLabel ?? "Approve";
  actions.append(reject, approve);
  panel.append(actions);
  root.append(panel);

  // Double-click guard. The next queued request's Approve button mounts in the
  // exact spot the previous one just occupied, so a fast double-click on request
  // N could otherwise land its second click on request N+1. Two defenses:
  //   1. Approve is disabled for a short delay after every render, so the second
  //      click of a double-click (tens of ms later) hits an inert button.
  //   2. Approval requires a fresh pointer press — pointerdown AND pointerup both
  //      after the delay — so a stray mouseup or a click whose press began on the
  //      previous request cannot approve this one. Keyboard activation (a
  //      deliberate, separate action) is honored once enabled. Reject is always
  //      immediate; rejecting is never dangerous.
  const approveDelayMs = options.approveDelayMs ?? DEFAULT_APPROVE_DELAY_MS;
  let completed = false;
  let approveEnabled = false;
  let pressArmed = false;
  approve.disabled = true;

  const enableTimer = setTimeout(() => {
    approveEnabled = true;
    approve.disabled = false;
  }, approveDelayMs);

  const finish = (approved: boolean) => {
    if (completed) return;
    completed = true;
    clearTimeout(enableTimer);
    approve.disabled = true;
    reject.disabled = true;
    resolve(approved);
  };

  const disarm = () => {
    pressArmed = false;
  };
  approve.addEventListener("pointerdown", () => {
    // Only a press that begins after the guard delay can arm approval.
    if (approveEnabled) pressArmed = true;
  });
  approve.addEventListener("pointerup", () => {
    if (approveEnabled && pressArmed) finish(true);
  });
  approve.addEventListener("pointercancel", disarm);
  approve.addEventListener("pointerleave", disarm);
  approve.addEventListener("keydown", (event) => {
    if (approveEnabled && (event.key === "Enter" || event.key === " ")) {
      event.preventDefault();
      finish(true);
    }
  });
  reject.addEventListener("click", () => finish(false), { once: true });
  reject.focus();
}

function renderConnection(
  panel: HTMLElement,
  confirmation: WalletConnectionConfirmation,
): void {
  appendField(panel, "Action", "Connect this site");
  appendField(panel, "Permission", "Sign native WEBC transfers");
  appendField(
    panel,
    "Maximum amount per transfer (base units)",
    confirmation.limits.max_amount_per_transaction,
  );
  appendField(
    panel,
    "Maximum cumulative amount (base units)",
    confirmation.limits.max_total_amount,
  );
  appendField(
    panel,
    "Maximum fee per transfer (base units)",
    confirmation.limits.max_fee_per_transaction,
  );
}

function renderRevocation(
  panel: HTMLElement,
  _confirmation: WalletRevocationConfirmation,
): void {
  appendField(panel, "Action", "Disconnect this site");
  appendField(
    panel,
    "Effect",
    "Removes the site's permission and its cumulative spend history",
  );
}

function renderTransfer(
  panel: HTMLElement,
  confirmation: WalletTransferConfirmation,
): void {
  appendField(panel, "Action", confirmation.action);
  appendField(panel, "Recipient", confirmation.recipient, true);
  appendField(panel, "Amount", confirmation.amount_webc);
  appendField(panel, "Amount (base units)", confirmation.amount_base_units);
  appendField(panel, "Asset", confirmation.asset);
  appendField(
    panel,
    "Maximum fee (base units)",
    confirmation.maximum_fee_base_units,
  );
  appendField(panel, "Chain", confirmation.chain_id, true);
  appendField(panel, "Authorization lane", confirmation.authorization_lane, true);
  appendField(
    panel,
    "Authorization policy revision",
    confirmation.authorization_policy_revision.toString(10),
  );
}

function appendField(
  panel: HTMLElement,
  label: string,
  value: string,
  code = false,
): void {
  const group = document.createElement("p");
  const strong = document.createElement("strong");
  strong.textContent = `${label}: `;
  const content = code ? document.createElement("code") : document.createElement("span");
  content.textContent = value;
  content.style.overflowWrap = "anywhere";
  group.append(strong, content);
  panel.append(group);
}
