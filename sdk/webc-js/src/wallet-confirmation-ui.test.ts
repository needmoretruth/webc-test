/**
 * @vitest-environment happy-dom
 * Trusted confirmation DOM rendering and explicit button-decision tests.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import type { WalletTransferConfirmation } from "./wallet-request";
import {
  DEFAULT_APPROVE_DELAY_MS,
  createWalletConfirmationUi,
} from "./wallet-confirmation-ui";

afterEach(() => {
  document.body.replaceChildren();
  vi.useRealTimers();
});

/** Dispatches a genuine fresh pointer press (pointerdown then pointerup). */
function press(button: Element): void {
  button.dispatchEvent(new Event("pointerdown"));
  button.dispatchEvent(new Event("pointerup"));
}

function transferConfirmation(tag: string): WalletTransferConfirmation {
  return {
    kind: "native_transfer",
    origin: `https://shop.example/${tag}`,
    action: "Send WEBC",
    asset: "WEBC",
    recipient: `webc1recipient-${tag}`,
    amount_base_units: "1000000000000",
    amount_webc: "1 WEBC",
    maximum_fee_base_units: "5000",
    chain_id: "webc-devnet-1",
    authorization_lane: "ab".repeat(32),
    authorization_policy_revision: 0,
  };
}

describe("trusted wallet confirmation UI", () => {
  it("shows origin and every transfer field without interpreting host HTML", async () => {
    vi.useFakeTimers();
    const root = document.createElement("div");
    document.body.append(root);
    const confirm = createWalletConfirmationUi({ root });
    const decision = confirm({
      kind: "native_transfer",
      origin: "https://shop.example/<img src=x onerror=alert(1)>",
      action: "Send WEBC",
      asset: "WEBC",
      recipient: "webc1recipient",
      amount_base_units: "1000000000000",
      amount_webc: "1 WEBC",
      maximum_fee_base_units: "5000",
      chain_id: "webc-devnet-1",
      authorization_lane: "ab".repeat(32),
      authorization_policy_revision: 0,
    });

    expect(root.textContent).toContain("https://shop.example/<img");
    expect(root.textContent).toContain("Send WEBC");
    expect(root.textContent).toContain("webc1recipient");
    expect(root.textContent).toContain("1 WEBC");
    expect(root.textContent).toContain("1000000000000");
    expect(root.textContent).toContain("WEBC");
    expect(root.textContent).toContain("5000");
    expect(root.textContent).toContain("webc-devnet-1");
    expect(root.querySelector("img")).toBeNull();

    const buttons = root.querySelectorAll("button");
    expect(buttons).toHaveLength(2);
    // Approve only after the guard delay and via a genuine pointer press.
    vi.advanceTimersByTime(DEFAULT_APPROVE_DELAY_MS);
    press(buttons[1]);
    await expect(decision).resolves.toBe(true);
  });

  it("shows grant limits and rejects only on an explicit reject click", async () => {
    const root = document.createElement("div");
    document.body.append(root);
    const confirm = createWalletConfirmationUi({ root });
    const decision = confirm({
      kind: "connect",
      origin: "https://shop.example",
      scopes: ["sign_native_transfer"],
      limits: {
        max_amount_per_transaction: "10",
        max_total_amount: "20",
        max_fee_per_transaction: "3",
      },
    });
    expect(root.textContent).toContain("Connect this site");
    expect(root.textContent).toContain("10");
    expect(root.textContent).toContain("20");
    expect(root.textContent).toContain("3");
    root.querySelectorAll("button")[0].click();
    await expect(decision).resolves.toBe(false);
  });

  it("keeps Approve inert during the guard window so a carried-over click cannot approve (S1)", async () => {
    vi.useFakeTimers();
    const root = document.createElement("div");
    document.body.append(root);
    const confirm = createWalletConfirmationUi({ root });
    const decision = confirm(transferConfirmation("1"));

    let outcome: boolean | undefined;
    void decision.then((value) => {
      outcome = value;
    });

    // The next queued request renders its Approve button in the same position
    // the instant the previous one resolves. The second half of a double-click
    // (a full press plus its follow-up click) arriving immediately must NOT
    // approve, because Approve is still inside its guard window.
    const approve = root.querySelectorAll("button")[1];
    approve.dispatchEvent(new Event("pointerdown"));
    approve.dispatchEvent(new Event("pointerup"));
    approve.dispatchEvent(new Event("click"));
    await Promise.resolve();
    expect(outcome).toBeUndefined();

    // Only a deliberate fresh press after the guard delay approves.
    vi.advanceTimersByTime(DEFAULT_APPROVE_DELAY_MS);
    press(approve);
    await expect(decision).resolves.toBe(true);
  });

  it("requires the pointerdown to begin after render, not just a stray pointerup (S1)", async () => {
    vi.useFakeTimers();
    const root = document.createElement("div");
    document.body.append(root);
    const confirm = createWalletConfirmationUi({ root });
    const decision = confirm(transferConfirmation("2"));

    let outcome: boolean | undefined;
    void decision.then((value) => {
      outcome = value;
    });

    // Past the delay, a lone pointerup (a press that began before this render, on
    // a prior request) must not approve without a matching fresh pointerdown.
    vi.advanceTimersByTime(DEFAULT_APPROVE_DELAY_MS);
    const approve = root.querySelectorAll("button")[1];
    approve.dispatchEvent(new Event("pointerup"));
    await Promise.resolve();
    expect(outcome).toBeUndefined();

    // A complete fresh press approves.
    press(approve);
    await expect(decision).resolves.toBe(true);
  });
});
