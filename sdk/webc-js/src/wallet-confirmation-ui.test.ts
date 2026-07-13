/**
 * @vitest-environment happy-dom
 * Trusted confirmation DOM rendering and explicit button-decision tests.
 */

import { afterEach, describe, expect, it } from "vitest";
import { createWalletConfirmationUi } from "./wallet-confirmation-ui";

afterEach(() => document.body.replaceChildren());

describe("trusted wallet confirmation UI", () => {
  it("shows origin and every transfer field without interpreting host HTML", async () => {
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
    buttons[1].click();
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
});
