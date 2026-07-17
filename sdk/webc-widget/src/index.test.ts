/**
 * @vitest-environment happy-dom
 * Host widget isolation, separate-origin validation, and lifecycle tests.
 */

import { describe, expect, it } from "vitest";
import { mountWebcWidget } from "./index";

describe("webc widget package", () => {
  it("exports the mount function", () => {
    expect(typeof mountWebcWidget).toBe("function");
  });

  it("mounts only a trusted-popup connector and cleans up", () => {
    const target = document.createElement("div");
    document.body.append(target);
    const handle = mountWebcWidget({
      target,
      walletUrl: "https://wallet.webc.example/app",
      limits: {
        max_amount_per_transaction: "100",
        max_total_amount: "1000",
        max_fee_per_transaction: "10",
      },
    });
    expect(target.textContent).toContain("Connect WEBC wallet");
    expect(target.textContent).toContain("never receives your recovery phrase");
    expect(target.textContent).not.toContain("Create WEBC wallet");
    handle.destroy();
    expect(target.childElementCount).toBe(0);
  });

  it("rejects a wallet URL on the untrusted host's own origin", () => {
    const target = document.createElement("div");
    expect(() =>
      mountWebcWidget({
        target,
        walletUrl: `${window.location.origin}/wallet`,
        limits: {
          max_amount_per_transaction: "1",
          max_total_amount: "1",
          max_fee_per_transaction: "1",
        },
      }),
    ).toThrow("separate trusted origin");
  });
});
