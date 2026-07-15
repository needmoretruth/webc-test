/** Adversarial tests for the authenticated encrypted permission store v1. */

import { beforeAll, describe, expect, it } from "vitest";
import {
  MAX_PERMISSION_GRANTS,
  PermissionStoreError,
  decryptPermissionStore,
  encryptPermissionStore,
  openPermissionStore,
  parsePermissionStore,
  serializePermissionStore,
  type PermissionStoreIdentity,
  type PersistedPermissionGrant,
  type WebcPermissionStoreV1,
} from "./permission-store";
import { createWallet, type WebcWallet } from "./wallet";
import type { WalletSpendLimitsJson } from "./wallet-request";

const PASSWORD = "correct horse battery";
const LANE_A = "a".repeat(64);
const LANE_B = "b".repeat(64);
const LIMITS: WalletSpendLimitsJson = {
  max_amount_per_transaction: "2000000000000",
  max_total_amount: "2500000000000",
  max_fee_per_transaction: "10000",
};

let walletA: WebcWallet;
let walletB: WebcWallet;
let identityA: PermissionStoreIdentity;
let identityB: PermissionStoreIdentity;

beforeAll(async () => {
  walletA = await createWallet();
  walletB = await createWallet();
  identityA = { address: walletA.address, publicKey: walletA.publicKey };
  identityB = { address: walletB.address, publicKey: walletB.publicKey };
});

function grant(
  origin: string,
  lane: string,
  spent = "0",
): PersistedPermissionGrant {
  return {
    origin,
    authorization_lane: lane,
    scopes: ["sign_native_transfer"],
    limits: LIMITS,
    spent_amount: spent,
  };
}

describe("encrypted permission store v1", () => {
  it("round-trips grants including cumulative spend through strict JSON", async () => {
    const records = [
      grant("https://shop.example", LANE_A, "1000000000000"),
      grant("https://game.example", LANE_B, "0"),
    ];
    const store = await encryptPermissionStore(records, PASSWORD, identityA);
    const serialized = serializePermissionStore(store);
    const reparsed = parsePermissionStore(serialized);
    const restored = await decryptPermissionStore(reparsed, PASSWORD, identityA);

    expect(restored).toHaveLength(2);
    // Deterministic origin ordering: game.example sorts before shop.example.
    expect(restored.map((r) => r.origin)).toEqual([
      "https://game.example",
      "https://shop.example",
    ]);
    const shop = restored.find((r) => r.origin === "https://shop.example");
    expect(shop?.spent_amount).toBe("1000000000000");
    expect(shop?.authorization_lane).toBe(LANE_A);
  });

  it("uses fresh salt and IV for repeated exports of the same grants", async () => {
    const records = [grant("https://shop.example", LANE_A)];
    const first = await encryptPermissionStore(records, PASSWORD, identityA);
    const second = await encryptPermissionStore(records, PASSWORD, identityA);
    expect(first.kdf.salt).not.toBe(second.kdf.salt);
    expect(first.cipher.iv).not.toBe(second.cipher.iv);
    expect(first.cipher.ciphertext).not.toBe(second.cipher.ciphertext);
  });

  it("gives one failure for wrong passwords and authenticated tampering", async () => {
    const store = await encryptPermissionStore(
      [grant("https://shop.example", LANE_A, "1000000000000")],
      PASSWORD,
      identityA,
    );

    await expect(
      decryptPermissionStore(store, "wrong password here", identityA),
    ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });

    // Flip a ciphertext byte; GCM authentication must reject it.
    const tampered: WebcPermissionStoreV1 = {
      ...store,
      cipher: {
        ...store.cipher,
        ciphertext:
          store.cipher.ciphertext.slice(0, -2) +
          (store.cipher.ciphertext.endsWith("00") ? "11" : "00"),
      },
    };
    await expect(
      decryptPermissionStore(tampered, PASSWORD, identityA),
    ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
  });

  it("rejects a store belonging to a different wallet identity before KDF work", async () => {
    const store = await encryptPermissionStore(
      [grant("https://shop.example", LANE_A)],
      PASSWORD,
      identityA,
    );
    await expect(
      decryptPermissionStore(store, PASSWORD, identityB),
    ).rejects.toMatchObject({ code: "IDENTITY_MISMATCH" });
  });

  it("rejects grant sets that break their own invariants", async () => {
    // spent above the cumulative cap.
    await expect(
      encryptPermissionStore(
        [grant("https://shop.example", LANE_A, "9999999999999999")],
        PASSWORD,
        identityA,
      ),
    ).rejects.toBeInstanceOf(PermissionStoreError);

    // duplicate origins.
    await expect(
      encryptPermissionStore(
        [grant("https://shop.example", LANE_A), grant("https://shop.example", LANE_B)],
        PASSWORD,
        identityA,
      ),
    ).rejects.toMatchObject({ code: "INVALID_SCHEMA" });

    // insecure (non-https, non-localhost) origin.
    await expect(
      encryptPermissionStore(
        [grant("http://shop.example", LANE_A)],
        PASSWORD,
        identityA,
      ),
    ).rejects.toMatchObject({ code: "INVALID_SCHEMA" });

    // too many grants.
    const many = Array.from({ length: MAX_PERMISSION_GRANTS + 1 }, (_, i) =>
      grant(`https://site${i}.example`, LANE_A),
    );
    await expect(
      encryptPermissionStore(many, PASSWORD, identityA),
    ).rejects.toMatchObject({ code: "INVALID_SCHEMA" });
  });

  it("rejects short passwords when creating but allows them when decrypting", async () => {
    await expect(
      encryptPermissionStore([grant("https://shop.example", LANE_A)], "short", identityA),
    ).rejects.toMatchObject({ code: "INVALID_PASSWORD" });
  });

  it("open/save/reopen persists across a simulated wallet restart", async () => {
    let backing: string | null = null;
    const write = async (serialized: string) => {
      backing = serialized;
    };

    const opened = await openPermissionStore({
      serialized: null,
      password: PASSWORD,
      identity: identityA,
      write,
    });
    expect(opened.records).toEqual([]);
    await opened.port.save([grant("https://shop.example", LANE_A, "500000000000")]);
    expect(backing).not.toBeNull();

    // A fresh wallet session reopens the persisted bytes with only Argon2 once.
    const reopened = await openPermissionStore({
      serialized: backing,
      password: PASSWORD,
      identity: identityA,
      write,
    });
    expect(reopened.records).toHaveLength(1);
    expect(reopened.records[0]?.spent_amount).toBe("500000000000");
    expect(reopened.records[0]?.authorization_lane).toBe(LANE_A);

    // Reopening with the wrong password fails closed.
    await expect(
      openPermissionStore({
        serialized: backing,
        password: "totally wrong password",
        identity: identityA,
        write,
      }),
    ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
  });
});
