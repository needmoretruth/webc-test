/** Adversarial tests for authenticated encrypted recovery-keystore v1. */

import { describe, expect, it } from "vitest";
import {
  KEYSTORE_ARGON2_MEMORY_KIB,
  KeystoreError,
  encryptMnemonicKeystore,
  parseKeystore,
  serializeKeystore,
  unlockMnemonicKeystore,
  type WebcKeystoreV1,
} from "./keystore";

const MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSWORD = "correct horse battery staple";

describe("encrypted keystore v1", () => {
  it("round-trips through strict JSON and recovers only the public wallet", async () => {
    const encrypted = await encryptMnemonicKeystore(MNEMONIC, PASSWORD, {
      account: 2,
      index: 3,
      mnemonicPassphrase: "optional recovery branch",
    });
    const parsed = parseKeystore(serializeKeystore(encrypted));
    const wallet = await unlockMnemonicKeystore(parsed, PASSWORD);

    expect(wallet.address).toBe(encrypted.public.address);
    expect("privateKey" in wallet).toBe(false);
    expect(encrypted.kdf.memory_kib).toBe(KEYSTORE_ARGON2_MEMORY_KIB);
    expect(JSON.stringify(encrypted)).not.toContain(MNEMONIC);
    expect(JSON.stringify(encrypted)).not.toContain("optional recovery branch");
  }, 15_000);

  it("uses fresh salt and IV for repeated exports", async () => {
    const [first, second] = await Promise.all([
      encryptMnemonicKeystore(MNEMONIC, PASSWORD),
      encryptMnemonicKeystore(MNEMONIC, PASSWORD),
    ]);
    expect(first.kdf.salt).not.toBe(second.kdf.salt);
    expect(first.cipher.iv).not.toBe(second.cipher.iv);
    expect(first.cipher.ciphertext).not.toBe(second.cipher.ciphertext);
    const [firstWallet, secondWallet] = await Promise.all([
      unlockMnemonicKeystore(first, PASSWORD),
      unlockMnemonicKeystore(second, PASSWORD),
    ]);
    expect(firstWallet.address).toBe(secondWallet.address);
  }, 15_000);

  it("gives one failure for wrong passwords and authenticated tampering", async () => {
    const encrypted = await encryptMnemonicKeystore(MNEMONIC, PASSWORD);
    await expect(
      unlockMnemonicKeystore(encrypted, "wrong password that is long enough"),
    ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });

    const last = encrypted.cipher.ciphertext.at(-1) === "0" ? "1" : "0";
    const tampered: WebcKeystoreV1 = {
      ...encrypted,
      cipher: {
        ...encrypted.cipher,
        ciphertext: encrypted.cipher.ciphertext.slice(0, -1) + last,
      },
    };
    await expect(
      unlockMnemonicKeystore(tampered, PASSWORD),
    ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });

    const metadataTampered: WebcKeystoreV1 = {
      ...encrypted,
      public: {
        ...encrypted.public,
        address: "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3",
      },
    };
    await expect(
      unlockMnemonicKeystore(metadataTampered, PASSWORD),
    ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
  }, 15_000);

  it("rejects hostile cost fields and unknown keys before KDF work", async () => {
    const encrypted = await encryptMnemonicKeystore(MNEMONIC, PASSWORD);
    const hostile = {
      ...encrypted,
      kdf: { ...encrypted.kdf, memory_kib: 2 ** 31 },
    };
    await expect(unlockMnemonicKeystore(hostile, PASSWORD)).rejects.toMatchObject({
      code: "INVALID_SCHEMA",
    });
    expect(() =>
      parseKeystore(JSON.stringify({ ...encrypted, surprise: true })),
    ).toThrow(KeystoreError);
    expect(() =>
      parseKeystore(
        JSON.stringify({
          ...encrypted,
          public: {
            ...encrypted.public,
            public_key: encrypted.public.public_key.toUpperCase(),
          },
        }),
      ),
    ).toThrow(KeystoreError);
  }, 15_000);

  it("rejects weak, oversized, and invalid-Unicode passwords", async () => {
    await expect(
      encryptMnemonicKeystore(MNEMONIC, "too short"),
    ).rejects.toMatchObject({ code: "INVALID_PASSWORD" });
    await expect(
      encryptMnemonicKeystore(MNEMONIC, "x".repeat(1_025)),
    ).rejects.toMatchObject({ code: "INVALID_PASSWORD" });
    await expect(
      encryptMnemonicKeystore(MNEMONIC, `valid prefix ${String.fromCharCode(0xd800)}`),
    ).rejects.toMatchObject({ code: "INVALID_PASSWORD" });
  });
});
