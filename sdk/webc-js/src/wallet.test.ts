/** Wallet recovery, secret-encapsulation, and cross-language signature vectors. */

import { describe, expect, it } from "vitest";
import { bytesToHex } from "./hex";
import {
  createDevnetWalletFromMnemonic,
  generateRecoveryMnemonic,
  isValidRecoveryMnemonic,
  WalletDerivationError,
  webcDevnetDerivationPath,
} from "./wallet-derivation";
import { signWithWallet, verifyEd25519 } from "./wallet";

const BIP39_VECTOR_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

describe("standard wallet derivation", () => {
  it("uses a stable hardened testnet path", () => {
    expect(webcDevnetDerivationPath()).toBe("m/44'/1'/0'/0'/0'");
    expect(webcDevnetDerivationPath(7, 9)).toBe("m/44'/1'/7'/0'/9'");
    expect(() => webcDevnetDerivationPath(-1, 0)).toThrow(
      WalletDerivationError,
    );
    expect(() => webcDevnetDerivationPath(0, 2 ** 31)).toThrow(
      WalletDerivationError,
    );
  });

  it("generates a valid 24-word recovery phrase", () => {
    const mnemonic = generateRecoveryMnemonic();
    expect(mnemonic.split(" ")).toHaveLength(24);
    expect(isValidRecoveryMnemonic(mnemonic)).toBe(true);
  });

  it("derives and signs the fixed Rust-compatible fixture", async () => {
    const wallet = await createDevnetWalletFromMnemonic(BIP39_VECTOR_MNEMONIC);
    const message = new TextEncoder().encode("WEBC_WALLET_DERIVATION_V1");
    const signature = await signWithWallet(wallet, message);

    expect(bytesToHex(wallet.publicKey)).toBe(
      "437541f4d29af2d2f1c2aa568ab16842b06b1820fc654494468d45cbdf5e1b56",
    );
    expect(wallet.address).toBe(
      "webc153HwTorSAA3P8GNpTs1Z19dKPKVt5pmMQa2XbJ8Ff71V",
    );
    expect(bytesToHex(signature)).toBe(
      "02ba5df7a18727d096516c0cea9c7637763a8119077d6a4d1c841115731144ed447bf2d683158d5cb8777d10bc7095c4c0cdc525a291c3ffbb4101ea01455c07",
    );
    expect(await verifyEd25519(wallet.publicKey, message, signature)).toBe(true);
    expect("privateKey" in wallet).toBe(false);
  });

  it("rejects invalid and oversized recovery inputs without echoing them", async () => {
    await expect(
      createDevnetWalletFromMnemonic("abandon ".repeat(12)),
    ).rejects.toMatchObject({ code: "INVALID_MNEMONIC" });
    await expect(
      createDevnetWalletFromMnemonic(BIP39_VECTOR_MNEMONIC, {
        passphrase: "x".repeat(1_025),
      }),
    ).rejects.toMatchObject({ code: "INPUT_TOO_LARGE" });
  });
});
