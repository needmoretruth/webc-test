/** Verifies that the emitted ESM package entry loads in a plain Node runtime. */

import {
  WEBC_DEVNET_DERIVATION_PATH_V1,
  createDevnetWalletFromMnemonic,
  TrustedWalletService,
  WalletHostClient,
  createWalletConfirmationUi,
  encryptMnemonicKeystore,
  unlockMnemonicKeystore,
} from "../dist/index.js";

const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const wallet = await createDevnetWalletFromMnemonic(mnemonic);

if (WEBC_DEVNET_DERIVATION_PATH_V1 !== "m/44'/1'/0'/0'/0'") {
  throw new Error("emitted wallet derivation path is incorrect");
}
if (wallet.address !== "webc153HwTorSAA3P8GNpTs1Z19dKPKVt5pmMQa2XbJ8Ff71V") {
  throw new Error("emitted package derives an unexpected public address");
}
if ("privateKey" in wallet) {
  throw new Error("emitted public wallet object exposes a private key handle");
}
if (
  typeof encryptMnemonicKeystore !== "function" ||
  typeof unlockMnemonicKeystore !== "function"
) {
  throw new Error("emitted package is missing keystore v1 entry points");
}
if (
  typeof TrustedWalletService !== "function" ||
  typeof WalletHostClient !== "function" ||
  typeof createWalletConfirmationUi !== "function"
) {
  throw new Error("emitted package is missing isolated wallet entry points");
}
