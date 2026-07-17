/**
 * Host-side WEBC connection widget for a separate trusted wallet popup.
 *
 * This package never creates, imports, stores, or receives wallet secrets. It
 * opens a configured HTTPS wallet origin and exposes only the public connection
 * plus an exact-origin `WalletHostClient` to the host application.
 */

import {
  WalletHostClient,
  isSecureWalletHostOrigin,
  type WalletConnectionResult,
  type WalletSpendLimitsJson,
} from "@webc/coin";

export interface WebcWidgetOptions {
  /** Element or selector where the widget should be mounted. */
  target: HTMLElement | string;
  /** Optional title shown at the top of the widget. */
  title?: string;
  /** Absolute URL served by a separate trusted wallet HTTPS origin. */
  walletUrl: string;
  /** Spend limits shown and approved by the wallet popup. */
  limits: WalletSpendLimitsJson;
  /** Called with public connection data and the safe host request client. */
  onConnected?: (
    connection: WalletConnectionResult,
    client: WalletHostClient,
  ) => void;
  /** Called when something fails, so host websites can show their own UI. */
  onError?: (error: unknown) => void;
}

/** Handle used to remove listeners and close the popup created by the widget. */
export interface WebcWidgetHandle {
  destroy(): void;
}

/**
 * Mounts a WEBC trusted-popup connection widget.
 *
 * The configured wallet origin must differ from the host origin. Signing and
 * confirmation happen in a top-level popup so the host cannot read secrets or
 * overlay an embedded approval frame. Popup blockers may require another click.
 */
export function mountWebcWidget(options: WebcWidgetOptions): WebcWidgetHandle {
  const target = resolveTarget(options.target);
  const walletUrl = new URL(options.walletUrl, window.location.href);
  if (!isSecureWalletHostOrigin(walletUrl.origin)) {
    throw new Error("WEBC wallet URL must use HTTPS or localhost");
  }
  if (walletUrl.origin === window.location.origin) {
    throw new Error("WEBC wallet must use a separate trusted origin");
  }
  target.replaceChildren();
  let client: WalletHostClient | undefined;
  let popup: Window | null = null;

  const root = document.createElement("section");
  root.style.border = "1px solid currentColor";
  root.style.borderRadius = "12px";
  root.style.padding = "16px";
  root.style.maxWidth = "420px";
  root.style.fontFamily = "system-ui, sans-serif";

  const title = document.createElement("h2");
  title.textContent = options.title ?? "WEBC Wallet";
  title.style.marginTop = "0";

  const description = document.createElement("p");
  description.textContent =
    "Connect through the separate WEBC wallet window. This site never receives your recovery phrase or key.";

  const button = document.createElement("button");
  button.type = "button";
  button.textContent = "Connect WEBC wallet";

  const output = document.createElement("pre");
  output.style.whiteSpace = "pre-wrap";
  output.style.wordBreak = "break-word";

  button.addEventListener("click", async () => {
    button.disabled = true;
    output.textContent = "Opening trusted wallet window...";
    try {
      client?.close();
      popup?.close();
      popup = window.open(
        walletUrl.href,
        "webc-trusted-wallet",
        "popup,width=560,height=760,resizable=yes,scrollbars=yes",
      );
      if (!popup) throw new Error("wallet popup was blocked");
      client = new WalletHostClient({
        walletWindow: popup,
        walletOrigin: walletUrl.origin,
      });
      const connection = await client.connect(options.limits);
      output.textContent = `Connected address:\n${connection.address}\n\nPublic key:\n${connection.public_key}\n\nOrigin lane:\n${connection.authorization_lane}`;
      options.onConnected?.(connection, client);
    } catch (error) {
      client?.close();
      client = undefined;
      output.textContent =
        "Failed to connect the trusted WEBC wallet window. Check popup permissions and wallet origin.";
      options.onError?.(error);
    } finally {
      button.disabled = false;
    }
  });

  root.append(title, description, button, output);
  target.append(root);
  return {
    destroy() {
      client?.close();
      client = undefined;
      popup?.close();
      popup = null;
      target.replaceChildren();
    },
  };
}

function resolveTarget(target: HTMLElement | string): HTMLElement {
  if (typeof target !== "string") return target;
  const element = document.querySelector<HTMLElement>(target);
  if (!element) throw new Error(`WEBC widget target not found: ${target}`);
  return element;
}
