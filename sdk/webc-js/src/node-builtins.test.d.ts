/** Minimal Node built-in declaration used only by cross-language fixture tests. */
declare module "node:fs" {
  export function readFileSync(path: URL, encoding: "utf8"): string;
}
