/**
 * Checks repository-local Markdown links without making network requests.
 * External URLs are intentionally excluded because CI network availability is
 * not a protocol correctness dependency.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, normalize, relative, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const ignored = new Set([".git", "node_modules", "target", "dist"]);

function markdownFiles(directory) {
  return readdirSync(directory).flatMap((name) => {
    if (ignored.has(name)) return [];
    const path = join(directory, name);
    return statSync(path).isDirectory()
      ? markdownFiles(path)
      : path.endsWith(".md")
        ? [path]
        : [];
  });
}

const failures = [];
const linkPattern = /\[[^\]]*\]\(([^)]+)\)/g;

for (const file of markdownFiles(root)) {
  const text = readFileSync(file, "utf8");
  for (const match of text.matchAll(linkPattern)) {
    const raw = match[1].trim().replace(/^<|>$/g, "");
    if (/^(?:https?:|mailto:|#)/i.test(raw)) continue;
    const [pathname] = raw.split("#", 1);
    if (!pathname) continue;
    const target = normalize(resolve(dirname(file), decodeURIComponent(pathname)));
    if (!target.startsWith(root) || !existsSync(target)) {
      failures.push(`${relative(root, file)} -> ${raw}`);
    }
  }
}

if (failures.length > 0) {
  console.error(`Broken local Markdown links:\n${failures.join("\n")}`);
  process.exitCode = 1;
} else {
  console.log("All repository-local Markdown links are valid.");
}
