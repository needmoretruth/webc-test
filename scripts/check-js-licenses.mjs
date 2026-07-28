/**
 * Enforces the JavaScript dependency-license allowlist.
 *
 * Responsibilities: validate pnpm's complete installed dependency report and
 * reject any unreviewed license or malformed/empty report. Non-responsibilities:
 * interpreting novel SPDX expressions or deciding license policy. Data flow is
 * `pnpm licenses list --json` on stdin into an explicit allowlist. Security
 * boundary: unknown, missing, composite, or newly introduced licenses fail
 * closed until a reviewer deliberately approves the exact identifier.
 */

import { pathToFileURL } from "node:url";

export const ALLOWED_JAVASCRIPT_LICENSES = new Set([
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "MIT",
  "Unlicense",
  "Zlib",
]);

export function validateLicenseReport(report) {
  if (report === null || Array.isArray(report) || typeof report !== "object") {
    return ["license report must be a JSON object"];
  }

  const groups = Object.entries(report);
  if (groups.length === 0) return ["license report must not be empty"];

  const failures = [];
  for (const [license, packages] of groups) {
    if (!ALLOWED_JAVASCRIPT_LICENSES.has(license)) {
      failures.push(`unapproved license ${JSON.stringify(license)}`);
    }
    if (!Array.isArray(packages) || packages.length === 0) {
      failures.push(`license ${JSON.stringify(license)} has no package records`);
      continue;
    }
    for (const dependency of packages) {
      if (
        dependency === null ||
        typeof dependency !== "object" ||
        typeof dependency.name !== "string" ||
        dependency.name.length === 0 ||
        !Array.isArray(dependency.versions) ||
        dependency.versions.length === 0
      ) {
        failures.push(`license ${JSON.stringify(license)} has a malformed package record`);
      }
    }
  }
  return failures;
}

async function readStandardInput() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

async function main() {
  const input = await readStandardInput();
  let report;
  try {
    report = JSON.parse(input);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.error(`JavaScript license report is not valid JSON: ${detail}`);
    process.exitCode = 1;
    return;
  }

  const failures = validateLicenseReport(report);
  if (failures.length > 0) {
    console.error(`JavaScript license policy violations:\n${failures.join("\n")}`);
    process.exitCode = 1;
  } else {
    console.log(
      `JavaScript dependency licenses are allowed (${Object.keys(report).sort().join(", ")}).`,
    );
  }
}

const entryPoint = process.argv[1] ? pathToFileURL(process.argv[1]).href : undefined;
if (entryPoint === import.meta.url) await main();
