/**
 * Enforces WEBC's repository-owned GitHub Actions security policy.
 *
 * Responsibilities: reject mutable action references, missing resource limits,
 * incomplete merge gates, unlocked Rust resolution, and fuzz loops that can
 * silently execute zero targets. Non-responsibilities: parsing arbitrary YAML
 * or replacing GitHub's workflow validator. Data flow is the committed CI file
 * into fixed, fail-closed policy checks. Security boundary: a workflow edit
 * must update this explicit policy deliberately rather than weakening a gate by
 * accident.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const workflowPath = resolve(root, ".github", "workflows", "ci.yml");
const workflow = readFileSync(workflowPath, "utf8");
const failures = [];

function requirePattern(pattern, message) {
  if (!pattern.test(workflow)) failures.push(message);
}

function requireOccurrences(pattern, minimum, message) {
  const count = [...workflow.matchAll(pattern)].length;
  if (count < minimum) failures.push(`${message} (found ${count}, need ${minimum})`);
}

if (/^\s*pull_request_target\s*:/m.test(workflow)) {
  failures.push("pull_request_target is forbidden for workflows that execute PR code");
}

requirePattern(
  /^permissions:\r?\n\s+contents:\s+read\s*$/m,
  "workflow permissions must remain read-only",
);

const actionReferences = [...workflow.matchAll(/^\s*(?:-\s+)?uses:\s+([^\s#]+)/gm)].map(
  (match) => match[1],
);
if (actionReferences.length === 0) failures.push("workflow must use explicitly pinned actions");
for (const reference of actionReferences) {
  if (reference.startsWith("./")) continue;
  if (!/@[0-9a-f]{40}$/.test(reference)) {
    failures.push(`action reference is not pinned to a full commit SHA: ${reference}`);
  }
}

const checkoutCount = actionReferences.filter((reference) =>
  reference.startsWith("actions/checkout@"),
).length;
const credentialGuards = [...workflow.matchAll(/persist-credentials:\s+false/g)].length;
if (checkoutCount === 0 || credentialGuards < checkoutCount) {
  failures.push(
    `every checkout must disable persisted credentials (checkouts ${checkoutCount}, guards ${credentialGuards})`,
  );
}

const lines = workflow.split(/\r?\n/);
const jobs = new Map();
let insideJobs = false;
let currentJob;
for (const line of lines) {
  if (line === "jobs:") {
    insideJobs = true;
    continue;
  }
  if (!insideJobs) continue;
  const heading = /^  ([a-z0-9-]+):\s*$/.exec(line);
  if (heading) {
    currentJob = heading[1];
    jobs.set(currentJob, []);
    continue;
  }
  if (currentJob) jobs.get(currentJob).push(line);
}
for (const [job, body] of jobs) {
  if (!body.some((line) => /^\s{4}timeout-minutes:\s+[1-9][0-9]*\s*$/.test(line))) {
    failures.push(`job ${job} must set timeout-minutes`);
  }
}

requirePattern(
  /toolchain:\s+1\.96\.0/,
  "stable Rust CI must explicitly select toolchain 1.96.0",
);
requirePattern(
  /toolchain:\s+nightly-\d{4}-\d{2}-\d{2}/,
  "fuzz CI must use a dated nightly toolchain",
);
requirePattern(
  /cargo clippy --locked --workspace --all-targets -- -D warnings/,
  "workspace Clippy must use the committed lockfile",
);
requirePattern(
  /cargo clippy --locked --workspace --lib --bins --/,
  "production Clippy must use the committed lockfile",
);
requirePattern(
  /-D clippy::checked_conversions/,
  "production Clippy must reject unchecked numeric conversions",
);
requirePattern(
  /cargo test --locked --workspace/,
  "workspace tests must use the committed lockfile",
);
requirePattern(
  /cargo doc --locked --workspace --no-deps/,
  "rustdoc must use the committed lockfile",
);
requirePattern(
  /cargo run --locked -p webc-node -- demo/,
  "the deterministic node demo is a required merge gate",
);
requireOccurrences(
  /^\s+arguments:\s+--all-features --locked\s*$/gm,
  2,
  "root and fuzz cargo-deny checks must lock dependency resolution",
);
requirePattern(
  /pnpm install --frozen-lockfile/,
  "pnpm installation must use the committed lockfile",
);
requirePattern(
  /pnpm audit --audit-level=moderate/,
  "all JavaScript dependencies must be audited at moderate severity",
);
requirePattern(
  /pnpm licenses:check/,
  "JavaScript dependency licenses must pass the repository allowlist",
);
requirePattern(
  /cargo \+nightly-\d{4}-\d{2}-\d{2} install cargo-fuzz --version 0\.13\.2 --locked/,
  "cargo-fuzz must use the reviewed pinned version",
);
requirePattern(
  /cargo \+nightly-\d{4}-\d{2}-\d{2} metadata --locked --format-version 1/,
  "the independent fuzz lockfile must be checked before execution",
);
if (/for\s+target\s+in\s+\$\(/.test(workflow)) {
  failures.push("command substitution inside a for-list can hide cargo fuzz list failure");
}
requirePattern(
  /targets="\$\(cargo \+nightly-\d{4}-\d{2}-\d{2} fuzz list\)"/,
  "fuzz target discovery must be a standalone fail-fast assignment",
);
requirePattern(/test -n "\$targets"/, "fuzz CI must reject an empty target list");
requirePattern(
  /while IFS= read -r target/,
  "fuzz targets must be consumed without shell word splitting",
);

if (failures.length > 0) {
  console.error(`CI policy violations:\n${failures.map((failure) => `- ${failure}`).join("\n")}`);
  process.exitCode = 1;
} else {
  console.log("GitHub Actions workflow satisfies the WEBC CI security policy.");
}
