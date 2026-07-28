/**
 * Regression tests for the fail-closed JavaScript dependency-license policy.
 *
 * Responsibilities: prove allowed packages pass and unknown, forbidden, empty,
 * or malformed reports fail. Non-responsibilities: querying pnpm or the npm
 * registry. Data flow is fixed in-memory reports into the policy validator.
 * Security boundary: a permissive-policy regression must fail before CI accepts
 * a changed dependency graph.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { validateLicenseReport } from "./check-js-licenses.mjs";

const packageRecord = { name: "example", versions: ["1.0.0"] };

test("accepts the complete standing permissive allowlist", () => {
  const report = {
    "Apache-2.0": [packageRecord],
    "BSD-2-Clause": [packageRecord],
    "BSD-3-Clause": [packageRecord],
    ISC: [packageRecord],
    MIT: [packageRecord],
    Unlicense: [packageRecord],
    Zlib: [packageRecord],
  };
  assert.deepEqual(validateLicenseReport(report), []);
});

test("rejects a copyleft dependency", () => {
  assert.deepEqual(validateLicenseReport({ "AGPL-3.0-only": [packageRecord] }), [
    'unapproved license "AGPL-3.0-only"',
  ]);
});

test("rejects unknown composite expressions pending explicit review", () => {
  assert.deepEqual(validateLicenseReport({ "MIT OR GPL-3.0-only": [packageRecord] }), [
    'unapproved license "MIT OR GPL-3.0-only"',
  ]);
});

test("rejects empty and malformed reports", () => {
  assert.deepEqual(validateLicenseReport({}), ["license report must not be empty"]);
  assert.deepEqual(validateLicenseReport({ MIT: [] }), [
    'license "MIT" has no package records',
  ]);
  assert.deepEqual(validateLicenseReport({ MIT: [{ name: "example", versions: [] }] }), [
    'license "MIT" has a malformed package record',
  ]);
});
