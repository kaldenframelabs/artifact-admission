import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import {
  BOUNDARY,
  POLICY_SCHEMA,
  RECEIPT_SCHEMA,
  evaluateAdmission,
  isSafeRelativePath,
  isValidRfc3339,
  loadPolicy,
  parseStrictJson,
  sha256File,
  validatePolicy,
  validateReceipt
} from "../src/gate.mjs";

const NOW = new Date("2026-09-27T18:00:00Z");

async function makeFixture(t) {
  const base = await mkdtemp(join(tmpdir(), "artifact-admission-test-"));
  t.after(() => rm(base, { recursive: true, force: true }));
  const root = join(base, "workspace");
  const subjectPath = join(root, "dist", "application.txt");
  const evidencePath = join(root, "reports", "verification.json");
  const receiptDirectory = join(root, "receipts");
  await mkdir(join(root, "dist"), { recursive: true });
  await mkdir(join(root, "reports"), { recursive: true });
  await mkdir(receiptDirectory, { recursive: true });
  await writeFile(subjectPath, "synthetic application\n", "utf8");
  await writeFile(evidencePath, "{\"result\":\"passed\"}\n", "utf8");
  const subjectSha = await sha256File(subjectPath);
  const evidenceSha = await sha256File(evidencePath);
  const policy = {
    schema: POLICY_SCHEMA,
    policy_id: "synthetic-release",
    policy_version: "1",
    admission_stage: "reviewed",
    receipt_kind: "independent-verification",
    subject: { path: "dist/application.txt", sha256: subjectSha },
    receipt_directory: "receipts",
    allowed_states: ["PASSED"],
    max_receipt_age_hours: 24,
    allowed_verifiers: [{
      name: "synthetic-verifier",
      version: "1.0.0",
      source_sha256: "1".repeat(64)
    }],
    deny_if_paths_exist: ["governance/REVOKED"],
    required_evidence: [{ path: "reports/verification.json", sha256: evidenceSha }]
  };
  const receipt = {
    schema: RECEIPT_SCHEMA,
    receipt_id: "synthetic-verification-001",
    policy_id: policy.policy_id,
    policy_version: policy.policy_version,
    admission_stage: policy.admission_stage,
    receipt_kind: policy.receipt_kind,
    state: "PASSED",
    subject: { ...policy.subject },
    verified_at: "2026-09-27T17:00:00Z",
    verifier: {
      name: "synthetic-verifier",
      version: "1.0.0",
      source_sha256: "1".repeat(64)
    },
    evidence: [{ ...policy.required_evidence[0] }]
  };
  const receiptPath = join(receiptDirectory, "verification.json");
  await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  const policyPath = join(base, "policy.json");
  await writeFile(policyPath, `${JSON.stringify(policy, null, 2)}\n`, "utf8");
  return { base, root, subjectPath, evidencePath, receiptDirectory, receiptPath, policyPath, policy, receipt };
}

async function decide(fixture, policy = fixture.policy) {
  return evaluateAdmission({ root: fixture.root, policy, now: NOW });
}

function deniedCheck(decision, id) {
  return decision.checks.find((check) => check.id === id && check.status === "DENY");
}

test("valid synthetic packet is admitted with a repeated boundary", async (t) => {
  const fixture = await makeFixture(t);
  const decision = await decide(fixture);
  assert.equal(decision.decision, "ADMIT");
  assert.equal(decision.summary.denied, 0);
  assert.equal(decision.boundary, BOUNDARY);
  assert.equal(decision.checks.length, 14);
  assert.equal(decision.receipt.file, "verification.json");
  assert.equal(decision.receipt.sha256, await sha256File(fixture.receiptPath));
});

test("subject hash mismatch denies admission", async (t) => {
  const fixture = await makeFixture(t);
  await writeFile(fixture.subjectPath, "changed application\n", "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.ok(deniedCheck(decision, "subject.hash"));
});

test("unsafe traversal in policy is rejected before workspace reads", async (t) => {
  const fixture = await makeFixture(t);
  const policy = structuredClone(fixture.policy);
  policy.subject.path = "../outside.bin";
  const decision = await decide(fixture, policy);
  assert.equal(decision.decision, "DENY");
  assert.ok(deniedCheck(decision, "policy.valid"));
  assert.equal(decision.checks.length, 1);
});

test("filesystem errors do not disclose absolute workspace paths", async (t) => {
  const fixture = await makeFixture(t);
  const missingRoot = join(fixture.base, "missing-workspace");
  const decision = await evaluateAdmission({ root: missingRoot, policy: fixture.policy, now: NOW });
  assert.equal(decision.decision, "DENY");
  assert.deepEqual(deniedCheck(decision, "workspace.available").details, { code: "ENOENT" });
  assert.equal(JSON.stringify(decision).includes(fixture.base), false);
});

test("configured terminal marker denies admission", async (t) => {
  const fixture = await makeFixture(t);
  await mkdir(join(fixture.root, "governance"), { recursive: true });
  await writeFile(join(fixture.root, "governance", "REVOKED"), "revoked\n", "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.ok(deniedCheck(decision, "terminal_markers.absent"));
});

test("stale receipt denies admission", async (t) => {
  const fixture = await makeFixture(t);
  fixture.receipt.verified_at = "2026-09-25T17:00:00Z";
  await writeFile(fixture.receiptPath, JSON.stringify(fixture.receipt), "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.match(deniedCheck(decision, "receipt.freshness").message, /stale/i);
});

test("future-dated receipt denies admission", async (t) => {
  const fixture = await makeFixture(t);
  fixture.receipt.verified_at = "2026-09-27T19:00:00Z";
  await writeFile(fixture.receiptPath, JSON.stringify(fixture.receipt), "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.match(deniedCheck(decision, "receipt.freshness").message, /future/i);
});

test("two matching receipts deny as ambiguous", async (t) => {
  const fixture = await makeFixture(t);
  const second = structuredClone(fixture.receipt);
  second.receipt_id = "synthetic-verification-002";
  await writeFile(join(fixture.receiptDirectory, "second.json"), JSON.stringify(second), "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.equal(deniedCheck(decision, "receipts.unambiguous").details.matching_files.length, 2);
});

test("receipt for a different lifecycle stage does not match", async (t) => {
  const fixture = await makeFixture(t);
  fixture.receipt.admission_stage = "experimental";
  await writeFile(fixture.receiptPath, JSON.stringify(fixture.receipt), "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.deepEqual(deniedCheck(decision, "receipts.unambiguous").details.matching_files, []);
});

test("changed evidence file denies both file and receipt binding checks", async (t) => {
  const fixture = await makeFixture(t);
  await writeFile(fixture.evidencePath, "{\"result\":\"changed\"}\n", "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.ok(deniedCheck(decision, "evidence.file:reports/verification.json"));
  assert.ok(deniedCheck(decision, "evidence.receipt:reports/verification.json"));
});

test("missing verifier source digest denies verifier identity", async (t) => {
  const fixture = await makeFixture(t);
  delete fixture.receipt.verifier.source_sha256;
  await writeFile(fixture.receiptPath, JSON.stringify(fixture.receipt), "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.ok(deniedCheck(decision, "receipt.verifier_identity"));
});

test("unlisted verifier source digest denies verifier identity", async (t) => {
  const fixture = await makeFixture(t);
  fixture.receipt.verifier.source_sha256 = "2".repeat(64);
  await writeFile(fixture.receiptPath, JSON.stringify(fixture.receipt), "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.ok(deniedCheck(decision, "receipt.verifier_identity"));
});

test("malformed extra receipt denies the receipt set", async (t) => {
  const fixture = await makeFixture(t);
  await writeFile(join(fixture.receiptDirectory, "broken.json"), "{not json", "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.ok(deniedCheck(decision, "receipts.valid"));
});

test("duplicate JSON keys are rejected at every object depth", () => {
  assert.throws(() => parseStrictJson('{"policy_id":"first","policy_id":"second"}'), /Duplicate JSON object key/);
  assert.throws(() => parseStrictJson('{"subject":{"path":"a","p\\u0061th":"b"}}'), /Duplicate JSON object key/);
  assert.deepEqual(parseStrictJson('{"values":[true,false,null,1.5e2]}'), { values: [true, false, null, 150] });
});

test("duplicate keys in a receipt deny the receipt set", async (t) => {
  const fixture = await makeFixture(t);
  await writeFile(fixture.receiptPath, '{"schema":"kaldenframe.artifact-admission.receipt.v1","schema":"kaldenframe.artifact-admission.receipt.v1"}', "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.match(JSON.stringify(deniedCheck(decision, "receipts.valid").details), /Duplicate JSON object key/);
});

test("receipt set over 200 JSON entries denies before parsing", async (t) => {
  const fixture = await makeFixture(t);
  await Promise.all(Array.from({ length: 200 }, (_, index) => writeFile(join(fixture.receiptDirectory, `extra-${String(index).padStart(3, "0")}.json`), "{}", "utf8")));
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.equal(deniedCheck(decision, "receipts.bounded").details.count, 201);
});

test("oversized receipt denies without being parsed", async (t) => {
  const fixture = await makeFixture(t);
  await writeFile(join(fixture.receiptDirectory, "oversized.json"), `${" ".repeat(256 * 1024)}{}`, "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.match(JSON.stringify(deniedCheck(decision, "receipts.valid").details), /exceeds 262144 bytes/);
});

test("policy loader rejects oversized and duplicate-key policies", async (t) => {
  const fixture = await makeFixture(t);
  await writeFile(fixture.policyPath, '{"schema":"one","schema":"two"}', "utf8");
  await assert.rejects(loadPolicy(fixture.policyPath), /Duplicate JSON object key/);
  await writeFile(fixture.policyPath, `${" ".repeat(256 * 1024)}{}`, "utf8");
  await assert.rejects(loadPolicy(fixture.policyPath), /exceeds 262144 bytes/);
});

test("receipt symlink escaping the workspace denies admission", async (t) => {
  const fixture = await makeFixture(t);
  const outside = join(fixture.base, "outside-receipt.json");
  await writeFile(outside, JSON.stringify(fixture.receipt), "utf8");
  await rm(fixture.receiptPath);
  try {
    await symlink(outside, fixture.receiptPath, "file");
  } catch (error) {
    if (error?.code === "EPERM") return t.skip("Creating file symlinks requires Windows Developer Mode or elevated rights.");
    throw error;
  }
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.match(JSON.stringify(deniedCheck(decision, "receipts.valid").details), /escapes the workspace root/);
});

test("unknown receipt fields deny instead of being ignored", async (t) => {
  const fixture = await makeFixture(t);
  fixture.receipt.unreviewed_extension = true;
  await writeFile(fixture.receiptPath, JSON.stringify(fixture.receipt), "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.ok(deniedCheck(decision, "receipts.valid"));
});

test("impossible calendar timestamp is rejected", async (t) => {
  const fixture = await makeFixture(t);
  fixture.receipt.verified_at = "2026-02-30T12:00:00Z";
  await writeFile(fixture.receiptPath, JSON.stringify(fixture.receipt), "utf8");
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.ok(deniedCheck(decision, "receipts.valid"));
});

test("no matching receipt denies admission", async (t) => {
  const fixture = await makeFixture(t);
  await rm(fixture.receiptPath);
  const decision = await decide(fixture);
  assert.equal(decision.decision, "DENY");
  assert.deepEqual(deniedCheck(decision, "receipts.unambiguous").details.matching_files, []);
});

test("decision is deterministic for the same inputs and clock", async (t) => {
  const fixture = await makeFixture(t);
  const first = await decide(fixture);
  const second = await decide(fixture);
  assert.deepEqual(first, second);
});

test("path and timestamp primitives reject boundary cases", () => {
  assert.equal(isSafeRelativePath("reports/result.json"), true);
  assert.equal(isSafeRelativePath("../result.json"), false);
  assert.equal(isSafeRelativePath("reports//result.json"), false);
  assert.equal(isSafeRelativePath("C:\\secret.txt"), false);
  assert.equal(isSafeRelativePath("reports\\result.json"), false);
  assert.equal(isSafeRelativePath("reports/./result.json"), false);
  assert.equal(isSafeRelativePath("reports/NUL.txt"), false);
  assert.equal(isSafeRelativePath("reports/result.json."), false);
  assert.equal(isSafeRelativePath("reports/result.json:stream"), false);
  assert.equal(isValidRfc3339("2024-02-29T23:59:59+14:00"), true);
  assert.equal(isValidRfc3339("2026-02-29T12:00:00Z"), false);
  assert.equal(isValidRfc3339("2026-01-01T24:00:00Z"), false);
  assert.equal(isValidRfc3339("2026-01-01T12:00:00+14:01"), false);
});

test("runtime validators reject unknown policy keys and duplicate evidence", () => {
  const policy = {
    schema: POLICY_SCHEMA,
    policy_id: "p",
    policy_version: "1",
    admission_stage: "reviewed",
    receipt_kind: "verification",
    subject: { path: "a.bin", sha256: "a".repeat(64) },
    receipt_directory: "receipts",
    allowed_states: ["PASSED", "PASSED"],
    max_receipt_age_hours: 1,
    allowed_verifiers: [
      { name: "v", version: "1", source_sha256: "1".repeat(64) },
      { name: "v", version: "1", source_sha256: "1".repeat(64) }
    ],
    deny_if_paths_exist: [],
    required_evidence: [
      { path: "report.json", sha256: "b".repeat(64) },
      { path: "report.json", sha256: "b".repeat(64) }
    ],
    extra: true
  };
  const errors = validatePolicy(policy).join("\n");
  assert.match(errors, /unknown keys/);
  assert.match(errors, /allowed_states must not contain duplicates/);
  assert.match(errors, /allowed_verifiers contains duplicate identity/);
  assert.match(errors, /duplicate path/);
});

test("receipt validator accepts optional source digest only when well formed", () => {
  const receipt = {
    schema: RECEIPT_SCHEMA,
    receipt_id: "r",
    policy_id: "p",
    policy_version: "1",
    admission_stage: "reviewed",
    receipt_kind: "verification",
    state: "PASSED",
    subject: { path: "a.bin", sha256: "a".repeat(64) },
    verified_at: "2026-09-27T17:00:00Z",
    verifier: { name: "v", version: "1" },
    evidence: []
  };
  assert.deepEqual(validateReceipt(receipt), []);
  receipt.verifier.source_sha256 = "bad";
  assert.match(validateReceipt(receipt).join("\n"), /source_sha256/);
});

test("CLI emits ADMIT with exit 0 and DENY with exit 1", async (t) => {
  const fixture = await makeFixture(t);
  const cli = resolve(import.meta.dirname, "..", "src", "cli.mjs");
  const cwd = resolve(import.meta.dirname, "..");
  const admitted = spawnSync(process.execPath, [cli, "verify", "--policy", fixture.policyPath, "--root", fixture.root, "--compact"], { cwd, encoding: "utf8" });
  assert.equal(admitted.status, 0, admitted.stderr);
  assert.equal(JSON.parse(admitted.stdout).decision, "ADMIT");

  await writeFile(fixture.subjectPath, "changed\n", "utf8");
  const denied = spawnSync(process.execPath, [cli, "verify", "--policy", fixture.policyPath, "--root", fixture.root, "--compact"], { cwd, encoding: "utf8" });
  assert.equal(denied.status, 1, denied.stderr);
  assert.equal(JSON.parse(denied.stdout).decision, "DENY");
});

test("CLI rejects unknown and duplicate flags with exit 2", async (t) => {
  const fixture = await makeFixture(t);
  const cli = resolve(import.meta.dirname, "..", "src", "cli.mjs");
  const cwd = resolve(import.meta.dirname, "..");
  const unknown = spawnSync(process.execPath, [cli, "verify", "--policy", fixture.policyPath, "--root", fixture.root, "--surprise"], { cwd, encoding: "utf8" });
  assert.equal(unknown.status, 2);
  assert.match(unknown.stderr, /unknown verify argument/);
  const duplicate = spawnSync(process.execPath, [cli, "verify", "--policy", fixture.policyPath, "--policy", fixture.policyPath, "--root", fixture.root], { cwd, encoding: "utf8" });
  assert.equal(duplicate.status, 2);
  assert.match(duplicate.stderr, /only once/);
});

test("CLI writes a complete decision atomically without leaving temp files", async (t) => {
  const fixture = await makeFixture(t);
  const cli = resolve(import.meta.dirname, "..", "src", "cli.mjs");
  const cwd = resolve(import.meta.dirname, "..");
  const output = join(fixture.base, "nested", "decision.json");
  const result = spawnSync(process.execPath, [cli, "verify", "--policy", fixture.policyPath, "--root", fixture.root, "--output", output], { cwd, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(await readFile(output, "utf8")).decision, "ADMIT");
  assert.deepEqual((await readdir(join(fixture.base, "nested"))).filter((name) => name.includes(".tmp-")), []);
});

test("CLI hash matches the library digest", async (t) => {
  const fixture = await makeFixture(t);
  const cli = resolve(import.meta.dirname, "..", "src", "cli.mjs");
  const cwd = resolve(import.meta.dirname, "..");
  const result = spawnSync(process.execPath, [cli, "hash", fixture.subjectPath], { cwd, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), await sha256File(fixture.subjectPath));
});

test("example policy and receipt remain parseable JSON", async () => {
  const base = resolve(import.meta.dirname, "..", "examples", "valid");
  assert.equal(JSON.parse(await readFile(join(base, "policy.json"), "utf8")).schema, POLICY_SCHEMA);
  const receipt = JSON.parse(await readFile(join(base, "workspace", "receipts", "verification.json"), "utf8"));
  assert.equal(receipt.schema, RECEIPT_SCHEMA);
  assert.equal(receipt.verifier.source_sha256, await sha256File(join(base, "synthetic-verifier.mjs")));
});

test("synthetic verifier reproduces the bundled receipt exactly", async (t) => {
  const base = resolve(import.meta.dirname, "..", "examples", "valid");
  const temporary = await mkdtemp(join(tmpdir(), "artifact-admission-verifier-"));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const output = join(temporary, "receipt.json");
  const verifier = join(base, "synthetic-verifier.mjs");
  const result = spawnSync(process.execPath, [verifier, join(base, "policy.json"), join(base, "workspace"), output, "2026-09-27T18:10:00Z"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(await readFile(output, "utf8")), JSON.parse(await readFile(join(base, "workspace", "receipts", "verification.json"), "utf8")));
});
