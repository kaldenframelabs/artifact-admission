#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadPolicy, RECEIPT_SCHEMA, sha256File } from "../../src/gate.mjs";

const [policyArgument, rootArgument, outputArgument, timestampArgument] = process.argv.slice(2);
if (!policyArgument || !rootArgument || !outputArgument || process.argv.length > 6) {
  throw new Error("usage: node synthetic-verifier.mjs <policy.json> <workspace> <receipt.json> [verified-at]");
}

const policy = await loadPolicy(resolve(policyArgument));
const root = resolve(rootArgument);
const subjectSha = await sha256File(resolve(root, policy.subject.path));
if (subjectSha !== policy.subject.sha256) throw new Error("subject digest does not match policy");

for (const item of policy.required_evidence) {
  if (await sha256File(resolve(root, item.path)) !== item.sha256) {
    throw new Error(`evidence digest does not match policy: ${item.path}`);
  }
}

const verifiedAt = timestampArgument || new Date().toISOString();
if (!Number.isFinite(Date.parse(verifiedAt))) throw new Error("verified-at must be a timestamp");
const receipt = {
  schema: RECEIPT_SCHEMA,
  receipt_id: "synthetic-verification-001",
  policy_id: policy.policy_id,
  policy_version: policy.policy_version,
  admission_stage: policy.admission_stage,
  receipt_kind: policy.receipt_kind,
  state: "PASSED",
  subject: { ...policy.subject },
  verified_at: verifiedAt,
  verifier: {
    name: "synthetic-verifier",
    version: "1.0.0",
    source_sha256: await sha256File(fileURLToPath(import.meta.url))
  },
  evidence: policy.required_evidence.map((item) => ({ ...item }))
};

const output = resolve(outputArgument);
await mkdir(dirname(output), { recursive: true });
await writeFile(output, `${JSON.stringify(receipt, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
process.stdout.write(`${output}\n`);
