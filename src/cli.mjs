#!/usr/bin/env node
import { link, lstat, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { evaluateAdmission, loadPolicy, sha256File, validatePolicy } from "./gate.mjs";

function usage() {
  return `Artifact Admission 0.1.1

Usage:
  artifact-admission verify --policy <policy.json> --root <workspace> [--output <decision.json>] [--compact]
  artifact-admission hash <file>

Exit codes:
  0  artifact admitted (or hash completed)
  1  artifact denied by policy
  2  invalid invocation or unexpected runtime failure`;
}

function safeErrorMessage(error) {
  if (error && typeof error.code === "string") return `filesystem operation failed (${error.code})`;
  return String(error?.message || error);
}

function parseVerifyArgs(args) {
  const parsed = { policy: null, root: null, output: null, compact: false };
  const valueFlags = new Map([["--policy", "policy"], ["--root", "root"], ["--output", "output"]]);
  const seen = new Set();
  for (let index = 1; index < args.length; index += 1) {
    const flag = args[index];
    if (flag === "--compact") {
      if (seen.has(flag)) throw new Error(`${flag} may be provided only once`);
      seen.add(flag);
      parsed.compact = true;
      continue;
    }
    const key = valueFlags.get(flag);
    if (!key) throw new Error(`unknown verify argument: ${flag}`);
    if (seen.has(flag)) throw new Error(`${flag} may be provided only once`);
    seen.add(flag);
    const value = args[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`${flag} requires a value`);
    parsed[key] = value;
    index += 1;
  }
  return parsed;
}

async function writeAtomic(path, text) {
  const target = resolve(path);
  await mkdir(dirname(target), { recursive: true });
  try {
    await lstat(target);
    const error = new Error("output path already exists");
    error.code = "EEXIST";
    throw error;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const temporary = `${target}.tmp-${process.pid}`;
  try {
    await writeFile(temporary, text, { encoding: "utf8", flag: "wx" });
    await link(temporary, target);
    await rm(temporary);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

function pathIsWithin(parent, candidate) {
  const rel = relative(parent, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

function validateOutputPath(output, policyPath, root, policy) {
  const target = resolve(output);
  const protectedFiles = [
    resolve(policyPath),
    resolve(root, policy.subject.path),
    ...policy.required_evidence.map((item) => resolve(root, item.path)),
    ...policy.deny_if_paths_exist.map((item) => resolve(root, item))
  ];
  if (protectedFiles.some((path) => relative(path, target) === "")) {
    throw new Error("--output must not overlap the policy, subject, evidence, or deny-marker paths");
  }
  if (pathIsWithin(resolve(root, policy.receipt_directory), target)) {
    throw new Error("--output must not be inside the configured receipt directory");
  }
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  if (!command || command === "--help" || command === "-h") {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }

  if (command === "hash") {
    if (args.length !== 2) throw new Error("hash requires exactly one file path");
    process.stdout.write(`${await sha256File(resolve(args[1]))}\n`);
    return 0;
  }

  if (command !== "verify") throw new Error(`unknown command: ${command}`);
  const { policy: policyPath, root, output, compact } = parseVerifyArgs(args);
  if (!policyPath || !root) throw new Error("verify requires --policy and --root");

  const policy = await loadPolicy(resolve(policyPath));
  if (output && validatePolicy(policy).length === 0) validateOutputPath(output, policyPath, root, policy);
  const decision = await evaluateAdmission({ root: resolve(root), policy });
  const text = `${JSON.stringify(decision, null, compact ? 0 : 2)}\n`;
  if (output) await writeAtomic(output, text);
  else process.stdout.write(text);
  return decision.decision === "ADMIT" ? 0 : 1;
}

main().then((code) => {
  process.exitCode = code;
}).catch((error) => {
  process.stderr.write(`artifact-admission: ${safeErrorMessage(error)}\n\n${usage()}\n`);
  process.exitCode = 2;
});
