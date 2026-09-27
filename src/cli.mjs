#!/usr/bin/env node
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { evaluateAdmission, loadPolicy, sha256File } from "./gate.mjs";

function usage() {
  return `Artifact Admission 0.1.0

Usage:
  artifact-admission verify --policy <policy.json> --root <workspace> [--output <decision.json>] [--compact]
  artifact-admission hash <file>

Exit codes:
  0  artifact admitted (or hash completed)
  1  artifact denied by policy
  2  invalid invocation or unexpected runtime failure`;
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
  const temporary = `${target}.tmp-${process.pid}`;
  try {
    await writeFile(temporary, text, { encoding: "utf8", flag: "wx" });
    await rename(temporary, target);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
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
  const decision = await evaluateAdmission({ root: resolve(root), policy });
  const text = `${JSON.stringify(decision, null, compact ? 0 : 2)}\n`;
  if (output) await writeAtomic(output, text);
  else process.stdout.write(text);
  return decision.decision === "ADMIT" ? 0 : 1;
}

main().then((code) => {
  process.exitCode = code;
}).catch((error) => {
  process.stderr.write(`artifact-admission: ${error.message || error}\n\n${usage()}\n`);
  process.exitCode = 2;
});
