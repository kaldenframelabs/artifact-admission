import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, readFile, readdir, realpath, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

export const POLICY_SCHEMA = "kaldenframe.artifact-admission.policy.v1";
export const RECEIPT_SCHEMA = "kaldenframe.artifact-admission.receipt.v1";
export const DECISION_SCHEMA = "kaldenframe.artifact-admission.decision.v1";
export const BOUNDARY = "Local consistency and policy admission only; not a signature, provenance attestation, security audit, or guarantee that an artifact is safe or fit for use.";

const SHA256_RE = /^[a-f0-9]{64}$/;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const MAX_POLICY_BYTES = 256 * 1024;
const MAX_RECEIPT_BYTES = 256 * 1024;
const MAX_RECEIPTS = 200;

function makeCheck(id, passed, message, details) {
  const row = { id, status: passed ? "PASS" : "DENY", message };
  if (details !== undefined) row.details = details;
  return row;
}

function safeErrorDetail(error) {
  if (error && typeof error.code === "string") return { code: error.code };
  return String(error?.message || error);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateId(value) {
  return typeof value === "string" && ID_RE.test(value);
}

function validateSha(value) {
  return typeof value === "string" && SHA256_RE.test(value);
}

function rejectUnknownKeys(value, allowed, label, errors) {
  if (!isPlainObject(value)) return;
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key)).sort();
  if (unknown.length) errors.push(`${label} contains unknown keys: ${unknown.join(", ")}`);
}

export function validatePolicy(policy) {
  const errors = [];
  if (!isPlainObject(policy)) return ["Policy must be a JSON object."];
  rejectUnknownKeys(policy, ["schema", "policy_id", "policy_version", "admission_stage", "receipt_kind", "subject", "receipt_directory", "allowed_states", "max_receipt_age_hours", "allowed_verifiers", "deny_if_paths_exist", "required_evidence"], "policy", errors);
  if (policy.schema !== POLICY_SCHEMA) errors.push(`schema must equal ${POLICY_SCHEMA}`);
  for (const key of ["policy_id", "policy_version", "admission_stage", "receipt_kind"]) {
    if (!validateId(policy[key])) errors.push(`${key} must be a non-empty portable identifier`);
  }
  if (!isPlainObject(policy.subject)) errors.push("subject must be an object");
  else {
    rejectUnknownKeys(policy.subject, ["path", "sha256"], "subject", errors);
    if (!isSafeRelativePath(policy.subject.path)) errors.push("subject.path must be a contained relative path");
    if (!validateSha(policy.subject.sha256)) errors.push("subject.sha256 must be a lowercase SHA-256 digest");
  }
  if (!isSafeRelativePath(policy.receipt_directory)) errors.push("receipt_directory must be a contained relative path");
  if (!Array.isArray(policy.allowed_states) || policy.allowed_states.length === 0 || policy.allowed_states.some((value) => !validateId(value))) {
    errors.push("allowed_states must be a non-empty array of portable identifiers");
  } else if (new Set(policy.allowed_states).size !== policy.allowed_states.length) {
    errors.push("allowed_states must not contain duplicates");
  }
  if (typeof policy.max_receipt_age_hours !== "number" || !Number.isFinite(policy.max_receipt_age_hours) || policy.max_receipt_age_hours <= 0 || policy.max_receipt_age_hours > 8760) {
    errors.push("max_receipt_age_hours must be greater than 0 and no more than 8760");
  }
  if (!Array.isArray(policy.allowed_verifiers) || policy.allowed_verifiers.length === 0) {
    errors.push("allowed_verifiers must be a non-empty array");
  } else {
    const seen = new Set();
    for (const [index, verifier] of policy.allowed_verifiers.entries()) {
      rejectUnknownKeys(verifier, ["name", "version", "source_sha256"], `allowed_verifiers[${index}]`, errors);
      if (!isPlainObject(verifier) || !validateId(verifier.name) || !validateId(verifier.version) || !validateSha(verifier.source_sha256)) {
        errors.push(`allowed_verifiers[${index}] must contain a portable name, portable version, and lowercase SHA-256 source digest`);
      } else {
        const identity = `${verifier.name}\u0000${verifier.version}\u0000${verifier.source_sha256}`;
        if (seen.has(identity)) errors.push(`allowed_verifiers contains duplicate identity at index ${index}`);
        seen.add(identity);
      }
    }
  }
  if (!Array.isArray(policy.deny_if_paths_exist) || policy.deny_if_paths_exist.some((value) => !isSafeRelativePath(value))) {
    errors.push("deny_if_paths_exist must be an array of contained relative paths");
  } else if (new Set(policy.deny_if_paths_exist).size !== policy.deny_if_paths_exist.length) {
    errors.push("deny_if_paths_exist must not contain duplicates");
  }
  if (!Array.isArray(policy.required_evidence)) errors.push("required_evidence must be an array");
  else {
    const seen = new Set();
    for (const [index, item] of policy.required_evidence.entries()) {
      rejectUnknownKeys(item, ["path", "sha256"], `required_evidence[${index}]`, errors);
      if (!isPlainObject(item) || !isSafeRelativePath(item.path) || !validateSha(item.sha256)) {
        errors.push(`required_evidence[${index}] must contain a relative path and lowercase SHA-256 digest`);
      } else if (seen.has(item.path)) {
        errors.push(`required_evidence contains duplicate path ${item.path}`);
      } else {
        seen.add(item.path);
      }
    }
  }
  return errors;
}

export function validateReceipt(receipt) {
  const errors = [];
  if (!isPlainObject(receipt)) return ["Receipt must be a JSON object."];
  rejectUnknownKeys(receipt, ["schema", "receipt_id", "policy_id", "policy_version", "admission_stage", "receipt_kind", "state", "subject", "verified_at", "verifier", "evidence"], "receipt", errors);
  if (receipt.schema !== RECEIPT_SCHEMA) errors.push(`schema must equal ${RECEIPT_SCHEMA}`);
  for (const key of ["receipt_id", "policy_id", "policy_version", "admission_stage", "receipt_kind", "state"]) {
    if (!validateId(receipt[key])) errors.push(`${key} must be a non-empty portable identifier`);
  }
  if (!isPlainObject(receipt.subject)) errors.push("subject must be an object");
  else {
    rejectUnknownKeys(receipt.subject, ["path", "sha256"], "subject", errors);
    if (!isSafeRelativePath(receipt.subject.path)) errors.push("subject.path must be a contained relative path");
    if (!validateSha(receipt.subject.sha256)) errors.push("subject.sha256 must be a lowercase SHA-256 digest");
  }
  if (!isValidRfc3339(receipt.verified_at)) errors.push("verified_at must be a real RFC 3339 timestamp");
  if (!isPlainObject(receipt.verifier)) errors.push("verifier must be an object");
  else {
    rejectUnknownKeys(receipt.verifier, ["name", "version", "source_sha256"], "verifier", errors);
    if (!validateId(receipt.verifier.name)) errors.push("verifier.name must be a portable identifier");
    if (!validateId(receipt.verifier.version)) errors.push("verifier.version must be a portable identifier");
    if (receipt.verifier.source_sha256 !== undefined && !validateSha(receipt.verifier.source_sha256)) {
      errors.push("verifier.source_sha256 must be a lowercase SHA-256 digest when present");
    }
  }
  if (!Array.isArray(receipt.evidence)) errors.push("evidence must be an array");
  else {
    const seen = new Set();
    for (const [index, item] of receipt.evidence.entries()) {
      rejectUnknownKeys(item, ["path", "sha256"], `evidence[${index}]`, errors);
      if (!isPlainObject(item) || !isSafeRelativePath(item.path) || !validateSha(item.sha256)) {
        errors.push(`evidence[${index}] must contain a relative path and lowercase SHA-256 digest`);
      } else if (seen.has(item.path)) {
        errors.push(`evidence contains duplicate path ${item.path}`);
      } else {
        seen.add(item.path);
      }
    }
  }
  return errors;
}

export function isSafeRelativePath(value) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0") || value.includes("\\") || value.includes(":") || isAbsolute(value)) return false;
  if (value.startsWith("/") || /[\u0000-\u001f\u007f]/.test(value)) return false;
  const parts = value.split("/");
  if (parts.some((part) => part === "" || part === "." || part === ".." || part.endsWith(".") || part.endsWith(" "))) return false;
  const windowsReserved = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;
  if (parts.some((part) => windowsReserved.test(part))) return false;
  return true;
}

export function isValidRfc3339(value) {
  if (typeof value !== "string" || !RFC3339_RE.test(value)) return false;
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|([+-])(\d{2}):(\d{2}))$/);
  if (!match) return false;
  const [, yText, mText, dText, hhText, mmText, ssText, , , offHText, offMText] = match;
  const year = Number(yText);
  const month = Number(mText);
  const day = Number(dText);
  const hour = Number(hhText);
  const minute = Number(mmText);
  const second = Number(ssText);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1]) return false;
  if (hour > 23 || minute > 59 || second > 59) return false;
  if (offHText !== undefined && (Number(offHText) > 14 || Number(offMText) > 59 || (Number(offHText) === 14 && Number(offMText) !== 0))) return false;
  return Number.isFinite(Date.parse(value));
}

export async function sha256File(path) {
  return new Promise((accept, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => accept(hash.digest("hex")));
  });
}

async function pathExists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error && error.code === "ENOENT") return false;
    throw error;
  }
}

function lexicallyContained(root, candidate) {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

async function resolveExistingContained(rootReal, relativePath) {
  if (!isSafeRelativePath(relativePath)) throw new Error("path is not a safe relative path");
  const candidate = resolve(rootReal, relativePath);
  if (!lexicallyContained(rootReal, candidate)) throw new Error("path escapes the workspace root");
  const actual = await realpath(candidate);
  if (!lexicallyContained(rootReal, actual)) throw new Error("resolved path escapes the workspace root");
  return actual;
}

export function parseStrictJson(text) {
  if (typeof text !== "string") throw new TypeError("JSON input must be a string");
  let index = 0;

  function fail(message) {
    throw new SyntaxError(`${message} at character ${index}`);
  }

  function skipWhitespace() {
    while (index < text.length && /[\u0020\u0009\u000a\u000d]/.test(text[index])) index += 1;
  }

  function parseString() {
    const start = index;
    if (text[index] !== '"') fail("Expected JSON string");
    index += 1;
    while (index < text.length) {
      const code = text.charCodeAt(index);
      if (text[index] === '"') {
        index += 1;
        return JSON.parse(text.slice(start, index));
      }
      if (text[index] === "\\") {
        index += 1;
        if (index >= text.length) fail("Unterminated JSON escape");
        if (text[index] === "u") {
          if (!/^[a-fA-F0-9]{4}$/.test(text.slice(index + 1, index + 5))) fail("Invalid JSON Unicode escape");
          index += 5;
          continue;
        }
        if (!'"\\/bfnrt'.includes(text[index])) fail("Invalid JSON escape");
        index += 1;
        continue;
      }
      if (code < 0x20) fail("Unescaped control character in JSON string");
      index += 1;
    }
    fail("Unterminated JSON string");
  }

  function parseNumber() {
    const match = text.slice(index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (!match) fail("Invalid JSON number");
    index += match[0].length;
    return JSON.parse(match[0]);
  }

  function parseArray() {
    const value = [];
    index += 1;
    skipWhitespace();
    if (text[index] === "]") {
      index += 1;
      return value;
    }
    while (index < text.length) {
      value.push(parseValue());
      skipWhitespace();
      if (text[index] === "]") {
        index += 1;
        return value;
      }
      if (text[index] !== ",") fail("Expected comma or closing bracket");
      index += 1;
      skipWhitespace();
    }
    fail("Unterminated JSON array");
  }

  function parseObject() {
    const value = {};
    const keys = new Set();
    index += 1;
    skipWhitespace();
    if (text[index] === "}") {
      index += 1;
      return value;
    }
    while (index < text.length) {
      if (text[index] !== '"') fail("Expected JSON object key");
      const key = parseString();
      if (keys.has(key)) throw new SyntaxError(`Duplicate JSON object key ${JSON.stringify(key)}`);
      keys.add(key);
      skipWhitespace();
      if (text[index] !== ":") fail("Expected colon after JSON object key");
      index += 1;
      const member = parseValue();
      Object.defineProperty(value, key, { value: member, enumerable: true, configurable: true, writable: true });
      skipWhitespace();
      if (text[index] === "}") {
        index += 1;
        return value;
      }
      if (text[index] !== ",") fail("Expected comma or closing brace");
      index += 1;
      skipWhitespace();
    }
    fail("Unterminated JSON object");
  }

  function parseValue() {
    skipWhitespace();
    const token = text[index];
    if (token === "{") return parseObject();
    if (token === "[") return parseArray();
    if (token === '"') return parseString();
    if (token === "-" || /[0-9]/.test(token || "")) return parseNumber();
    for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(literal, index)) {
        index += literal.length;
        return value;
      }
    }
    fail("Expected JSON value");
  }

  const value = parseValue();
  skipWhitespace();
  if (index !== text.length) fail("Unexpected trailing JSON content");
  return value;
}

async function readBoundedJsonDocument(path, maxBytes) {
  const metadata = await stat(path);
  if (!metadata.isFile()) throw new Error("JSON path is not a regular file");
  if (metadata.size > maxBytes) throw new Error(`JSON file exceeds ${maxBytes} bytes`);
  const bytes = await readFile(path);
  if (bytes.length > maxBytes) throw new Error(`JSON file exceeds ${maxBytes} bytes`);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return {
    value: parseStrictJson(text),
    sha256: createHash("sha256").update(bytes).digest("hex")
  };
}

async function readBoundedJson(path, maxBytes) {
  return (await readBoundedJsonDocument(path, maxBytes)).value;
}

function decisionFrom(policy, now, checks, selectedReceipt = null) {
  const denied = checks.filter((check) => check.status === "DENY").length;
  return {
    schema: DECISION_SCHEMA,
    decision: denied === 0 ? "ADMIT" : "DENY",
    policy: {
      id: policy?.policy_id ?? null,
      version: policy?.policy_version ?? null,
      stage: policy?.admission_stage ?? null
    },
    subject: {
      path: policy?.subject?.path ?? null,
      sha256: policy?.subject?.sha256 ?? null
    },
    receipt: selectedReceipt ? {
      file: selectedReceipt.file,
      sha256: selectedReceipt.sha256,
      id: selectedReceipt.receipt.receipt_id,
      state: selectedReceipt.receipt.state,
      verified_at: selectedReceipt.receipt.verified_at,
      verifier: {
        name: selectedReceipt.receipt.verifier.name,
        version: selectedReceipt.receipt.verifier.version,
        source_sha256: selectedReceipt.receipt.verifier.source_sha256 ?? null
      }
    } : null,
    checked_at: now.toISOString(),
    summary: { passed: checks.length - denied, denied },
    checks,
    boundary: BOUNDARY
  };
}

export async function evaluateAdmission({ root, policy, now = new Date() }) {
  const checks = [];
  const policyErrors = validatePolicy(policy);
  checks.push(makeCheck("policy.valid", policyErrors.length === 0, policyErrors.length ? "Policy is invalid." : "Policy shape and values are valid.", policyErrors.length ? policyErrors : undefined));
  if (policyErrors.length) return decisionFrom(policy, now, checks);

  let rootReal;
  try {
    rootReal = await realpath(resolve(root));
    const rootMetadata = await stat(rootReal);
    if (!rootMetadata.isDirectory()) throw new Error("workspace root is not a directory");
    checks.push(makeCheck("workspace.available", true, "Workspace root exists and resolves to a directory."));
  } catch (error) {
    checks.push(makeCheck("workspace.available", false, "Workspace root cannot be resolved.", safeErrorDetail(error)));
    return decisionFrom(policy, now, checks);
  }

  let subjectPath;
  try {
    subjectPath = await resolveExistingContained(rootReal, policy.subject.path);
    checks.push(makeCheck("subject.contained", true, "Subject exists inside the resolved workspace root."));
    const actual = await sha256File(subjectPath);
    checks.push(makeCheck("subject.hash", actual === policy.subject.sha256, actual === policy.subject.sha256 ? "Subject SHA-256 matches policy." : "Subject SHA-256 does not match policy.", { expected: policy.subject.sha256, actual }));
  } catch (error) {
    checks.push(makeCheck("subject.contained", false, "Subject is missing, unreadable, or outside the workspace root.", safeErrorDetail(error)));
  }

  const markerHits = [];
  for (const marker of policy.deny_if_paths_exist) {
    const markerPath = resolve(rootReal, marker);
    if (!lexicallyContained(rootReal, markerPath)) markerHits.push(`${marker} (outside root)`);
    else if (await pathExists(markerPath)) markerHits.push(marker);
  }
  checks.push(makeCheck("terminal_markers.absent", markerHits.length === 0, markerHits.length ? "One or more deny markers exist." : "No configured deny marker exists.", markerHits.length ? markerHits : undefined));

  const actualEvidence = new Map();
  for (const item of policy.required_evidence) {
    try {
      const evidencePath = await resolveExistingContained(rootReal, item.path);
      const actual = await sha256File(evidencePath);
      actualEvidence.set(item.path, actual);
      checks.push(makeCheck(`evidence.file:${item.path}`, actual === item.sha256, actual === item.sha256 ? "Evidence file SHA-256 matches policy." : "Evidence file SHA-256 does not match policy.", { expected: item.sha256, actual }));
    } catch (error) {
      checks.push(makeCheck(`evidence.file:${item.path}`, false, "Evidence file is missing, unreadable, or outside the workspace root.", safeErrorDetail(error)));
    }
  }

  let receiptDirectory;
  try {
    receiptDirectory = await resolveExistingContained(rootReal, policy.receipt_directory);
    checks.push(makeCheck("receipts.directory", true, "Receipt directory exists inside the workspace root."));
  } catch (error) {
    checks.push(makeCheck("receipts.directory", false, "Receipt directory is missing, unreadable, or outside the workspace root.", safeErrorDetail(error)));
    return decisionFrom(policy, now, checks);
  }

  let entries;
  try {
    entries = (await readdir(receiptDirectory, { withFileTypes: true }))
      .filter((entry) => entry.name.toLowerCase().endsWith(".json"))
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
  } catch (error) {
    checks.push(makeCheck("receipts.readable", false, "Receipt directory cannot be read.", safeErrorDetail(error)));
    return decisionFrom(policy, now, checks);
  }
  checks.push(makeCheck("receipts.bounded", entries.length <= MAX_RECEIPTS, entries.length <= MAX_RECEIPTS ? `Receipt set is bounded (${entries.length}).` : `Receipt set exceeds the ${MAX_RECEIPTS}-file limit.`, { count: entries.length }));
  if (entries.length > MAX_RECEIPTS) return decisionFrom(policy, now, checks);

  const validReceipts = [];
  const invalidReceipts = [];
  for (const entry of entries) {
    const name = entry.name;
    try {
      const relativeReceiptPath = `${policy.receipt_directory}/${name}`;
      const receiptPath = await resolveExistingContained(rootReal, relativeReceiptPath);
      const document = await readBoundedJsonDocument(receiptPath, MAX_RECEIPT_BYTES);
      const receipt = document.value;
      const errors = validateReceipt(receipt);
      if (errors.length) invalidReceipts.push({ file: name, errors });
      else validReceipts.push({ file: name, sha256: document.sha256, receipt });
    } catch (error) {
      invalidReceipts.push({ file: name, errors: [safeErrorDetail(error)] });
    }
  }
  checks.push(makeCheck("receipts.valid", invalidReceipts.length === 0, invalidReceipts.length ? "Receipt directory contains invalid JSON receipts." : "Every JSON receipt has a valid shape.", invalidReceipts.length ? invalidReceipts : undefined));

  const matches = validReceipts.filter(({ receipt }) =>
    receipt.policy_id === policy.policy_id &&
    receipt.policy_version === policy.policy_version &&
    receipt.admission_stage === policy.admission_stage &&
    receipt.receipt_kind === policy.receipt_kind &&
    receipt.subject.path === policy.subject.path &&
    receipt.subject.sha256 === policy.subject.sha256
  );
  checks.push(makeCheck("receipts.unambiguous", matches.length === 1, matches.length === 1 ? "Exactly one receipt matches the subject and lifecycle policy." : `Expected exactly one matching receipt; found ${matches.length}.`, { matching_files: matches.map((match) => match.file) }));
  if (matches.length !== 1) return decisionFrom(policy, now, checks);

  const selectedReceipt = matches[0];
  const { receipt } = selectedReceipt;
  const stateAllowed = policy.allowed_states.includes(receipt.state);
  checks.push(makeCheck("receipt.state", stateAllowed, stateAllowed ? `Receipt state ${receipt.state} is allowed.` : `Receipt state ${receipt.state} is not allowed.`, { allowed_states: policy.allowed_states }));

  const verifiedAt = new Date(receipt.verified_at);
  const ageHours = (now.getTime() - verifiedAt.getTime()) / 3_600_000;
  const fresh = ageHours >= 0 && ageHours <= policy.max_receipt_age_hours;
  checks.push(makeCheck("receipt.freshness", fresh, fresh ? "Receipt timestamp is current under policy." : ageHours < 0 ? "Receipt timestamp is in the future." : "Receipt is stale under policy.", { age_hours: Number(ageHours.toFixed(6)), max_age_hours: policy.max_receipt_age_hours }));

  const verifierBound = policy.allowed_verifiers.some((verifier) =>
    receipt.verifier.name === verifier.name &&
    receipt.verifier.version === verifier.version &&
    receipt.verifier.source_sha256 === verifier.source_sha256
  );
  checks.push(makeCheck("receipt.verifier_identity", verifierBound, verifierBound ? "Verifier name, version, and source digest match an allowed identity." : "Verifier identity is not allowed by policy.", {
    receipt: {
      name: receipt.verifier.name,
      version: receipt.verifier.version,
      source_sha256: receipt.verifier.source_sha256 ?? null
    }
  }));

  const receiptEvidence = new Map(receipt.evidence.map((item) => [item.path, item.sha256]));
  for (const item of policy.required_evidence) {
    const recorded = receiptEvidence.get(item.path);
    const actual = actualEvidence.get(item.path);
    const bound = recorded === item.sha256 && actual === item.sha256;
    checks.push(makeCheck(`evidence.receipt:${item.path}`, bound, bound ? "Receipt binds the required evidence digest." : "Receipt does not bind the required evidence digest.", { expected: item.sha256, recorded: recorded ?? null, actual: actual ?? null }));
  }

  return decisionFrom(policy, now, checks, selectedReceipt);
}

export async function loadPolicy(path) {
  return readBoundedJson(path, MAX_POLICY_BYTES);
}
