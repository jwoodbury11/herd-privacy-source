import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

export function canonicalStringify(value) {
  return serialize(value, new Set());
}

function serialize(value, seen) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON cannot contain a non-finite number.");
    if (Object.is(value, -0)) return "0";
    return JSON.stringify(value);
  }
  if (typeof value !== "object" || value === undefined) {
    throw new TypeError("Canonical JSON contains an unsupported value.");
  }
  if (seen.has(value)) throw new TypeError("Canonical JSON cannot contain a cycle.");
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((item) => serialize(item, seen)).join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("Canonical JSON accepts only plain objects.");
    }
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${serialize(value[key], seen)}`)
      .join(",")}}`;
  } finally {
    seen.delete(value);
  }
}

export function canonicalJson(value) {
  return `${canonicalStringify(value)}\n`;
}

export function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function sha256Base64Url(value) {
  return createHash("sha256").update(value).digest("base64url");
}

export async function hashFile(filePath) {
  let handle;
  try {
    handle = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    throw new TypeError(
      `${filePath} must be an accessible regular, non-symbolic-link file: ${error instanceof Error ? error.message : error}`,
    );
  }
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new TypeError(`${filePath} must be a safely sized regular file.`);
    }
    const hash = createHash("sha256");
    let size = 0;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      size += chunk.byteLength;
      hash.update(chunk);
    }
    const after = await handle.stat({ bigint: true });
    if (
      BigInt(size) !== before.size ||
      after.size !== before.size ||
      after.mtimeNs !== before.mtimeNs ||
      after.ctimeNs !== before.ctimeNs
    ) {
      throw new TypeError(`${filePath} changed while it was being hashed.`);
    }
    return { sha256: hash.digest("hex"), size };
  } finally {
    await handle.close();
  }
}

export async function readJson(filePath) {
  const text = await readFile(filePath, "utf8");
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new TypeError(`${filePath} is not valid JSON: ${error instanceof Error ? error.message : error}`);
  }
  return parsed;
}

export async function writeCanonicalJson(filePath, value) {
  await mkdir(path.dirname(path.resolve(filePath)), { recursive: true });
  const temporaryPath = `${filePath}.tmp-${process.pid}`;
  await writeFile(temporaryPath, canonicalJson(value), { mode: 0o600 });
  await rename(temporaryPath, filePath);
}

export function exactKeys(value, expected, label) {
  if (!isPlainObject(value)) throw new TypeError(`${label} must be an object.`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new TypeError(`${label} contains unsupported or missing fields.`);
  }
  return value;
}

export function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function requireString(value, label, { minimum = 1, maximum = 4096, pattern } = {}) {
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    (pattern && !pattern.test(value))
  ) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

export function requireInteger(value, label, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${label} must be an integer from ${minimum} through ${maximum}.`);
  }
  return value;
}

export function requireSha256(value, label) {
  return requireString(value, label, { minimum: 64, maximum: 64, pattern: /^[0-9a-f]{64}$/u });
}

export function requireCanonicalTimestamp(value, label) {
  requireString(value, label, { maximum: 40 });
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new TypeError(`${label} must be a canonical UTC timestamp.`);
  }
  return value;
}

export function timestampFromEpoch(epochSeconds) {
  requireInteger(epochSeconds, "source date epoch", { maximum: 253402300799 });
  return new Date(epochSeconds * 1000).toISOString();
}

export function parseArgs(argv, { boolean = [] } = {}) {
  const booleans = new Set(boolean);
  const result = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!argument.startsWith("--")) {
      result._.push(argument);
      continue;
    }
    const name = argument.slice(2);
    if (!name || name.includes("=")) throw new TypeError(`Unsupported argument ${argument}.`);
    if (booleans.has(name)) {
      result[name] = true;
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new TypeError(`Argument --${name} requires a value.`);
    }
    if (Object.hasOwn(result, name)) throw new TypeError(`Argument --${name} was repeated.`);
    result[name] = value;
    index += 1;
  }
  return result;
}

export function requireArg(args, name) {
  return requireString(args[name], `--${name}`);
}

export async function assertRegularFile(filePath, label = filePath) {
  const metadata = await lstat(filePath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new TypeError(`${label} must be a regular, non-symbolic-link file.`);
  }
  return metadata;
}
