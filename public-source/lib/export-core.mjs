import { execFile } from "node:child_process";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import {
  canonicalJson,
  exactKeys,
  requireInteger,
  requireString,
  sha256Hex,
  timestampFromEpoch,
} from "../../release/lib/canonical.mjs";

const run = promisify(execFile);
const PRIVATE_KEY_BLOCK = /(?:^|\n)-----BEGIN (?:EC |RSA |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{16,}\r?\n/u;
const SECRET_ENVIRONMENT_NAME = /(?:^|_)(?:AUTH|BYPASS|CREDENTIAL|PASSWORD|PEPPER|PRIVATE_KEY|SECRET|TOKEN)(?:_|$)|API_KEY/u;
const SAFE_EXAMPLE_SECRET_VALUE = /(?:replace|x{4,}|^false$)/iu;

function posixRelative(value, label) {
  requireString(value, label, { maximum: 500 });
  const normalized = value.replaceAll("\\", "/");
  if (
    normalized.startsWith("/") ||
    normalized.endsWith("/") ||
    normalized.split("/").some((segment) => !segment || segment === "." || segment === "..")
  ) {
    throw new TypeError(`${label} must be a normalized relative path.`);
  }
  return normalized;
}

export function normalizeExportPolicy(value) {
  exactKeys(
    value,
    [
      "schemaVersion",
      "archivePrefix",
      "license",
      "maximumFileBytes",
      "prohibitedPathFragments",
      "prohibitedExtensions",
      "includes",
    ],
    "export policy",
  );
  if (value.schemaVersion !== 1 || value.license !== "Apache-2.0") {
    throw new TypeError("Export policy schema or license is unsupported.");
  }
  const stringArray = (items, label) => {
    if (!Array.isArray(items) || items.length === 0) throw new TypeError(`${label} must not be empty.`);
    const result = items.map((item, index) => requireString(item, `${label}[${index}]`, { maximum: 120 }));
    if (new Set(result.map((item) => item.toLowerCase())).size !== result.length) {
      throw new TypeError(`${label} contains duplicates.`);
    }
    return result;
  };
  if (!Array.isArray(value.includes) || value.includes.length === 0) {
    throw new TypeError("Export policy includes must not be empty.");
  }
  const includes = value.includes.map((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new TypeError(`includes[${index}] must be an object.`);
    }
    const allowed = [
      "path",
      "recursive",
      "extensions",
      "optional",
      "binarySha256",
      "exampleSha256",
    ];
    const unexpected = Object.keys(entry).filter((key) => !allowed.includes(key));
    if (unexpected.length > 0) throw new TypeError(`includes[${index}] contains unsupported fields.`);
    const extensions = entry.extensions === undefined
      ? null
      : stringArray(entry.extensions, `includes[${index}].extensions`).map((extension) => {
          if (!extension.startsWith(".") || extension !== extension.toLowerCase()) {
            throw new TypeError(`includes[${index}].extensions must be lowercase file extensions.`);
          }
          return extension;
        });
    const includePath = posixRelative(entry.path, `includes[${index}].path`);
    const binarySha256 = entry.binarySha256 === undefined
      ? null
      : requireString(entry.binarySha256, `includes[${index}].binarySha256`, {
          minimum: 64,
          maximum: 64,
          pattern: /^[0-9a-f]{64}$/u,
        });
    const exampleSha256 = entry.exampleSha256 === undefined
      ? null
      : requireString(entry.exampleSha256, `includes[${index}].exampleSha256`, {
          minimum: 64,
          maximum: 64,
          pattern: /^[0-9a-f]{64}$/u,
        });
    if (
      binarySha256 &&
      (entry.recursive === true || extensions !== null || path.posix.extname(includePath).toLowerCase() !== ".png")
    ) {
      throw new TypeError(
        `includes[${index}].binarySha256 is allowed only for an exact PNG file include.`,
      );
    }
    if (
      exampleSha256 &&
      (
        binarySha256 ||
        entry.recursive === true ||
        extensions !== null ||
        path.posix.basename(includePath).toLowerCase() !== ".env.example"
      )
    ) {
      throw new TypeError(
        `includes[${index}].exampleSha256 is allowed only for an exact .env.example file include.`,
      );
    }
    return {
      path: includePath,
      recursive: entry.recursive === true,
      extensions,
      optional: entry.optional === true,
      binarySha256,
      exampleSha256,
    };
  });
  return {
    schemaVersion: 1,
    archivePrefix: posixRelative(value.archivePrefix, "archivePrefix"),
    license: "Apache-2.0",
    maximumFileBytes: requireInteger(value.maximumFileBytes, "maximumFileBytes", {
      minimum: 1,
      maximum: 64 * 1024 * 1024,
    }),
    prohibitedPathFragments: stringArray(
      value.prohibitedPathFragments,
      "prohibitedPathFragments",
    ).map((fragment) => fragment.toLowerCase()),
    prohibitedExtensions: stringArray(
      value.prohibitedExtensions,
      "prohibitedExtensions",
    ).map((extension) => extension.toLowerCase()),
    includes,
  };
}

function isProhibitedPath(relativePath, policy) {
  const lowered = relativePath.toLowerCase();
  const segments = lowered.split("/");
  return policy.prohibitedPathFragments.some((fragment) => {
    if (fragment.includes("/")) return lowered.includes(fragment);
    return segments.some(
      (segment) => segment === fragment || segment.startsWith(`${fragment}-`),
    );
  });
}

export function assertSafePath(relativePath, policy) {
  const lowered = relativePath.toLowerCase();
  const exactPinnedPng = policy.includes.some(
    (entry) => entry.binarySha256 && entry.path.toLowerCase() === lowered,
  );
  const exactPinnedExample = policy.includes.some(
    (entry) => entry.exampleSha256 && entry.path.toLowerCase() === lowered,
  );
  if (isProhibitedPath(relativePath, policy)) {
    throw new TypeError(`Prohibited path entered export: ${relativePath}`);
  }
  const extension = path.posix.extname(lowered);
  if (policy.prohibitedExtensions.includes(extension) && !exactPinnedPng) {
    throw new TypeError(`Prohibited file type entered export: ${relativePath}`);
  }
  if (
    !exactPinnedExample &&
    (path.posix.basename(lowered) === ".env" || path.posix.basename(lowered).startsWith(".env."))
  ) {
    throw new TypeError(`Environment file entered export: ${relativePath}`);
  }
}

function assertPng(bytes, relativePath) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (bytes.byteLength < 33 || !bytes.subarray(0, signature.byteLength).equals(signature)) {
    throw new TypeError(`Pinned binary asset is not a PNG: ${relativePath}`);
  }
  let offset = signature.byteLength;
  let chunkIndex = 0;
  let sawEnd = false;
  while (offset < bytes.byteLength) {
    if (offset + 12 > bytes.byteLength) throw new TypeError(`PNG is truncated: ${relativePath}`);
    const length = bytes.readUInt32BE(offset);
    const type = bytes.subarray(offset + 4, offset + 8).toString("ascii");
    const end = offset + 12 + length;
    if (!/^[A-Za-z]{4}$/u.test(type) || end > bytes.byteLength) {
      throw new TypeError(`PNG has an invalid chunk: ${relativePath}`);
    }
    if (chunkIndex === 0 && (type !== "IHDR" || length !== 13)) {
      throw new TypeError(`PNG lacks a canonical IHDR: ${relativePath}`);
    }
    if (type === "IEND") {
      if (length !== 0 || end !== bytes.byteLength) {
        throw new TypeError(`PNG has an invalid IEND: ${relativePath}`);
      }
      sawEnd = true;
    }
    offset = end;
    chunkIndex += 1;
  }
  if (!sawEnd) throw new TypeError(`PNG lacks an IEND chunk: ${relativePath}`);
}

function assertPlaceholderEnvironmentExample(bytes, relativePath) {
  const text = bytes.toString("utf8");
  const lines = text.split(/\r?\n/u);
  for (let index = 0; index < lines.length; index += 1) {
    let line = lines[index].trim();
    if (!line) continue;
    if (line.startsWith("#")) {
      line = line.slice(1).trim();
      if (!/^(?:export\s+)?[A-Z][A-Z0-9_]*=/u.test(line)) continue;
    }
    const assignment = /^(?:export\s+)?([A-Z][A-Z0-9_]*)=(.*)$/u.exec(line);
    if (!assignment) {
      throw new TypeError(
        `Pinned configuration example has an invalid assignment at ${relativePath}:${index + 1}`,
      );
    }
    const [, name, value] = assignment;
    if (SECRET_ENVIRONMENT_NAME.test(name) && !SAFE_EXAMPLE_SECRET_VALUE.test(value)) {
      throw new TypeError(
        `Pinned configuration example contains a non-placeholder secret at ${relativePath}:${index + 1}`,
      );
    }
  }
}

async function walk(root, relativePath, entry, policy, output) {
  const absolutePath = path.resolve(root, relativePath);
  if (absolutePath !== path.join(root, ...relativePath.split("/"))) {
    throw new TypeError(`Include escapes repository root: ${relativePath}`);
  }
  let metadata;
  try {
    metadata = await lstat(absolutePath);
  } catch (error) {
    if (entry.optional && error?.code === "ENOENT") return;
    throw error;
  }
  if (metadata.isSymbolicLink()) throw new TypeError(`Symbolic links are not exportable: ${relativePath}`);
  if (metadata.isDirectory()) {
    if (!entry.recursive) throw new TypeError(`Directory include must be recursive: ${relativePath}`);
    const children = await readdir(absolutePath);
    children.sort();
    for (const child of children) {
      const childPath = `${relativePath}/${child}`;
      if (isProhibitedPath(childPath, policy)) continue;
      await walk(root, childPath, entry, policy, output);
    }
    return;
  }
  if (!metadata.isFile()) throw new TypeError(`Only regular files are exportable: ${relativePath}`);
  if (entry.extensions && !entry.extensions.includes(path.posix.extname(relativePath).toLowerCase())) return;
  assertSafePath(relativePath, policy);
  if (metadata.size > policy.maximumFileBytes) throw new TypeError(`Export file exceeds size limit: ${relativePath}`);
  const bytes = await readFile(absolutePath);
  if (entry.binarySha256) {
    assertPng(bytes, relativePath);
    if (sha256Hex(bytes) !== entry.binarySha256) {
      throw new TypeError(`Pinned binary asset digest changed: ${relativePath}`);
    }
  } else {
    if (bytes.includes(0)) {
      throw new TypeError(`Binary/NUL-containing file entered export: ${relativePath}`);
    }
    if (entry.exampleSha256) {
      if (sha256Hex(bytes) !== entry.exampleSha256) {
        throw new TypeError(`Pinned configuration example digest changed: ${relativePath}`);
      }
      assertPlaceholderEnvironmentExample(bytes, relativePath);
    }
  }
  if (PRIVATE_KEY_BLOCK.test(bytes.toString("utf8"))) {
    throw new TypeError(`Private key material entered export: ${relativePath}`);
  }
  output.set(relativePath, {
    path: relativePath,
    bytes,
    mode: bytes.subarray(0, 2).toString("utf8") === "#!" ? 0o755 : 0o644,
  });
}

export async function collectExportFiles(rootPath, policy) {
  const root = path.resolve(rootPath);
  const files = new Map();
  for (const entry of policy.includes) await walk(root, entry.path, entry, policy, files);
  const paths = [...files.keys()].sort();
  const folded = new Set();
  for (const filePath of paths) {
    const key = filePath.toLowerCase();
    if (folded.has(key)) throw new TypeError(`Case-insensitive export path collision: ${filePath}`);
    folded.add(key);
  }
  return paths.map((filePath) => files.get(filePath));
}

function octal(value, bytes) {
  const text = value.toString(8);
  if (text.length > bytes - 1) throw new TypeError("USTAR numeric value is too large.");
  return `${text.padStart(bytes - 1, "0")}\0`;
}

function tarName(archivePath) {
  const bytes = Buffer.byteLength(archivePath);
  if (bytes <= 100) return { name: archivePath, prefix: "" };
  const segments = archivePath.split("/");
  for (let index = segments.length - 1; index > 0; index -= 1) {
    const prefix = segments.slice(0, index).join("/");
    const name = segments.slice(index).join("/");
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100) return { name, prefix };
  }
  throw new TypeError(`USTAR path is too long: ${archivePath}`);
}

function writeField(header, offset, length, value) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.byteLength > length) throw new TypeError(`USTAR header field is too long: ${value}`);
  bytes.copy(header, offset);
}

export function tarEntry(archivePath, bytes, mode, epochSeconds) {
  const header = Buffer.alloc(512);
  const { name, prefix } = tarName(archivePath);
  writeField(header, 0, 100, name);
  writeField(header, 100, 8, octal(mode, 8));
  writeField(header, 108, 8, octal(0, 8));
  writeField(header, 116, 8, octal(0, 8));
  writeField(header, 124, 12, octal(bytes.byteLength, 12));
  writeField(header, 136, 12, octal(epochSeconds, 12));
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  writeField(header, 257, 6, "ustar\0");
  writeField(header, 263, 2, "00");
  writeField(header, 345, 155, prefix);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeField(header, 148, 8, `${checksum.toString(8).padStart(6, "0")}\0 `);
  const padding = Buffer.alloc((512 - (bytes.byteLength % 512)) % 512);
  return Buffer.concat([header, bytes, padding]);
}

export function createExportManifest({ files, policyBytes, policyPath, sourceRevision, sourceDateEpoch, archivePrefix }) {
  const createdAt = timestampFromEpoch(sourceDateEpoch);
  return {
    schemaVersion: 1,
    archiveFormat: "ustar",
    archivePrefix,
    createdAt,
    sourceDateEpoch,
    sourceRevision: requireString(sourceRevision, "sourceRevision", {
      minimum: 40,
      maximum: 64,
      pattern: /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u,
    }),
    license: "Apache-2.0",
    policy: {
      path: posixRelative(policyPath, "policy path"),
      sha256: sha256Hex(policyBytes),
    },
    files: files.map(({ path: filePath, bytes, mode }) => ({
      path: filePath,
      mode: mode.toString(8).padStart(4, "0"),
      size: bytes.byteLength,
      sha256: sha256Hex(bytes),
    })),
  };
}

export function normalizeExportManifest(value, policy) {
  exactKeys(
    value,
    [
      "schemaVersion",
      "archiveFormat",
      "archivePrefix",
      "createdAt",
      "sourceDateEpoch",
      "sourceRevision",
      "license",
      "policy",
      "files",
    ],
    "public-source manifest",
  );
  if (
    value.schemaVersion !== 1 ||
    value.archiveFormat !== "ustar" ||
    value.license !== "Apache-2.0"
  ) {
    throw new TypeError("Public-source manifest uses an unsupported schema, archive, or license.");
  }
  const sourceDateEpoch = requireInteger(value.sourceDateEpoch, "sourceDateEpoch", {
    maximum: 253402300799,
  });
  if (value.createdAt !== timestampFromEpoch(sourceDateEpoch)) {
    throw new TypeError("Public-source manifest timestamp does not match sourceDateEpoch.");
  }
  if (!Array.isArray(value.files) || value.files.length === 0) {
    throw new TypeError("Public-source manifest files must not be empty.");
  }
  const files = value.files.map((file, index) => {
    const label = `files[${index}]`;
    exactKeys(file, ["path", "mode", "size", "sha256"], label);
    const filePath = posixRelative(file.path, `${label}.path`);
    assertSafePath(filePath, policy);
    if (file.mode !== "0644" && file.mode !== "0755") {
      throw new TypeError(`${label}.mode is unsupported.`);
    }
    return {
      path: filePath,
      mode: file.mode,
      size: requireInteger(file.size, `${label}.size`, { maximum: policy.maximumFileBytes }),
      sha256: requireString(file.sha256, `${label}.sha256`, {
        minimum: 64,
        maximum: 64,
        pattern: /^[0-9a-f]{64}$/u,
      }),
    };
  });
  const paths = files.map(({ path: filePath }) => filePath);
  if (
    paths.some((filePath, index) => index > 0 && paths[index - 1] >= filePath) ||
    new Set(paths.map((filePath) => filePath.toLowerCase())).size !== paths.length
  ) {
    throw new TypeError("Public-source manifest paths must be strictly sorted and collision-free.");
  }
  exactKeys(value.policy, ["path", "sha256"], "policy");
  return {
    schemaVersion: 1,
    archiveFormat: "ustar",
    archivePrefix: posixRelative(value.archivePrefix, "archivePrefix"),
    createdAt: value.createdAt,
    sourceDateEpoch,
    sourceRevision: requireString(value.sourceRevision, "sourceRevision", {
      minimum: 40,
      maximum: 64,
      pattern: /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u,
    }),
    license: "Apache-2.0",
    policy: {
      path: posixRelative(value.policy.path, "policy.path"),
      sha256: requireString(value.policy.sha256, "policy.sha256", {
        minimum: 64,
        maximum: 64,
        pattern: /^[0-9a-f]{64}$/u,
      }),
    },
    files,
  };
}

export function createTarArchive(files, manifest, sourceDateEpoch) {
  const prefix = manifest.archivePrefix;
  const entries = files.map(({ path: filePath, bytes, mode }) =>
    tarEntry(`${prefix}/${filePath}`, bytes, mode, sourceDateEpoch),
  );
  entries.push(
    tarEntry(
      `${prefix}/PUBLIC-SOURCE-MANIFEST.json`,
      Buffer.from(canonicalJson(manifest)),
      0o644,
      sourceDateEpoch,
    ),
  );
  entries.push(Buffer.alloc(1024));
  return Buffer.concat(entries);
}

export async function assertCleanRepository(rootPath) {
  const { stdout } = await run("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: rootPath,
    maxBuffer: 4 * 1024 * 1024,
  });
  if (stdout.trim()) throw new TypeError("Public-source export requires a clean working tree.");
}
