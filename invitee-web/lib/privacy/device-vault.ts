"use client";

import {
  base64UrlToBytes,
  bytesToBase64Url,
  concatenateBytes,
  uuidToBytes,
} from "./protocol";

const DATABASE_NAME = "herd-private-vault-v1";
const DATABASE_VERSION = 1;
const VAULT_STORE = "account-root-secrets";
const DEVICE_WRAP_LABEL = "HERD-ARS-DEVICE-WRAP-AAD-V1";
const ARS_COMMITMENT_LABEL = "HERD-ARS-COMMITMENT-V1";
const AES_GCM_NONCE_BYTES = 12;
const AES_GCM_TAG_BITS = 128;
const ACCOUNT_ROOT_SECRET_BYTES = 32;
const ARS_WRAP_FRAME_BYTES = 60;
const textEncoder = new TextEncoder();

type StoredVaultRecord = {
  id: string;
  userId: string;
  accountKeyEpochId: string;
  deviceKeyId: string;
  deviceKey: CryptoKey;
  wrappedAccountRootSecret: string;
  createdAt: string;
};

export type LocalAccountRootSecret = {
  accountKeyEpochId: string;
  deviceKeyId: string;
  bytes: Uint8Array;
};

export class PrivateVaultError extends Error {
  readonly canStartOver: boolean;

  constructor(message: string, options: { canStartOver?: boolean } = {}) {
    super(message);
    this.name = "PrivateVaultError";
    this.canStartOver = options.canStartOver ?? false;
  }
}

function cryptoApi(): Crypto {
  if (!globalThis.crypto?.subtle) {
    throw new PrivateVaultError(
      "Private responses require a browser with Web Crypto support.",
    );
  }
  return globalThis.crypto;
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  return value.buffer.slice(
    value.byteOffset,
    value.byteOffset + value.byteLength,
  ) as ArrayBuffer;
}

function randomBytes(length: number): Uint8Array {
  return cryptoApi().getRandomValues(new Uint8Array(length));
}

function randomUuid(): string {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function normalizeEpochId(value: string): string {
  try {
    uuidToBytes(value);
  } catch {
    throw new PrivateVaultError("The account key epoch is invalid.");
  }
  return value.toLowerCase();
}

function vaultRecordId(userId: string, accountKeyEpochId: string): string {
  if (!userId) throw new PrivateVaultError("The signed-in account is unavailable.");
  return `${userId}\u0000${normalizeEpochId(accountKeyEpochId)}`;
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed."));
  });
}

function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction failed."));
    transaction.onabort = () =>
      reject(transaction.error ?? new Error("IndexedDB transaction was aborted."));
  });
}

async function openVaultDatabase(): Promise<IDBDatabase> {
  if (typeof indexedDB === "undefined") {
    throw new PrivateVaultError(
      "Private responses require persistent browser storage.",
    );
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(VAULT_STORE)) {
        database.createObjectStore(VAULT_STORE, { keyPath: "id" });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(
        new PrivateVaultError(
          "Herd could not open this browser’s private key storage.",
        ),
      );
    request.onblocked = () =>
      reject(
        new PrivateVaultError(
          "Close other Herd tabs, then try opening private key storage again.",
        ),
      );
  });
}

async function readRecord(id: string): Promise<StoredVaultRecord | null> {
  const database = await openVaultDatabase();
  try {
    const transaction = database.transaction(VAULT_STORE, "readonly");
    const result = await requestResult(
      transaction.objectStore(VAULT_STORE).get(id),
    );
    return (result as StoredVaultRecord | undefined) ?? null;
  } finally {
    database.close();
  }
}

async function addRecord(record: StoredVaultRecord): Promise<void> {
  const database = await openVaultDatabase();
  try {
    const transaction = database.transaction(VAULT_STORE, "readwrite");
    transaction.objectStore(VAULT_STORE).add(record);
    await transactionComplete(transaction);
  } finally {
    database.close();
  }
}

async function deleteRecord(id: string): Promise<void> {
  const database = await openVaultDatabase();
  try {
    const transaction = database.transaction(VAULT_STORE, "readwrite");
    transaction.objectStore(VAULT_STORE).delete(id);
    await transactionComplete(transaction);
  } finally {
    database.close();
  }
}

async function deviceWrapAad(
  userId: string,
  deviceKeyId: string,
  accountKeyEpochId: string,
): Promise<Uint8Array> {
  const accountHash = new Uint8Array(
    await cryptoApi().subtle.digest(
      "SHA-256",
      toArrayBuffer(textEncoder.encode(userId)),
    ),
  );
  return concatenateBytes(
    textEncoder.encode(DEVICE_WRAP_LABEL),
    new Uint8Array([0]),
    accountHash,
    uuidToBytes(deviceKeyId),
    uuidToBytes(accountKeyEpochId),
  );
}

function decodeWrap(value: string): Uint8Array {
  let frame: Uint8Array;
  try {
    frame = base64UrlToBytes(value);
  } catch {
    throw new PrivateVaultError("The local account-key vault is malformed.", {
      canStartOver: true,
    });
  }
  if (
    frame.length !== ARS_WRAP_FRAME_BYTES ||
    bytesToBase64Url(frame) !== value
  ) {
    throw new PrivateVaultError("The local account-key vault is malformed.", {
      canStartOver: true,
    });
  }
  return frame;
}

function validateStoredDeviceKey(key: CryptoKey): void {
  if (
    !key ||
    key.type !== "secret" ||
    key.extractable ||
    key.algorithm.name !== "AES-GCM" ||
    !key.usages.includes("decrypt")
  ) {
    throw new PrivateVaultError("The local device key is invalid.", {
      canStartOver: true,
    });
  }
}

async function unwrapRecord(record: StoredVaultRecord): Promise<LocalAccountRootSecret> {
  validateStoredDeviceKey(record.deviceKey);
  const accountKeyEpochId = normalizeEpochId(record.accountKeyEpochId);
  const frame = decodeWrap(record.wrappedAccountRootSecret);
  const iv = frame.subarray(0, AES_GCM_NONCE_BYTES);
  const ciphertextAndTag = frame.subarray(AES_GCM_NONCE_BYTES);
  let accountRootSecret: Uint8Array;
  try {
    accountRootSecret = new Uint8Array(
      await cryptoApi().subtle.decrypt(
        {
          name: "AES-GCM",
          iv: toArrayBuffer(iv),
          additionalData: toArrayBuffer(
            await deviceWrapAad(
              record.userId,
              record.deviceKeyId,
              accountKeyEpochId,
            ),
          ),
          tagLength: AES_GCM_TAG_BITS,
        },
        record.deviceKey,
        toArrayBuffer(ciphertextAndTag),
      ),
    );
  } catch {
    throw new PrivateVaultError(
      "This browser can no longer open the account key stored on this device.",
      { canStartOver: true },
    );
  }
  if (accountRootSecret.length !== ACCOUNT_ROOT_SECRET_BYTES) {
    accountRootSecret.fill(0);
    throw new PrivateVaultError("The local account root secret has the wrong size.", {
      canStartOver: true,
    });
  }
  return {
    accountKeyEpochId,
    deviceKeyId: record.deviceKeyId,
    bytes: accountRootSecret,
  };
}

export async function accountRootSecretCommitment(
  accountRootSecret: Uint8Array,
): Promise<string> {
  if (accountRootSecret.length !== ACCOUNT_ROOT_SECRET_BYTES) {
    throw new PrivateVaultError("The account root secret has the wrong size.");
  }
  const digest = await cryptoApi().subtle.digest(
    "SHA-256",
    toArrayBuffer(
      concatenateBytes(
        textEncoder.encode(ARS_COMMITMENT_LABEL),
        new Uint8Array([0]),
        accountRootSecret,
      ),
    ),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

async function verifyCommitment(
  accountRootSecret: LocalAccountRootSecret,
  expectedCommitment: string | undefined,
): Promise<LocalAccountRootSecret> {
  if (expectedCommitment === undefined) return accountRootSecret;
  let decoded: Uint8Array;
  try {
    decoded = base64UrlToBytes(expectedCommitment);
  } catch {
    accountRootSecret.bytes.fill(0);
    throw new PrivateVaultError("The account-key commitment is malformed.");
  }
  if (
    decoded.length !== 32 ||
    bytesToBase64Url(decoded) !== expectedCommitment ||
    await accountRootSecretCommitment(accountRootSecret.bytes) !== expectedCommitment
  ) {
    accountRootSecret.bytes.fill(0);
    throw new PrivateVaultError(
      "This device’s account key does not match the active account-key epoch.",
      { canStartOver: true },
    );
  }
  return accountRootSecret;
}

async function createRecord(
  userId: string,
  accountKeyEpochId: string,
): Promise<StoredVaultRecord> {
  const epochId = normalizeEpochId(accountKeyEpochId);
  const deviceKeyId = randomUuid();
  const accountRootSecret = randomBytes(ACCOUNT_ROOT_SECRET_BYTES);
  try {
    const deviceKey = (await cryptoApi().subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    )) as CryptoKey;
    const iv = randomBytes(AES_GCM_NONCE_BYTES);
    const ciphertextAndTag = new Uint8Array(
      await cryptoApi().subtle.encrypt(
        {
          name: "AES-GCM",
          iv: toArrayBuffer(iv),
          additionalData: toArrayBuffer(
            await deviceWrapAad(userId, deviceKeyId, epochId),
          ),
          tagLength: AES_GCM_TAG_BITS,
        },
        deviceKey,
        toArrayBuffer(accountRootSecret),
      ),
    );
    const wrapped = concatenateBytes(iv, ciphertextAndTag);
    if (wrapped.length !== ARS_WRAP_FRAME_BYTES) {
      throw new PrivateVaultError(
        "The browser produced an invalid account-key vault.",
      );
    }
    return {
      id: vaultRecordId(userId, epochId),
      userId,
      accountKeyEpochId: epochId,
      deviceKeyId,
      deviceKey,
      wrappedAccountRootSecret: bytesToBase64Url(wrapped),
      createdAt: new Date().toISOString(),
    };
  } finally {
    accountRootSecret.fill(0);
  }
}

export async function loadAccountRootSecret(
  userId: string,
  accountKeyEpochId: string,
  expectedCommitment?: string,
): Promise<LocalAccountRootSecret | null> {
  const id = vaultRecordId(userId, accountKeyEpochId);
  const record = await readRecord(id);
  return record
    ? verifyCommitment(await unwrapRecord(record), expectedCommitment)
    : null;
}

export async function getOrCreateAccountRootSecret(
  userId: string,
  accountKeyEpochId: string,
  expectedCommitment?: string,
): Promise<LocalAccountRootSecret> {
  const id = vaultRecordId(userId, accountKeyEpochId);
  const existing = await readRecord(id);
  if (existing) {
    return verifyCommitment(await unwrapRecord(existing), expectedCommitment);
  }

  const candidate = await createRecord(userId, accountKeyEpochId);
  try {
    await addRecord(candidate);
    await requestPrivateStoragePersistence();
    const stored = await readRecord(id);
    if (!stored) throw new PrivateVaultError("The local account-key vault was not saved.");
    return verifyCommitment(await unwrapRecord(stored), expectedCommitment);
  } catch (error) {
    if (error instanceof DOMException && error.name === "ConstraintError") {
      const winner = await readRecord(id);
      if (winner) {
        return verifyCommitment(await unwrapRecord(winner), expectedCommitment);
      }
    }
    if (error instanceof PrivateVaultError) throw error;
    throw new PrivateVaultError(
      "Herd could not persist a private key in this browser.",
    );
  }
}

export async function forgetAccountRootSecret(
  userId: string,
  accountKeyEpochId: string,
): Promise<void> {
  await deleteRecord(vaultRecordId(userId, accountKeyEpochId));
}

export async function forgetAllAccountRootSecrets(userId: string): Promise<void> {
  if (!userId) throw new PrivateVaultError("The signed-in account is unavailable.");
  const database = await openVaultDatabase();
  try {
    const transaction = database.transaction(VAULT_STORE, "readwrite");
    const completion = transactionComplete(transaction);
    const cursorRequest = transaction.objectStore(VAULT_STORE).openCursor();
    await new Promise<void>((resolve, reject) => {
      cursorRequest.onerror = () =>
        reject(cursorRequest.error ?? new Error("IndexedDB cursor failed."));
      cursorRequest.onsuccess = () => {
        const cursor = cursorRequest.result;
        if (!cursor) {
          resolve();
          return;
        }
        const record = cursor.value as StoredVaultRecord;
        if (record.userId === userId) cursor.delete();
        cursor.continue();
      };
    });
    await completion;
  } catch (error) {
    if (error instanceof PrivateVaultError) throw error;
    throw new PrivateVaultError(
      "Herd could not remove this account’s private keys from the browser.",
    );
  } finally {
    database.close();
  }
}

export async function requestPrivateStoragePersistence(): Promise<boolean> {
  try {
    if (!navigator.storage?.persist) return false;
    if (await navigator.storage.persisted?.()) return true;
    return navigator.storage.persist();
  } catch {
    return false;
  }
}

export async function verifyPrivateVaultSupport(): Promise<void> {
  if (typeof globalThis.isSecureContext === "boolean" && !globalThis.isSecureContext) {
    throw new PrivateVaultError("Private responses require a secure HTTPS connection.");
  }
  const probeUserId = `vault-probe-${randomUuid()}`;
  const probeEpoch = randomUuid();
  const probeId = vaultRecordId(probeUserId, probeEpoch);
  try {
    const record = await createRecord(probeUserId, probeEpoch);
    await addRecord(record);
    const loaded = await readRecord(probeId);
    if (!loaded) throw new PrivateVaultError("The private key storage check failed.");
    const accountRootSecret = await unwrapRecord(loaded);
    accountRootSecret.bytes.fill(0);
  } finally {
    await deleteRecord(probeId).catch(() => undefined);
  }
}
