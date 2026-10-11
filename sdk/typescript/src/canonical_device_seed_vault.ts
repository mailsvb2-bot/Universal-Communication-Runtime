import type {
  UcrCanonicalDeviceKeyVault,
  UcrDeviceVaultScope,
  UcrLocalDeviceSigner,
} from "./canonical_device_enrollment.ts";

/**
 * One endpoint-owned device signer, stored in the ALREADY EXISTING
 * ucr-endpoint-state-v1/wrapping-key-vault IndexedDB object store.
 * No call/session-derived key, server signing seed, shadow trust database,
 * phone directory, or replacement authorization authority.
 *
 * The AES-GCM wrapping CryptoKey is non-extractable and structured-cloned
 * into IndexedDB; the 32-byte Ed25519 seed exists in memory only while
 * generating, signing or initializing the canonical Rust/WASM media bridge.
 * This offers at-rest protection but does NOT defeat a compromised browser
 * origin or malware with access to active JavaScript. No hardware-backed
 * security or cross-device recovery is claimed.
 */
export interface UcrLocalSignerRecord {
  readonly version: number;
  readonly keyId: string;
  readonly publicKey: number[];
  readonly wrappingKey: CryptoKey;
  readonly iv: number[];
  readonly encryptedSeed: number[];
}

export interface UcrLocalSignerRecordStore {
  get(key: string): Promise<UcrLocalSignerRecord | null>;
  addIfAbsent(key: string, value: UcrLocalSignerRecord): Promise<boolean>;
}

const DB_NAME = "ucr-endpoint-state-v1";
const DB_VERSION = 2;
const RECORD_STORE = "wrapping-key-vault";
const RECORD_VERSION = 1;
const KEY_PREFIX = "ucr-device-signer:v1:";
const DOMAIN = "UCR-CANONICAL-DEVICE-SEED-V1\u0000";
const PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function browserCrypto(): Crypto {
  const provider = globalThis.crypto;
  if (!provider?.subtle || typeof provider.getRandomValues !== "function") {
    throw new Error("secure Ed25519 and AES-GCM WebCrypto unavailable");
  }
  return provider;
}

function validateScope(scope: UcrDeviceVaultScope): string {
  if (!scope || typeof scope.tenantId !== "string" ||
      typeof scope.deviceId !== "string" ||
      !(scope.namespaceId === null || typeof scope.namespaceId === "string")) {
    throw new Error("canonical tenant/namespace/Device scope required");
  }
  const bytes = new TextEncoder();
  for (const id of [scope.tenantId, scope.deviceId, scope.namespaceId]) {
    if (id !== null && (bytes.encode(id).length === 0 ||
         bytes.encode(id).length > 128)) {
      throw new Error("canonical Device scope identifier exceeds bounds");
    }
  }
  // The prefix and exact tuple cannot collide with call-scoped MLS records.
  const key = KEY_PREFIX + JSON.stringify([
    scope.tenantId, scope.namespaceId, scope.deviceId,
  ]);
  if (key.length > 2048) throw new Error("canonical Device vault key exceeds bounds");
  return key;
}

function bytes(value: number[], len: number, field: string): Uint8Array {
  if (!Array.isArray(value) || value.length !== len ||
      value.some(x => !Number.isInteger(x) || x < 0 || x > 255)) {
    throw new Error(`corrupt protected Device ${field}`);
  }
  return Uint8Array.from(value);
}

function aad(key: string, signer: UcrLocalDeviceSigner): Uint8Array {
  return new TextEncoder().encode(DOMAIN + JSON.stringify([
    key, signer.keyId, Array.from(signer.publicKey),
  ]));
}

function descriptor(record: UcrLocalSignerRecord): UcrLocalDeviceSigner {
  if (record?.version !== RECORD_VERSION ||
      typeof record.keyId !== "string" || !record.keyId ||
      !record.wrappingKey || record.wrappingKey.type !== "secret" ||
      record.wrappingKey.extractable ||
      record.wrappingKey.algorithm.name !== "AES-GCM" ||
      !record.wrappingKey.usages.includes("decrypt") ||
      !record.wrappingKey.usages.includes("encrypt")) {
    throw new Error("corrupt protected Device signer record");
  }
  bytes(record.iv, 12, "IV");
  bytes(record.encryptedSeed, 48, "ciphertext");
  return {keyId: record.keyId, publicKey: bytes(record.publicKey, 32, "public key")};
}

async function decryptSeed(key: string, record: UcrLocalSignerRecord): Promise<Uint8Array> {
  const signer = descriptor(record);
  const plaintext = new Uint8Array(await browserCrypto().subtle.decrypt(
    {name: "AES-GCM", iv: bytes(record.iv, 12, "IV"), additionalData: aad(key, signer)},
    record.wrappingKey,
    bytes(record.encryptedSeed, 48, "ciphertext"),
  ));
  if (plaintext.length !== 32) {
    plaintext.fill(0);
    throw new Error("corrupt protected Device signing seed length");
  }
  return plaintext;
}

function pkcs8(seed: Uint8Array): Uint8Array {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new Error("protected Device signing seed must be 32 bytes");
  }
  const blob = new Uint8Array(48);
  blob.set(PKCS8_PREFIX);
  blob.set(seed, PKCS8_PREFIX.length);
  return blob;
}

/**
 * Atomic compare-and-insert uses the existing object store. Competing tabs
 * cannot silently replace an already staged permanent Device signer.
 */
export function createUcrIndexedDbDeviceSignerStore(): UcrLocalSignerRecordStore {
  async function open(): Promise<IDBDatabase> {
    if (!globalThis.indexedDB) throw new Error("canonical local IndexedDB vault unavailable");
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains("sealed-snapshots")) {
          db.createObjectStore("sealed-snapshots");
        }
        if (!db.objectStoreNames.contains(RECORD_STORE)) {
          db.createObjectStore(RECORD_STORE);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("Device vault open failed"));
      request.onblocked = () => reject(new Error("Device vault upgrade blocked"));
    });
  }
  return {
    async get(key) {
      const db = await open();
      try {
        return await new Promise<UcrLocalSignerRecord | null>((resolve, reject) => {
          const tx = db.transaction(RECORD_STORE, "readonly");
          const query = tx.objectStore(RECORD_STORE).get(key);
          query.onsuccess = () => resolve(query.result ?? null);
          query.onerror = () => reject(query.error ?? new Error("Device vault read failed"));
          tx.onabort = () => reject(tx.error ?? new Error("Device vault read aborted"));
        });
      } finally {db.close();}
    },
    async addIfAbsent(key, value) {
      const db = await open();
      try {
        return await new Promise<boolean>((resolve, reject) => {
          const tx = db.transaction(RECORD_STORE, "readwrite");
          const put = tx.objectStore(RECORD_STORE).add(value, key);
          let duplicate = false;
          put.onerror = (event) => {
            if (put.error?.name === "ConstraintError") {
              duplicate = true;
              event.preventDefault();
              event.stopPropagation();
            }
          };
          tx.oncomplete = () => resolve(!duplicate);
          tx.onerror = () => reject(tx.error ?? new Error("Device vault write failed"));
          tx.onabort = () => reject(tx.error ?? new Error("Device vault write aborted"));
        });
      } finally {db.close();}
    },
  };
}

export interface UcrProtectedDeviceSeedVault extends UcrCanonicalDeviceKeyVault {
  /** The seed is handed to an independently authorized bridge initializer
   * only for the duration of this operation. The REQUIRED revoke callback
   * must invalidate any partially created/installed bridge if initialization
   * throws or trust is withdrawn while the asynchronous initializer runs.
   * Active media still requires its own live, synchronous isCurrent guard.
   * The callback must be idempotent and must never reauthorize.
   */
  withAuthorizedSeed<T>(
    scope: UcrDeviceVaultScope,
    current: () => Promise<boolean>,
    useSeed: (seed: Uint8Array) => Promise<T>,
    revokeOnFailure: () => void | Promise<void>,
  ): Promise<T>;
}

export function createUcrBrowserProtectedDeviceVault(
  store: UcrLocalSignerRecordStore = createUcrIndexedDbDeviceSignerStore(),
): UcrProtectedDeviceSeedVault {
  const loadRecord = async (key: string) => {
    const result = await store.get(key);
    if (result !== null) descriptor(result);
    return result;
  };
  return {
    async load(scope) {
      const key = validateScope(scope);
      const found = await loadRecord(key);
      return found === null ? null : descriptor(found);
    },
    async stageNew(scope) {
      const key = validateScope(scope);
      const existing = await loadRecord(key);
      if (existing) return descriptor(existing);
      const provider = browserCrypto();
      const pair = await provider.subtle.generateKey(
        {name: "Ed25519"}, true, ["sign", "verify"],
      );
      const publicKey = new Uint8Array(await provider.subtle.exportKey("raw", pair.publicKey));
      const secret = new Uint8Array(await provider.subtle.exportKey("pkcs8", pair.privateKey));
      let seed: Uint8Array | null = null;
      try {
        if (secret.length !== 48 ||
            !PKCS8_PREFIX.every((value, i) => secret[i] === value)) {
          throw new Error("unsupported protected Ed25519 seed encoding");
        }
        seed = secret.slice(16);
        const digest = new Uint8Array(await provider.subtle.digest("SHA-256", publicKey));
        const keyId = "ucr-ed25519-" +
          Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
        const signer = {keyId, publicKey};
        const wrappingKey = await provider.subtle.generateKey(
          {name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"],
        );
        const iv = provider.getRandomValues(new Uint8Array(12));
        const encryptedSeed = new Uint8Array(await provider.subtle.encrypt(
          {name: "AES-GCM", iv, additionalData: aad(key, signer)},
          wrappingKey, seed,
        ));
        const candidate: UcrLocalSignerRecord = {
          version: RECORD_VERSION, keyId, publicKey: Array.from(publicKey),
          wrappingKey, iv: Array.from(iv), encryptedSeed: Array.from(encryptedSeed),
        };
        // Atomic add: another browser tab can win. Never overwrite that seed.
        if (await store.addIfAbsent(key, candidate)) return descriptor(candidate);
        const winner = await loadRecord(key);
        if (!winner) throw new Error("concurrent Device key initialization lost");
        return descriptor(winner);
      } finally {
        secret.fill(0);
        seed?.fill(0);
      }
    },
    async signChallenge(scope, challenge) {
      if (!(challenge instanceof Uint8Array) || challenge.length === 0 ||
          challenge.length > 2048) {
        throw new Error("invalid canonical Device proof challenge");
      }
      const key = validateScope(scope);
      const found = await loadRecord(key);
      if (!found) throw new Error("protected Device signer is missing");
      const seed = await decryptSeed(key, found);
      const encoded = pkcs8(seed);
      try {
        const privateKey = await browserCrypto().subtle.importKey(
          "pkcs8", encoded, {name: "Ed25519"}, false, ["sign"],
        );
        return new Uint8Array(await browserCrypto().subtle.sign(
          "Ed25519", privateKey, challenge.slice(),
        ));
      } finally {
        seed.fill(0);
        encoded.fill(0);
      }
    },
    async withAuthorizedSeed(scope, current, useSeed, revokeOnFailure) {
      if (typeof current !== "function" || typeof useSeed !== "function" ||
          typeof revokeOnFailure !== "function" || !await current()) {
        throw new Error("independent canonical Device media trust and revoke hook required");
      }
      const key = validateScope(scope);
      const found = await loadRecord(key);
      if (!found) throw new Error("protected Device signer is missing");
      const seed = await decryptSeed(key, found);
      try {
        try {
          if (!await current()) throw new Error("canonical Device media trust revoked");
          const outcome = await useSeed(seed);
          // An initializer can already have installed a Rust/WASM bridge.
          // A rejected promise alone does not revoke its side effects.
          if (!await current()) throw new Error("canonical Device media trust revoked");
          return outcome;
        } catch (error) {
          try {
            await revokeOnFailure();
          } catch (rollbackError) {
            throw new AggregateError([error, rollbackError],
              "Device media bridge revocation failed after authorization error");
          }
          throw error;
        }
      } finally {seed.fill(0);}
    },
  };
}
