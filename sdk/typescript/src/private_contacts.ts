/**
 * Endpoint-local private contacts. Neither this book nor its portable backup
 * changes UCR's canonical Identity/Device owners or writes server state.
 * The browser stores ciphertext and a NON-EXTRACTABLE local AES-GCM key in
 * the existing ucr-endpoint-state-v1 IndexedDB database (no new DB/table).
 * Cross-device transfer requires an explicit user-held encrypted backup.
 * The contact book does NOT restore cryptographic Device trust or E2EE keys.
 */
export interface UcrContactScope {
  readonly tenantId: string;
  readonly namespaceId: string | null;
  readonly identityId: string;
}
export interface UcrPrivateContact {
  readonly id: string;
  readonly displayName: string;
  readonly peerIdentityId: string;
}
interface SealedBook { readonly version: 1; readonly revision: string; readonly iv: number[]; readonly data: number[]; }
export interface UcrPrivateContactsStorage {
  getKey(scopeKey: string): Promise<CryptoKey>;
  read(bookKey: string): Promise<SealedBook | null>;
  compareAndSwap(bookKey: string, revision: string | null, value: SealedBook): Promise<boolean>;
}
const DATABASE = "ucr-endpoint-state-v1", DB_VERSION = 2;
const KEYS = "wrapping-key-vault", BOOKS = "sealed-snapshots";
const LOCAL_DOMAIN = "UCR-PRIVATE-CONTACTS-LOCAL-V1\u0000";
const TRANSFER_DOMAIN = "UCR-PRIVATE-CONTACTS-TRANSFER-V1\u0000";
const KEY_PREFIX = "ucr-private-contacts-key:v1:";
const BOOK_PREFIX = "ucr-private-contacts-book:v1:";
const MAX_CONTACTS = 4096, MAX_BYTES = 1024 * 1024, ITERATIONS = 600000;

function cryptoApi(): Crypto {
  if (!globalThis.crypto?.subtle || !globalThis.crypto.getRandomValues) {
    throw new Error("secure WebCrypto required for private contacts");
  }
  return globalThis.crypto;
}
function encode(value: string): Uint8Array<ArrayBuffer> { return new TextEncoder().encode(value); }
function checkOpaque(value: unknown): asserts value is string {
  if (typeof value !== "string" || !value || encode(value).length > 128) {
    throw new Error("invalid canonical Identity/scope identifier");
  }
}
function checkedScope(scope: UcrContactScope): string {
  if (!scope || !(scope.namespaceId === null || typeof scope.namespaceId === "string")) {
    throw new Error("invalid private contact scope");
  }
  checkOpaque(scope.tenantId);
  checkOpaque(scope.identityId);
  if (scope.namespaceId !== null) checkOpaque(scope.namespaceId);
  return JSON.stringify([scope.tenantId, scope.namespaceId, scope.identityId]);
}
function checkContact(value: UcrPrivateContact): void {
  if (!value || typeof value.id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.id)) {
    throw new Error("invalid local contact identifier");
  }
  if (typeof value.displayName !== "string" || !value.displayName.trim() || encode(value.displayName).length > 256) {
    throw new Error("invalid contact display name");
  }
  checkOpaque(value.peerIdentityId);
}
function checkContacts(input: unknown): UcrPrivateContact[] {
  if (!Array.isArray(input) || input.length > MAX_CONTACTS) throw new Error("contacts quota exceeded");
  const ids = new Set<string>(), peers = new Set<string>();
  for (const contact of input) {
    checkContact(contact);
    if (ids.has(contact.id) || peers.has(contact.peerIdentityId)) throw new Error("duplicate private contact");
    ids.add(contact.id); peers.add(contact.peerIdentityId);
  }
  return input.map(item => ({id:item.id, displayName:item.displayName, peerIdentityId:item.peerIdentityId}));
}
function randomBytes(length: number): Uint8Array<ArrayBuffer> {return cryptoApi().getRandomValues(new Uint8Array(length));}
function bytes(input: unknown, expected: number | null = null): Uint8Array<ArrayBuffer> {
  if (!Array.isArray(input) || input.length > MAX_BYTES + 32 ||
      (expected !== null && input.length !== expected) ||
      input.some(x => !Number.isInteger(x) || x < 0 || x > 255)) throw new Error("corrupt encrypted contacts record");
  return Uint8Array.from(input);
}
function toBase64(value: Uint8Array): string {
  let s = "";
  for (let i = 0; i < value.length; i += 8192) s += String.fromCharCode(...value.subarray(i, i + 8192));
  return btoa(s);
}
function fromBase64(s: unknown, max: number): Uint8Array<ArrayBuffer> {
  if (typeof s !== "string" || s.length > Math.ceil(max / 3) * 4 + 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    throw new Error("invalid encrypted contact backup encoding");
  }
  const data = atob(s);
  if (data.length > max) throw new Error("contact backup too large");
  return Uint8Array.from(data, x => x.charCodeAt(0));
}
function parseContacts(data: Uint8Array, scope: string): UcrPrivateContact[] {
  if (data.length > MAX_BYTES) throw new Error("contact book too large");
  const parsed: unknown = JSON.parse(new TextDecoder("utf-8", {fatal:true}).decode(data));
  if (!parsed || typeof parsed !== "object") throw new Error("invalid contact book");
  const p = parsed as {version?:unknown; scope?:unknown; contacts?:unknown};
  if (p.version !== 1 || p.scope !== scope) throw new Error("contact book owner mismatch");
  return checkContacts(p.contacts);
}
function serialize(contacts: UcrPrivateContact[], scope: string): Uint8Array<ArrayBuffer> {
  const data = encode(JSON.stringify({version:1, scope, contacts:checkContacts(contacts)}));
  if (data.length > MAX_BYTES) throw new Error("contact book too large");
  return data;
}
function validKey(key: CryptoKey): void {
  if (!key || key.type !== "secret" || key.extractable || key.algorithm.name !== "AES-GCM" ||
      !key.usages.includes("encrypt") || !key.usages.includes("decrypt")) {
    throw new Error("invalid local contact encryption key");
  }
}
async function transferKey(password: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  if (typeof password !== "string" || encode(password).length < 12 || encode(password).length > 1024) {
    throw new Error("backup passphrase must contain at least 12 UTF-8 bytes (max 1024)");
  }
  const material = await cryptoApi().subtle.importKey("raw", encode(password), "PBKDF2", false, ["deriveKey"]);
  return cryptoApi().subtle.deriveKey(
    {name:"PBKDF2", salt, iterations:ITERATIONS, hash:"SHA-256"},
    material, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"],
  );
}
function revision(): string {
  const value = randomBytes(16);
  return Array.from(value, x => x.toString(16).padStart(2,"0")).join("");
}
function validateRecord(record: SealedBook): void {
  if (!record || record.version !== 1 || typeof record.revision !== "string" || !/^[0-9a-f]{32}$/.test(record.revision)) {
    throw new Error("corrupt contact book revision");
  }
  bytes(record.iv,12); bytes(record.data);
}

/** Uses the existing endpoint-owned IndexedDB stores; no new server or database. */
export function createUcrIndexedDbContactsStorage(): UcrPrivateContactsStorage {
  async function open(): Promise<IDBDatabase> {
    if (!globalThis.indexedDB) throw new Error("endpoint-owned IndexedDB unavailable");
    return new Promise((resolve,reject) => {
      const request = indexedDB.open(DATABASE, DB_VERSION);
      let settled = false;
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(KEYS)) db.createObjectStore(KEYS);
        if (!db.objectStoreNames.contains(BOOKS)) db.createObjectStore(BOOKS);
      };
      request.onsuccess = () => {
        // A blocked upgrade can succeed after another tab releases its DB.
        // Never leak a late connection after the caller has already failed.
        if (settled) { request.result.close(); return; }
        settled = true;
        resolve(request.result);
      };
      request.onerror = () => {
        if (settled) return;
        settled = true;
        reject(request.error ?? new Error("endpoint IndexedDB open failed"));
      };
      request.onblocked = () => {
        if (settled) return;
        settled = true;
        reject(new Error("endpoint IndexedDB upgrade blocked"));
      };
    });
  }
  return {
    async getKey(scopeKey) {
      const db = await open();
      try {
        const current = await new Promise<CryptoKey | null>((resolve,reject) => {
          const tx = db.transaction(KEYS, "readonly");
          const q = tx.objectStore(KEYS).get(scopeKey);
          q.onsuccess = () => resolve(q.result ?? null);
          q.onerror = () => reject(q.error ?? new Error("contact key read failed"));
          tx.onabort = () => reject(tx.error ?? new Error("contact key read aborted"));
        });
        if (current) {validKey(current); return current;}
        const candidate = await cryptoApi().subtle.generateKey({name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
        return await new Promise<CryptoKey>((resolve,reject) => {
          const tx = db.transaction(KEYS,"readwrite");
          const store = tx.objectStore(KEYS);
          const q = store.get(scopeKey);
          let chosen = candidate;
          q.onsuccess = () => {
            if (q.result) { chosen = q.result; return; }
            store.add(candidate,scopeKey);
          };
          tx.oncomplete = () => {try {validKey(chosen);resolve(chosen);}catch(e){reject(e);}};
          tx.onerror = () => reject(tx.error ?? new Error("contact key write failed"));
          tx.onabort = () => reject(tx.error ?? new Error("contact key write aborted"));
        });
      } finally {db.close();}
    },
    async read(bookKey) {
      const db = await open();
      try {
        return await new Promise<SealedBook | null>((resolve,reject) => {
          const tx = db.transaction(BOOKS,"readonly");
          const q = tx.objectStore(BOOKS).get(bookKey);
          q.onsuccess = () => resolve(q.result ?? null);
          q.onerror = () => reject(q.error ?? new Error("contact book read failed"));
          tx.onabort = () => reject(tx.error ?? new Error("contact book read aborted"));
        });
      } finally {db.close();}
    },
    async compareAndSwap(bookKey, expected, value) {
      const db = await open();
      try {
        return await new Promise<boolean>((resolve,reject) => {
          const tx = db.transaction(BOOKS,"readwrite");
          const store = tx.objectStore(BOOKS);
          const q = store.get(bookKey);
          let changed = false;
          q.onsuccess = () => {
            const actual = q.result as SealedBook | undefined;
            if ((actual?.revision ?? null) !== expected) return;
            store.put(value,bookKey);
            changed = true;
          };
          tx.oncomplete = () => resolve(changed);
          tx.onerror = () => reject(tx.error ?? new Error("contact book update failed"));
          tx.onabort = () => reject(tx.error ?? new Error("contact book update aborted"));
        });
      } finally {db.close();}
    },
  };
}

/** Host must authenticate scope using its existing canonical Identity owner. */
export function createUcrPrivateContactBook(
  scope: UcrContactScope,
  storage: UcrPrivateContactsStorage = createUcrIndexedDbContactsStorage(),
) {
  const id = checkedScope(scope);
  const keyId = KEY_PREFIX + id, bookId = BOOK_PREFIX + id;
  async function snapshot() {
    const record = await storage.read(bookId);
    if (!record) return {contacts:[] as UcrPrivateContact[], revision:null as string|null};
    validateRecord(record);
    const key = await storage.getKey(keyId);
    validKey(key);
    const plaintext = new Uint8Array(await cryptoApi().subtle.decrypt(
      {name:"AES-GCM",iv:bytes(record.iv,12),additionalData:encode(LOCAL_DOMAIN+id)},
      key,bytes(record.data),
    ));
    try {return {contacts:parseContacts(plaintext,id), revision:record.revision};}
    finally {plaintext.fill(0);}
  }
  async function modify(change: (contacts: UcrPrivateContact[]) => UcrPrivateContact[]): Promise<void> {
    for (let attempt=0; attempt<6; attempt++) {
      const current = await snapshot();
      const contacts = checkContacts(change(current.contacts));
      const key = await storage.getKey(keyId);
      validKey(key);
      const iv = randomBytes(12), raw = serialize(contacts,id);
      let sealed:Uint8Array;
      try {
        sealed = new Uint8Array(await cryptoApi().subtle.encrypt(
          {name:"AES-GCM",iv,additionalData:encode(LOCAL_DOMAIN+id)},key,raw,
        ));
      } finally {raw.fill(0);}
      const value: SealedBook = {version:1,revision:revision(),iv:Array.from(iv),data:Array.from(sealed)};
      if (await storage.compareAndSwap(bookId,current.revision,value)) return;
    }
    throw new Error("concurrent contact book modification; retry explicitly");
  }
  return {
    async list() {return (await snapshot()).contacts;},
    async add(displayName:string,peerIdentityId:string):Promise<UcrPrivateContact> {
      const entry = {id:cryptoApi().randomUUID(),displayName,peerIdentityId};
      checkContact(entry);
      await modify(contacts => {
        if (contacts.some(x=>x.peerIdentityId===entry.peerIdentityId)) throw new Error("contact already exists");
        return [...contacts,entry];
      });
      return entry;
    },
    async rename(contactId:string,displayName:string):Promise<void> {
      await modify(contacts => {
        if (!contacts.some(x=>x.id===contactId)) throw new Error("contact not found");
        return contacts.map(x=>x.id===contactId?{...x,displayName}:x);
      });
    },
    async remove(contactId:string):Promise<void> {
      await modify(contacts => {
        if (!contacts.some(x=>x.id===contactId)) throw new Error("contact not found");
        return contacts.filter(x=>x.id!==contactId);
      });
    },
    async exportEncrypted(password:string):Promise<string> {
      const contacts = (await snapshot()).contacts;
      const salt = randomBytes(16), iv = randomBytes(12);
      const key = await transferKey(password,salt);
      const raw = serialize(contacts,id);
      let ciphertext: Uint8Array;
      try {
        ciphertext = new Uint8Array(await cryptoApi().subtle.encrypt(
          {name:"AES-GCM",iv,additionalData:encode(TRANSFER_DOMAIN)},key,raw,
        ));
      } finally {raw.fill(0);}
      return JSON.stringify({format:"ucr-private-contacts-backup-v1",kdf:"PBKDF2-SHA256",
        iterations:ITERATIONS,salt:toBase64(salt),iv:toBase64(iv),data:toBase64(ciphertext)});
    },
    async importEncrypted(text:string,password:string):Promise<void> {
      if (typeof text!=="string" || text.length>MAX_BYTES*2)throw new Error("invalid contact backup size");
      const p = JSON.parse(text);
      if (!p || p.format!=="ucr-private-contacts-backup-v1" || p.kdf!=="PBKDF2-SHA256" || p.iterations!==ITERATIONS) {
        throw new Error("unsupported contacts backup");
      }
      const salt=fromBase64(p.salt,16),iv=fromBase64(p.iv,12),cipher=fromBase64(p.data,MAX_BYTES+16);
      if (salt.length!==16 || iv.length!==12 || cipher.length<16) throw new Error("invalid contact backup parameters");
      const key=await transferKey(password,salt);
      const raw = new Uint8Array(await cryptoApi().subtle.decrypt(
        {name:"AES-GCM",iv,additionalData:encode(TRANSFER_DOMAIN)},key,cipher,
      ));
      let incoming:UcrPrivateContact[];
      try {incoming=parseContacts(raw,id);} finally {raw.fill(0);}
      await modify(existing => {
        const byId=new Map(existing.map(c=>[c.id,c]));
        const byPeer=new Map(existing.map(c=>[c.peerIdentityId,c]));
        const merged=[...existing];
        for (const c of incoming) {
          const conflict=byId.get(c.id) ?? byPeer.get(c.peerIdentityId);
          if (conflict) {
            if (conflict.id!==c.id || conflict.peerIdentityId!==c.peerIdentityId || conflict.displayName!==c.displayName) {
              throw new Error("contact import conflict: refusing overwrite");
            }
          } else {merged.push(c);byId.set(c.id,c);byPeer.set(c.peerIdentityId,c);}
        }
        return merged;
      });
    },
  };
}
