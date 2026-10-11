import assert from "node:assert/strict";
import {webcrypto} from "node:crypto";
import {createUcrPrivateContactBook, type UcrPrivateContactsStorage} from "./src/private_contacts.ts";
if (!globalThis.crypto) Object.defineProperty(globalThis,"crypto",{value:webcrypto});

function memoryStore(): {storage:UcrPrivateContactsStorage; encrypted:Map<string,unknown>; keys:Map<string,CryptoKey>} {
  const encrypted=new Map<string,any>(), keys=new Map<string,CryptoKey>();
  const storage:UcrPrivateContactsStorage = {
    async getKey(k) {
      let v=keys.get(k);
      if (!v) {
        v=await crypto.subtle.generateKey({name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
        keys.set(k,v);
      }
      return v;
    },
    async read(k) {return encrypted.get(k)??null;},
    async compareAndSwap(k,expected,value) {
      if ((encrypted.get(k)?.revision??null)!==expected)return false;
      encrypted.set(k,value); return true;
    },
  };
  return {storage,encrypted,keys};
}
const firstStore=memoryStore();
const scope={tenantId:"tenant",namespaceId:null,identityId:"owner"};
const first=createUcrPrivateContactBook(scope,firstStore.storage);
assert.deepEqual(await first.list(),[]);
const alex=await first.add("Alex","peer-alex");
await first.add("Sam","peer-sam");
assert.equal((await first.list()).length,2);
assert.equal(JSON.stringify([...firstStore.encrypted.values()]).includes("Alex"),false,"only ciphertext at rest");
assert.equal(firstStore.keys.size,1);
assert.equal([...firstStore.keys.values()][0].extractable,false);
await first.rename(alex.id,"Alex New");
assert.equal((await createUcrPrivateContactBook(scope,firstStore.storage).list())[0].displayName,"Alex New");
await assert.rejects(first.add("duplicate","peer-alex"),/already exists/);

const password="a secure transfer passphrase";
const payload=await first.exportEncrypted(password);
assert.equal(payload.includes("peer-alex"),false,"encrypted backup must hide contacts");
await assert.rejects(first.importEncrypted(payload,"incorrect password"));
const otherStore=memoryStore();
const second=createUcrPrivateContactBook(scope,otherStore.storage);
await second.importEncrypted(payload,password);
assert.deepEqual(await second.list(),await first.list(),"cross-device transfer for same identity");
assert.notEqual([...firstStore.keys.values()][0],[...otherStore.keys.values()][0],
  "transfer cannot export the existing device-local wrapping key");
await second.importEncrypted(payload,password);
assert.equal((await second.list()).length,2,"idempotent import");
await assert.rejects(
  createUcrPrivateContactBook({...scope,identityId:"another-owner"},otherStore.storage)
    .importEncrypted(payload,password),
  /owner mismatch/,
);
const tampered=JSON.parse(payload);
tampered.data=tampered.data.slice(0,-8)+"AAAAAAAA";
await assert.rejects(second.importEncrypted(JSON.stringify(tampered),password));
await second.rename(alex.id,"Different");
await assert.rejects(second.importEncrypted(payload,password),/conflict/);
await second.remove(alex.id);
assert.equal((await second.list()).length,1);
assert.equal((await first.list()).length,2,"device-local mutations must not sync to other device");

// Simulated CAS race: first writer loses once, reloads the latest encrypted
// state and retries without dropping the intervening contact.
let contested=false;
const concurrentStore=memoryStore();
const book=createUcrPrivateContactBook(scope,{
  ...concurrentStore.storage,
  async compareAndSwap(k,expected,value) {
    if (!contested) {
      contested=true;
      return false;
    }
    return concurrentStore.storage.compareAndSwap(k,expected,value);
  },
});
await book.add("Race","peer-race");
assert.equal((await book.list()).length,1);
assert.equal(contested,true);

console.log("UCR_PRIVATE_CONTACTS_LOCAL_ENCRYPTED_TRANSFER_OK");
