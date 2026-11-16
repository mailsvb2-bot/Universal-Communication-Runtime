import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {test} from "node:test";
import vm from "node:vm";
import {
  pickSystemContact, parseSingleVcard, readSelectedVcard,
  checkedPublicInvite, smsDraftHref, PhonebookUnavailable
} from "../crates/ucr-realtime-web/static/phonebook.js";

const site="https://app.petrellink.ru";
const source=readFileSync("crates/ucr-realtime-web/static/start.js","utf8");
const page=readFileSync("crates/ucr-realtime-web/static/start.html","utf8");

test("LOCK native phonebook: one user gesture, name/tel only, never bulk",async()=>{
  let invoked=0;
  const selected=await pickSystemContact({contacts:{select:async(fields,options)=>{
    invoked++;
    assert.deepEqual(fields,["name","tel"]);
    assert.deepEqual(options,{multiple:false});
    return [{name:["  Я Сбер  "],tel:["+7 (999) 111-22-33"]}];
  }}});
  assert.equal(invoked,1);
  assert.deepEqual(selected,{displayName:"Я Сбер",phone:"+79991112233"});
  assert.equal(Object.hasOwn(selected,"identity"),false,"OS number is not a PetrelLink identity");
  assert.equal(Object.hasOwn(selected,"peerIdentityId"),false);
  assert.equal(Object.isFrozen(selected),true);
  assert.equal(await pickSystemContact({contacts:{select:async()=>[]}}),null,"cancel must not manufacture contact");
  await assert.rejects(pickSystemContact({}),PhonebookUnavailable,"desktop fallback must be explicit");
});

test("LOCK phonebook: invalid OS input never yields an authenticated contact",async()=>{
  for(const entry of [
    {name:[],tel:["+79991112233"]},
    {name:[""],tel:["+79991112233"]},
    {name:["Name\u0000\n"],tel:["123"]},
  ]){
    if(entry.name[0]==="Name\u0000\n"){
      const item=await pickSystemContact({contacts:{select:async()=>[entry]}});
      assert.equal(item.displayName,"Name");
      assert.equal(item.phone,null);
    } else {
      await assert.rejects(pickSystemContact({contacts:{select:async()=>[entry]}}),PhonebookUnavailable);
    }
  }
});

test("LOCK vCard: exactly one local contact, no automatic address-book import",async()=>{
  const vcard="BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Мария Иванова\r\nTEL:+79991112233\r\nEND:VCARD\r\n";
  assert.deepEqual(parseSingleVcard(vcard),{displayName:"Мария Иванова",phone:"+79991112233"});
  assert.throws(()=>parseSingleVcard(vcard+vcard),PhonebookUnavailable);
  const file={name:"person.vcf",size:Buffer.byteLength(vcard),arrayBuffer:async()=>new TextEncoder().encode(vcard).buffer};
  assert.deepEqual(await readSelectedVcard(file),{displayName:"Мария Иванова",phone:"+79991112233"});
});

test("LOCK invite: phone numbers are SMS destinations, never identity or authority",()=>{
  const invite=site+"/start?contact=fp-id-safe123";
  assert.equal(checkedPublicInvite(invite,site),invite);
  const sms=smsDraftHref("+79991112233",invite,site);
  assert.match(sms,/^sms:\+79991112233\?body=/);
  assert.ok(decodeURIComponent(sms).includes(invite));
  for(const bad of [
    site+"/start?contact=fp-id-safe123&auth=secret",
    site+"/start?contact=fp-id-safe123#key=secret",
    "https://attacker.invalid/start?contact=fp-id-safe123",
    site+"/other?contact=fp-id-safe123",
  ])assert.throws(()=>checkedPublicInvite(bad,site),PhonebookUnavailable);
});

test("LOCK selected OS contact populates name only; no false calling identity",()=>{
  const begin=source.indexOf("let selectedPhone = null,selectedPhoneScope=null;");
  const end=source.indexOf('el("pl-pick-phone-contact").addEventListener',begin);
  assert.ok(begin>=0&&end>begin);
  const ids=["pl-phonebook-result","pl-sms-invite","pl-vcard-file","contact-name","pl-add-by-invite"];
  const elements=Object.fromEntries(ids.map(id=>[id,{hidden:true,textContent:"",value:"",open:false}]));
  const state={
    accountScope:"device:alice",plOwnIdentity:"alice",uiAuthGeneration:1,
    el:id=>{assert.ok(elements[id],id);return elements[id];}
  };
  vm.runInNewContext(source.slice(begin,end)+"\nthis.accept=acceptPhoneContact;this.reset=resetPhonebook;",state);
  const selected={displayName:"Я Сбер",phone:"+79991112233"};
  state.accept(selected);
  assert.equal(elements["contact-name"].value,"Я Сбер");
  assert.equal(elements["pl-sms-invite"].hidden,false);
  assert.equal(elements["pl-add-by-invite"].open,true);
  assert.match(elements["pl-phonebook-result"].textContent,/обменяться приглашениями/);
  assert.match(page,/id="contact-peer"[^>]*required/,"identity still requires explicit verified invitation");
  state.accountScope=null;
  state.reset();
  assert.equal(elements["pl-phonebook-result"].hidden,true);
  assert.equal(elements["pl-sms-invite"].hidden,true);
  assert.equal(elements["pl-vcard-file"].value,"");
});
