import assert from "node:assert/strict";
import {test} from "node:test";
import {parseSingleVcard,readSelectedVcard,normalizeSelectedPhone,smsDraftHref,pickSystemContact,PhonebookUnavailable,checkedPublicInvite} from "../crates/ucr-realtime-web/static/phonebook.js";
import {friendlyCallError,sharePublicInvite,supportedContactMethods} from "../crates/ucr-realtime-web/static/consumer-actions.js";
const origin="https://app.petrellink.ru";
test("one selected vCard",()=>{
 assert.deepEqual(parseSingleVcard("BEGIN:VCARD\r\nFN:Василий \r\n Петров\r\nTEL:+7 (999) 111-22-33\r\nEND:VCARD"),{displayName:"Василий Петров",phone:"+79991112233"});
});
test("reject bulk, malformed, injection",()=>{
 assert.throws(()=>parseSingleVcard("BEGIN:VCARD\nFN:One\nEND:VCARD\nBEGIN:VCARD\nFN:Two\nEND:VCARD"),PhonebookUnavailable);
 assert.throws(()=>parseSingleVcard("BEGIN:VCARD\nFN:One"),PhonebookUnavailable);
 for(const bad of ["tel:+79991112233","123;body=evil","911"])assert.equal(normalizeSelectedPhone(bad),null);
});
test("strict UTF-8 and actual file size",async()=>{
 await assert.rejects(readSelectedVcard({name:"one.vcf",size:5,arrayBuffer:async()=>Uint8Array.from([255]).buffer}),PhonebookUnavailable);
 await assert.rejects(readSelectedVcard({name:"one.vcf",size:5,arrayBuffer:async()=>new Uint8Array(1048577).buffer}),PhonebookUnavailable);
});
test("system picker selects one",async()=>{
 const c=await pickSystemContact({contacts:{select:async(keys,options)=>{assert.deepEqual(keys,["name","tel"]);assert.deepEqual(options,{multiple:false});return [{name:["Вася"],tel:["+79991112233"]}];}}});
 assert.equal(c.displayName,"Вася");await assert.rejects(pickSystemContact({}),PhonebookUnavailable);
});
test("strict public locator",()=>{
 const good=origin+"/start?contact=a";assert.equal(checkedPublicInvite(good,origin),good);
 for(const bad of [origin+"/start?contact=a&token=x",origin+"/start?contact=a#ucr_join=secret","https://evil.test/start?contact=a"])assert.throws(()=>checkedPublicInvite(bad,origin),PhonebookUnavailable);
 assert.match(smsDraftHref("+79991112233",good,origin),/^sms:/);
});
test("no automatic resend after sharing cancelled",async()=>{
 let copies=0;
 const state=await sharePublicInvite({url:origin+"/start?contact=a",origin,navigatorLike:{share:async()=>{const e=new Error("no");e.name="AbortError";throw e;}},copyFallback:async()=>{copies++;}});
 assert.equal(state,"cancelled");assert.equal(copies,0);
});
test("technical errors hidden; external apps not guessed",()=>{
 assert.doesNotMatch(friendlyCallError(new Error("HTTP 401 bearer password xyz")),/password|xyz|bearer/);
 assert.match(supportedContactMethods({hasPetrelLinkIdentity:true}).otherApps,/не определяется/);
});
