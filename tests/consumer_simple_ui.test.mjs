import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";
const html=readFileSync("crates/ucr-realtime-web/static/start.html","utf8");
const js=readFileSync("crates/ucr-realtime-web/static/start.js","utf8");
assert.match(html,/id="pl-contacts" hidden/);
assert.match(html,/class="call-stage"[^>]*hidden/);
assert.match(html,/id="pl-call-technical"/);
assert.match(html,/#pl-contacts\{order:4\}/);
assert.match(html,/id="pl-add-by-invite"/);
assert.match(html,/id="auth-diagnostics"/);
assert.match(js,/calls\.start\(contact\.id,media,requestId\)/);

function element(tag="div"){
 return {tag,children:[],dataset:{},hidden:false,textContent:"",className:"",
   append(...items){this.children.push(...items);},
   appendChild(item){this.children.push(item);},
   replaceChildren(){this.children=[];},
   setAttribute(k,v){this[k]=v},
 };
}
const list=element("ul"),filter={value:""};
const buttons=[];
const calls=[];
const context={
  knownContacts:[],lang:"ru",
  document:{createElement:element,createTextNode:x=>x},
  el:id=>id==="contacts"?list:id==="pl-contacts-filter"?filter:assert.fail("unexpected element "+id),
  textNode:v=>v,
  btn:(label,callback)=>{
    const b=element("button");
    b.textContent=label;
    b.callback=callback;
    buttons.push(b);return b;
  },
  dial:async (contact,media)=>{calls.push([contact.id,media]);},
  friendlyCallError:e=>e.message,
  localize:x=>x,
  window:{prompt:()=>null,confirm:()=>false},
  updateContacts:async()=>{},
};
const start=js.indexOf("function renderContacts(contacts) {");
const end=js.indexOf("async function updateContacts()",start);
assert.ok(start>=0&&end>start);
vm.runInNewContext(js.slice(start,end)+"\nthis.renderContacts=renderContacts;",context);
const people=[{id:"2",displayName:"Яна",peerIdentityId:"id-y"},
              {id:"1",displayName:"Василий",peerIdentityId:"id-v"}];
context.renderContacts(people);
assert.equal(list.children.length,2);
assert.equal(list.children[0].children[0].children[1].children[0],"Василий");
assert.equal(list.children[1].children[0].children[1].children[0],"Яна");
const audio=buttons.find(b=>b.textContent==="Позвонить");
const video=buttons.find(b=>b.textContent==="Видеозвонок");
assert.ok(audio&&video);
assert.match(audio["aria-label"],/Аудиозвонок: Василий/);
await audio.callback();await video.callback();
assert.equal(JSON.stringify(calls),JSON.stringify([["1","audio"],["1","video"]]));
filter.value="несуществующий";
context.renderContacts(people);
assert.equal(list.children.length,1);
assert.match(list.children[0].textContent,/не найдены/);
filter.value="";
context.renderContacts([]);
assert.match(list.children[0].textContent,/Пригласите друга/);

// A desktop browser must not expose a non-functional native address-book control.
const begin=js.indexOf("// Native Contact Picker is not available on most desktop browsers.");
const finish=js.indexOf("let selectedPhone = ",begin);
assert.ok(begin>=0&&finish>begin);
const picker=element("button"),hint=element("p");
vm.runInNewContext(js.slice(begin,finish),{
 navigator:{},
 el:id=>id==="pl-pick-phone-contact"?picker:id==="pl-phonebook-help"?hint:assert.fail(id)
});
assert.equal(picker.hidden,true);
assert.match(hint.textContent,/\.vcf/);
const supportedPicker=element("button");
vm.runInNewContext(js.slice(begin,finish),{
 navigator:{contacts:{select:async()=>[]}},
 el:id=>id==="pl-pick-phone-contact"?supportedPicker:element()
});
assert.equal(supportedPicker.hidden,false);
console.log("PASS: consumer UI renders searchable cards, real audio/video actions, correct empty states and honest picker fallback");
