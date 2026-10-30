#!/usr/bin/env node
// Executable regression for anonymous invitation onboarding. No media or
// authenticated-contact claim: the locator remains untrusted until confirmed.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";

const source=readFileSync("crates/ucr-realtime-web/static/start.js","utf8");
const begin=source.indexOf("function plClearAuthenticatedView(preserveRecoveryCode=false){");
const end=source.indexOf("function plInviteUrl(){",begin);
assert.ok(begin>=0 && end>begin,"canonical authenticated-view reset missing");
const resetSource=source.slice(begin,end);

function makeView({code="alice.device-1",invited=true,scope=null,identity=null}={}){
  const peer={value:code,dataset:invited?{invitedContact:"true"}:{}};
  const recovery={hidden:false};
  const recoveryCode={value:"one-time-recovery"};
  const nodes={
    "contact-peer":peer,
    "new-contact":{reset(){peer.value="";}},
    "devices":{replaceChildren(){}},
    "who":{textContent:""},
    "pl-invite-help":{hidden:false},
    "recovery-output":recovery,
    "recovery-code":recoveryCode,
  };
  const state={
    accountScope:scope,plOwnIdentity:identity,uiAuthGeneration:0,
    active:{},knownContacts:[{id:"old"}],timer:null,idempotency:new Map([["old",true]]),
    clearInterval(){},renderContacts(){},renderIncoming(){},showActive(){},
    plSetSignedIn(){state.plOwnIdentity=null;},
    el(id){assert.ok(nodes[id],"unexpected UI node "+id);return nodes[id];},
  };
  runInNewContext(resetSource+"\nthis.resetView=plClearAuthenticatedView;",state);
  return {state,peer,recovery,recoveryCode,reset:()=>state.resetView()};
}

const anonymous=makeView();
anonymous.reset();
assert.equal(anonymous.peer.value,"alice.device-1",
  "initial missing-session cleanup must retain the received invitation code");
assert.equal(anonymous.peer.dataset.invitedContact,"true");
assert.equal(anonymous.state.accountScope,null);
assert.equal(anonymous.state.active,null);
assert.equal(anonymous.state.knownContacts.length,0);
assert.equal(anonymous.state.uiAuthGeneration,1);
assert.equal(anonymous.recoveryCode.value,"",
  "ordinary anonymous cleanup must not retain old recovery credentials");

const invalid=makeView({code:"not a valid invitation!"});
invalid.reset();
assert.equal(invalid.peer.value,"","malformed invite must not survive cleanup");
assert.equal(invalid.peer.dataset.invitedContact,undefined);

const authenticated=makeView({scope:"existing-canonical-device",identity:"alice"});
authenticated.reset();
assert.equal(authenticated.peer.value,"",
  "logout or revoked authenticated Device must clear old invitation");
assert.equal(authenticated.peer.dataset.invitedContact,undefined);

const signedInWithoutScope=makeView({identity:"alice"});
signedInWithoutScope.reset();
assert.equal(signedInWithoutScope.peer.value,"",
  "account switch cannot carry an invitation when identity was authenticated");

const signupFailed=makeView();
signupFailed.reset(true);
assert.equal(signupFailed.peer.value,"alice.device-1");
assert.equal(signupFailed.recoveryCode.value,"one-time-recovery",
  "committed signup with failed session issuance must preserve recovery code");

console.log("PASS: anonymous invite survives signup failure; logout, invalid input and account switch clear it");
