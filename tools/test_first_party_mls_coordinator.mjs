#!/usr/bin/env node
// Contract-level test of the ACTUAL /start.js coordinator against an isolated
// in-memory BFF/WASM model. Not a physical media, TLS, TURN or E2EE proof.
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";

const source=readFileSync("crates/ucr-realtime-web/static/start.js","utf8");
const begin=source.indexOf("async function prepareFirstPartyEndpointMls(");
const end=source.indexOf("async function beginMedia(",begin);
assert.ok(begin>=0&&end>begin,"real pre-Join MLS coordinator is missing");
const implementation=source.slice(begin,end);
const directCall={callId:"call-1",revision:2,state:"active"};
const canonical={epoch:null,revision:null,ref:null,offers:[],peerDevice:null};
const snapshots=new Map();
const order=[];
let rejectFirstOffer=true,recipientPackage=null,recipientGenerations=0;
let rejectGroupBeforeCommit=true,rejectGroupAfterCommit=true,creatorGenerations=0;
let wrongCanonicalCreatorRef=false;

function encode(value){return new TextEncoder().encode(JSON.stringify(value));}
function decode(value){return JSON.parse(new TextDecoder().decode(value));}
class MockEndpointMlsState {
  constructor(_tenant,_namespace,_group,device){
    this.device=device;this.epoch=null;this.ref=null;this.peer=null;
    if(device==="device-b")recipientGenerations++;
  }
  static restore(_t,_n,_g,device,_key,snapshot,epoch,ref){
    const value=decode(snapshot);
    if(value.kind!=="joined"||value.device!==device||
       value.epoch!==Number(epoch)||value.ref!==ref)
      throw Error("not a matching joined snapshot");
    const state=Object.create(this.prototype);
    Object.assign(state,{device,epoch:value.epoch,ref:value.ref,peer:value.peer});
    return state;
  }
  static restore_unpublished_group(_t,_n,_g,device,_key,snapshot){
    const value=decode(snapshot);
    if(value.kind!=="unpublished"||value.device!==device||value.epoch!==0)
      throw Error("not a matching unpublished creator snapshot");
    const state=Object.create(this.prototype);
    Object.assign(state,{device,epoch:value.epoch,ref:value.ref,peer:null});
    return state;
  }
  static restore_unjoined_key_package(_t,_n,_g,device,_key,snapshot){
    const value=decode(snapshot);
    if(value.kind!=="unjoined"||value.device!==device)
      throw Error("not a matching unjoined snapshot");
    const state=Object.create(this.prototype);
    Object.assign(state,{device,epoch:null,ref:null,peer:null});
    return state;
  }
  key_package(){return Uint8Array.of(this.device==="device-b"?2:1);}
  create_endpoint_group(){creatorGenerations++;this.epoch=0;this.ref="ref-0";}
  crypto_state_ref(){return this.ref;}
  crypto_epoch(){return BigInt(this.epoch);}
  seal_snapshot(){return encode({kind:"joined",device:this.device,epoch:this.epoch,ref:this.ref,peer:this.peer});}
  seal_unpublished_group(){
    if(this.epoch!==0||this.peer)throw Error("not an unpublished Group");
    return encode({kind:"unpublished",device:this.device,epoch:this.epoch,ref:this.ref});
  }
  seal_unjoined_key_package(){return encode({kind:"unjoined",device:this.device});}
  stage_add_device(peer,bytes){
    assert.equal(peer,"device-b");assert.equal(bytes[0],2);
    this.pendingPeer=peer;return Uint8Array.of(7);
  }
  pending_epoch(){return 1n;}
  pending_state_ref(){return "ref-1";}
  pending_welcome(){return Uint8Array.of(8);}
  merge_endpoint_transition(epoch,ref){
    assert.equal(Number(epoch),1);assert.equal(ref,"ref-1");
    this.epoch=1;this.ref=ref;this.peer=this.pendingPeer;
  }
  join_from_welcome(bytes,epoch,ref){
    assert.equal(bytes[0],8);assert.equal(Number(epoch),1);
    this.epoch=1;this.ref=ref;this.peer="device-a";
  }
  process_commit(){throw Error("unexpected mock commit");}
  authorize_direct_call_roster(peer){
    if(this.epoch!==1||this.peer!==peer)throw Error("wrong canonical MLS roster");
  }
  free(){}
}
const module={EndpointMlsState:MockEndpointMlsState};
function createEndpoint(user){
  const scope=JSON.stringify([user.tenantId,user.namespaceId,user.participantId,user.deviceId]);
  const context={
    atob:globalThis.atob,
    accountScope:scope,navigating:false,
    active:{call:{...directCall},terminating:false},
    activeCallLocator:()=>"call-hint",
    principalScope:identity=>JSON.stringify([
      identity.tenantId,identity.namespaceId,identity.participantId,identity.deviceId
    ]),
    mlsStateKey:(_user,descriptor)=>descriptor.groupId+":"+user.deviceId,
    mlsWasm:async()=>module,
    mlsSnapshot:async key=>snapshots.get(key)??null,
    mlsSave:async(key,value,first=false)=>{
      if(first&&snapshots.has(key))throw Error("duplicate initial snapshot");
      snapshots.set(key,new Uint8Array(value));
    },
    mlsWrappingKey:async()=>new Uint8Array(32).fill(7),
    navigator:{locks:{request:async(_key,_options,operation)=>operation()}},
    crypto:{randomUUID:()=>"event-1"},
    calls:{inspect:async()=>({...directCall})},
    host:{
      resumeAuthenticatedDevice:async()=>user,
      describeAcceptedCallMls:async(_binding,input)=>{
        assert.equal(input.callId,directCall.callId);
        return {
          callId:input.callId,expectedRevision:input.expectedRevision,
          deviceId:user.deviceId,groupId:"fp-mg-1",mediaCallId:"fp-m-1",
          creatorPrincipalId:"alice",peerPrincipalId:user.participantId==="alice"?"bob":"alice",
          groupRevision:canonical.revision,cryptoEpoch:canonical.epoch,
          cryptoStateRef:wrongCanonicalCreatorRef&&user.deviceId==="device-a"
            ?"wrong-epoch-zero-ref":canonical.ref,
          expectedPeerDeviceId:canonical.epoch===1
            ?(user.deviceId==="device-a"?canonical.peerDevice:"device-a"):null,
          requiresEndpointOwnedCommit:true
        };
      },
      publishEndpointMlsGroup:async(_binding,input)=>{
        assert.equal(user.participantId,"alice");
        assert.equal(input.cryptoStateRef,"ref-0");
        assert.equal(canonical.epoch,null);
        if(rejectGroupBeforeCommit){
          rejectGroupBeforeCommit=false;throw Error("HTTP 503: create not committed");
        }
        canonical.epoch=0;canonical.revision=0;canonical.ref="ref-0";
        order.push("create");
        if(rejectGroupAfterCommit){
          rejectGroupAfterCommit=false;throw Error("HTTP 503: committed create reply lost");
        }
      },
      publishEndpointMlsOffer:async(_binding,input)=>{
        assert.equal(user.participantId,"bob");
        assert.equal(canonical.epoch,0,"recipient offer requires existing canonical Group");
        const bytes=new Uint8Array(input.keyPackage);
        if(recipientPackage)assert.deepEqual([...bytes],[...recipientPackage]);
        recipientPackage=bytes;
        if(rejectFirstOffer){rejectFirstOffer=false;throw Error("HTTP 503: lost response");}
        canonical.offers=[{
          recipientDeviceId:"device-b",recipientSignerKeyId:"key-b",
          recipientKeyPackageBase64Url:"Ag",
          recipientSignatureBase64Url:"signed-by-b"
        }];
        order.push("offer");
      },
      listEndpointMlsOffers:async()=>canonical.offers,
      addEndpointMlsPeer:async(_binding,input)=>{
        assert.equal(user.participantId,"alice");
        assert.equal(input.groupRevision,0);
        assert.equal(input.recipientDeviceId,"device-b");
        assert.equal(input.commit[0],7);assert.equal(input.welcome[0],8);
        canonical.epoch=1;canonical.revision=1;canonical.ref="ref-1";
        canonical.peerDevice="device-b";order.push("commit");
      },
      fetchEndpointMlsBootstrap:async()=>{
        assert.equal(user.participantId,"bob");
        order.push("welcome");
        return {
          groupId:"fp-mg-1",cryptoEpoch:1,cryptoStateRef:"ref-1",
          welcome:Uint8Array.of(8),welcomeEpoch:1,welcomeStateRef:"ref-1",commits:[]
        };
      }
    }
  };
  runInNewContext(implementation+"\nthis.prepare=prepareFirstPartyEndpointMls;",context);
  return {context,prepare:()=>context.prepare(directCall.callId,scope,"call-hint")};
}
const alice=createEndpoint({tenantId:"tenant",namespaceId:null,participantId:"alice",deviceId:"device-a"});
const bob=createEndpoint({tenantId:"tenant",namespaceId:null,participantId:"bob",deviceId:"device-b"});
assert.equal(await bob.prepare(),false,"recipient must not offer before Group creation");
assert.equal(canonical.offers.length,0);
await assert.rejects(alice.prepare(),/create not committed/);
assert.equal(decode(snapshots.get("fp-mg-1:device-a")).kind,"unpublished");
await assert.rejects(alice.prepare(),/committed create reply lost/);
assert.equal(decode(snapshots.get("fp-mg-1:device-a")).kind,"unpublished");
wrongCanonicalCreatorRef=true;
await assert.rejects(alice.prepare(),/digest differs from local Group/);
assert.equal(decode(snapshots.get("fp-mg-1:device-a")).kind,"unpublished",
  "mismatched canonical descriptor must not promote or overwrite private state");
wrongCanonicalCreatorRef=false;
assert.equal(await alice.prepare(),false,"accepted creator snapshot must promote without new Group");
assert.equal(creatorGenerations,1,"uncertain HTTP create must not generate a second MLS Group");
assert.equal(decode(snapshots.get("fp-mg-1:device-a")).kind,"joined");
await assert.rejects(bob.prepare(),/HTTP 503/,"lost offer response must fail closed");
assert.equal(await bob.prepare(),false,"same sealed recipient KeyPackage must be retried");
assert.equal(recipientGenerations,1,"retry must not generate a second recipient KeyPackage");
assert.equal(await alice.prepare(),true,"initiator must merge and seal canonical Commit");
assert.equal(await bob.prepare(),true,"recipient must consume durable Welcome before Join");
assert.deepEqual(order,["create","offer","commit","welcome"]);
assert.equal(decode(snapshots.get("fp-mg-1:device-a")).epoch,1);
assert.equal(decode(snapshots.get("fp-mg-1:device-b")).epoch,1);
bob.context.active.terminating=true;
await assert.rejects(bob.prepare(),/Call withdrawal/);
console.log("PASS: first-party pre-Join MLS coordinator: recover uncertain epoch-zero Group publication -> same sealed KeyPackage retry -> signed Commit -> recipient Welcome -> two-device roster -> revoke fence (MOCK, NOT live media)");
