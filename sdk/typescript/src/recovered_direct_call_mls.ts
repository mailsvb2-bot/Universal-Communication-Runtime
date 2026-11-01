import type { UcrAuthenticatedFirstEntry, UcrCanonicalJoinIssuance } from "./canonical_first_party_call_entry.ts";
import type { UcrDirectCall } from "./contact_call_journey.ts";
import type { UcrManagedFirstPartyHost, UcrEndpointMlsCallDescriptor } from "./first_party_browser_http.ts";

/**
 * Endpoint-only MLS operations. Every method runs on its respective Device;
 * the service receives only public epoch references, KeyPackages, Commit and
 * Welcome bytes. Implementations must use protected independent MLS stores.
 */
export interface UcrRecoveredCallEndpoint {
  createGroup(groupId: string): Promise<{cryptoStateRef:string}>;
  createKeyPackage(groupId: string): Promise<Uint8Array>;
  addPeer(groupId: string, signedPackage: Uint8Array): Promise<{
    commit:Uint8Array; welcome:Uint8Array; cryptoEpoch:number; cryptoStateRef:string;
  }>;
  applyWelcome(groupId: string, welcome: Uint8Array,
    commits: readonly {commit:Uint8Array;cryptoEpoch:number;cryptoStateRef:string}[]
  ): Promise<{cryptoEpoch:number;cryptoStateRef:string}>;
  /** Reject any roster containing the former server host or an unexpected Device. */
  verifyRoster(groupId:string, ownDeviceId:string, peerDeviceId:string): Promise<boolean>;
}
export interface UcrRecoveredCallPeer {
  readonly host: UcrManagedFirstPartyHost;
  readonly endpoint: UcrRecoveredCallEndpoint;
  readonly auth: UcrAuthenticatedFirstEntry;
}

/**
 * Run only after a NEW Call is accepted by both Devices. This orchestration
 * must be invoked by each authenticated endpoint's owning client (a trusted
 * local coordinator in integration tests); never deploy it as a server task.
 * The caller already restarted the compromised Call using a fresh Call ID.
 */
export async function establishRecoveredDirectCall(
  oldCallId:string,
  call:UcrDirectCall,
  initiator:UcrRecoveredCallPeer,
  recipient:UcrRecoveredCallPeer,
):Promise<{
  groupId:string; mediaCallId:string;
  callerJoin:UcrCanonicalJoinIssuance; recipientJoin:UcrCanonicalJoinIssuance;
}> {
  if (call.callId === oldCallId || call.state !== "active" ||
      call.callerIdentityId !== initiator.auth.participantId ||
      call.calleeIdentityId !== recipient.auth.participantId ||
      initiator.auth.deviceId === recipient.auth.deviceId ||
      initiator.auth.tenantId !== recipient.auth.tenantId ||
      initiator.auth.namespaceId !== recipient.auth.namespaceId) {
    throw new Error("recovery requires independent accepted Call and two authenticated Devices");
  }
  const ctx={callId:call.callId,expectedRevision:call.revision};
  const [caller,callee]=await Promise.all([
    initiator.host.describeAcceptedCallMls(initiator.auth,ctx),
    recipient.host.describeAcceptedCallMls(recipient.auth,ctx),
  ]);
  const same=(a:UcrEndpointMlsCallDescriptor,b:UcrEndpointMlsCallDescriptor)=>
    a.callId===b.callId && a.groupId===b.groupId &&
    a.mediaCallId===b.mediaCallId && a.conversationId===b.conversationId;
  if (!same(caller,callee) || caller.callId!==call.callId ||
      !caller.groupId.startsWith("fp-mg-") ||
      caller.creatorPrincipalId!==initiator.auth.participantId ||
      caller.peerPrincipalId!==recipient.auth.participantId ||
      callee.creatorPrincipalId!==caller.creatorPrincipalId ||
      caller.cryptoEpoch!==null || callee.cryptoEpoch!==null) {
    throw new Error("recovery MLS descriptor is not fresh and Call-bound");
  }
  const created=await initiator.endpoint.createGroup(caller.groupId);
  if (!created.cryptoStateRef) throw new Error("endpoint MLS creation failed");
  await initiator.host.publishEndpointMlsGroup(initiator.auth,{
    ...ctx,cryptoStateRef:created.cryptoStateRef,
  });
  const packageBytes=await recipient.endpoint.createKeyPackage(caller.groupId);
  await recipient.host.publishEndpointMlsOffer(recipient.auth,{...ctx,keyPackage:packageBytes});
  const offers=await initiator.host.listEndpointMlsOffers(initiator.auth,ctx);
  const offer=offers.find(x=>x.recipientDeviceId===recipient.auth.deviceId);
  if (!offer || offers.filter(x=>x.recipientDeviceId===recipient.auth.deviceId).length!==1) {
    throw new Error("missing unique authenticated recipient MLS offer");
  }
  // Decode using the platform-independent Base64URL decoder supplied by the
  // endpoint runtime (not an unauthenticated browser Join fragment).
  const decode=(value:string):Uint8Array=>{
    const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    if (!value || /[^A-Za-z0-9_-]/.test(value)) throw new Error("invalid KeyPackage wire");
    let carry=0,bits=0; const out:number[]=[];
    for(const ch of value){carry=(carry<<6)|alphabet.indexOf(ch);bits+=6;
      if(bits>=8){bits-=8;out.push((carry>>bits)&255);}}
    if(bits>0 && (carry&((1<<bits)-1))!==0) throw new Error("noncanonical KeyPackage");
    return Uint8Array.from(out);
  };
  const staged=await initiator.endpoint.addPeer(caller.groupId,decode(offer.recipientKeyPackageBase64Url));
  const updated=await initiator.host.describeAcceptedCallMls(initiator.auth,ctx);
  if (!same(caller,updated) || updated.groupRevision===null ||
      updated.cryptoEpoch!==0 || staged.cryptoEpoch!==1) {
    throw new Error("fresh MLS epoch/revision is not ready for endpoint Commit");
  }
  await initiator.host.addEndpointMlsPeer(initiator.auth,{
    ...ctx,groupRevision:updated.groupRevision,
    eventId:"recover-"+call.callId,cryptoEpoch:staged.cryptoEpoch,
    cryptoStateRef:staged.cryptoStateRef,
    recipientDeviceId:offer.recipientDeviceId,
    recipientSignerKeyId:offer.recipientSignerKeyId,
    recipientKeyPackageBase64Url:offer.recipientKeyPackageBase64Url,
    recipientSignatureBase64Url:offer.recipientSignatureBase64Url,
    commit:staged.commit,welcome:staged.welcome,
  });
  const bootstrap=await recipient.host.fetchEndpointMlsBootstrap(recipient.auth,ctx);
  if (bootstrap.groupId!==caller.groupId || bootstrap.cryptoEpoch!==staged.cryptoEpoch ||
      bootstrap.cryptoStateRef!==staged.cryptoStateRef) {
    throw new Error("recipient MLS bootstrap does not match endpoint Commit");
  }
  const recovered=await recipient.endpoint.applyWelcome(caller.groupId,bootstrap.welcome,bootstrap.commits);
  if (recovered.cryptoEpoch!==staged.cryptoEpoch ||
      recovered.cryptoStateRef!==staged.cryptoStateRef ||
      !(await initiator.endpoint.verifyRoster(caller.groupId,initiator.auth.deviceId,recipient.auth.deviceId)) ||
      !(await recipient.endpoint.verifyRoster(caller.groupId,recipient.auth.deviceId,initiator.auth.deviceId))) {
    throw new Error("endpoint-only MLS recovery roster or epoch verification failed");
  }
  // Server-issued Join follows completed endpoint MLS exchange, never precedes it.
  const [callerJoin,recipientJoin]=await Promise.all([
    initiator.host.issueSignedJoinForAcceptedCall(initiator.auth,ctx),
    recipient.host.issueSignedJoinForAcceptedCall(recipient.auth,ctx),
  ]);
  if (callerJoin.callId!==call.callId || recipientJoin.callId!==call.callId ||
      callerJoin.deviceId!==initiator.auth.deviceId ||
      recipientJoin.deviceId!==recipient.auth.deviceId) {
    throw new Error("recovered Call Join grant not bound to endpoint Device");
  }
  return {groupId:caller.groupId,mediaCallId:caller.mediaCallId,callerJoin,recipientJoin};
}
