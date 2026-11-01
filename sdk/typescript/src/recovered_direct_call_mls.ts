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
      caller.expectedRevision!==call.revision || callee.expectedRevision!==call.revision ||
      caller.deviceId!==initiator.auth.deviceId || callee.deviceId!==recipient.auth.deviceId ||
      caller.cryptoCapability!=="ucr.group.mls" || callee.cryptoCapability!=="ucr.group.mls" ||
      caller.requiresEndpointOwnedCommit!==true || callee.requiresEndpointOwnedCommit!==true ||
      !caller.groupId.startsWith("fp-mg-") ||
      caller.creatorPrincipalId!==initiator.auth.participantId ||
      caller.peerPrincipalId!==recipient.auth.participantId ||
      callee.creatorPrincipalId!==caller.creatorPrincipalId ||
      callee.peerPrincipalId!==initiator.auth.participantId ||
      caller.groupRevision!==null || callee.groupRevision!==null ||
      caller.expectedPeerDeviceId!==null || callee.expectedPeerDeviceId!==null ||
      caller.cryptoStateRef!==null || callee.cryptoStateRef!==null ||
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
    if (!value || value.length%4===1 || /[^A-Za-z0-9_-]/.test(value)) {
      throw new Error("invalid KeyPackage wire");
    }
    let carry=0,bits=0; const out:number[]=[];
    for(const ch of value){carry=(carry<<6)|alphabet.indexOf(ch);bits+=6;
      if(bits>=8){bits-=8;out.push((carry>>bits)&255);}}
    if(bits>0 && (carry&((1<<bits)-1))!==0) throw new Error("noncanonical KeyPackage");
    if(out.length===0) throw new Error("empty KeyPackage wire");
    return Uint8Array.from(out);
  };
  // A signed offer for the correct Device can still be stale. Commit must
  // target the exact public KeyPackage whose private provider this recipient
  // sealed for this recovery attempt; otherwise the accepted MLS epoch can
  // strand the recipient with an undecryptable Welcome.
  const offeredPackage=decode(offer.recipientKeyPackageBase64Url);
  if (offeredPackage.length!==packageBytes.length ||
      !offeredPackage.every((value,index)=>value===packageBytes[index])) {
    throw new Error("recipient MLS KeyPackage changed between publish and Commit");
  }
  const staged=await initiator.endpoint.addPeer(caller.groupId,offeredPackage);
  const updated=await initiator.host.describeAcceptedCallMls(initiator.auth,ctx);
  if (!same(caller,updated) || updated.deviceId!==initiator.auth.deviceId ||
      updated.expectedRevision!==call.revision || updated.groupRevision===null ||
      updated.expectedPeerDeviceId!==null ||
      updated.cryptoEpoch!==0 || updated.cryptoStateRef!==created.cryptoStateRef ||
      staged.cryptoEpoch!==1) {
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
      bootstrap.cryptoStateRef!==staged.cryptoStateRef ||
      bootstrap.welcomeEpoch!==staged.cryptoEpoch ||
      bootstrap.welcomeStateRef!==staged.cryptoStateRef) {
    throw new Error("recipient MLS bootstrap does not match endpoint Commit");
  }
  const recovered=await recipient.endpoint.applyWelcome(caller.groupId,bootstrap.welcome,bootstrap.commits);
  if (recovered.cryptoEpoch!==staged.cryptoEpoch ||
      recovered.cryptoStateRef!==staged.cryptoStateRef ||
      !(await initiator.endpoint.verifyRoster(caller.groupId,initiator.auth.deviceId,recipient.auth.deviceId)) ||
      !(await recipient.endpoint.verifyRoster(caller.groupId,recipient.auth.deviceId,initiator.auth.deviceId))) {
    throw new Error("endpoint-only MLS recovery roster or epoch verification failed");
  }
  // Re-read BOTH canonical Group views after Commit/Welcome. A valid local
  // roster alone is insufficient: the Call owner must bind the same committed
  // epoch to the exact two authenticated Devices before issuing either Join.
  const [committedCaller,committedRecipient]=await Promise.all([
    initiator.host.describeAcceptedCallMls(initiator.auth,ctx),
    recipient.host.describeAcceptedCallMls(recipient.auth,ctx),
  ]);
  if (!same(caller,committedCaller) || !same(caller,committedRecipient) ||
      committedCaller.deviceId!==initiator.auth.deviceId ||
      committedRecipient.deviceId!==recipient.auth.deviceId ||
      committedCaller.expectedRevision!==call.revision ||
      committedRecipient.expectedRevision!==call.revision ||
      committedCaller.expectedPeerDeviceId!==recipient.auth.deviceId ||
      committedRecipient.expectedPeerDeviceId!==initiator.auth.deviceId ||
      committedCaller.cryptoEpoch!==staged.cryptoEpoch ||
      committedRecipient.cryptoEpoch!==staged.cryptoEpoch ||
      committedCaller.cryptoStateRef!==staged.cryptoStateRef ||
      committedRecipient.cryptoStateRef!==staged.cryptoStateRef ||
      committedCaller.groupRevision===null || committedRecipient.groupRevision===null) {
    throw new Error("canonical committed MLS peer Device or epoch mismatch");
  }
  // Server-issued Join follows completed endpoint MLS exchange, never precedes it.
  const [callerJoin,recipientJoin]=await Promise.all([
    initiator.host.issueSignedJoinForAcceptedCall(initiator.auth,ctx),
    recipient.host.issueSignedJoinForAcceptedCall(recipient.auth,ctx),
  ]);
  const boundJoin=(join:UcrCanonicalJoinIssuance,auth:UcrAuthenticatedFirstEntry)=>
    join.tenantId===auth.tenantId && join.namespaceId===auth.namespaceId &&
    join.participantId===auth.participantId && join.deviceId===auth.deviceId &&
    join.callId===call.callId &&
    typeof join.sessionId==="string" &&
    /^[A-Za-z0-9_.:@-]{1,128}$/.test(join.sessionId) &&
    typeof join.joinFragment==="string" &&
    join.joinFragment.startsWith("#ucr_join=") &&
    join.joinFragment.length>"#ucr_join=".length && join.joinFragment.length<=16384;
  if (!boundJoin(callerJoin,initiator.auth) || !boundJoin(recipientJoin,recipient.auth) ||
      callerJoin.sessionId===recipientJoin.sessionId) {
    throw new Error("recovered Call Join grant not bound to authenticated endpoint Identity/Device");
  }
  return {groupId:caller.groupId,mediaCallId:caller.mediaCallId,callerJoin,recipientJoin};
}
