/**
 * Canonical RT0 browser media transport admission.
 *
 * Native RTP with encoded transforms is a future media implementation, NOT a
 * plaintext fallback. Never switch solely because a browser advertises
 * RTCRtpScriptTransform: SFU RTP routing, E2EE transforms on BOTH directions,
 * codec compatibility, and canonical authorization must all be confirmed.
 *
 * The existing authenticated E2EE DataChannel pipeline remains the operational
 * fallback until the canonical SFU advertises native encrypted RTP support.
 */
export type UcrBrowserMediaTransport = "native-e2ee-rtp" | "portable-e2ee-datachannel";

export interface UcrNativeRtpReadiness {
  readonly senderEncodedTransform: boolean;
  readonly receiverEncodedTransform: boolean;
  readonly workerAvailable: boolean;
  readonly sfuEncryptedRtpForwarding: boolean;
  readonly endpointMlsReady: boolean;
  readonly canonicalAuthorizationReady: boolean;
  readonly encryptedSenderInstalled: boolean;
  readonly encryptedReceiverInstalled: boolean;
}

export function ucrNativeRtpReady(value: UcrNativeRtpReadiness): boolean {
  return value.senderEncodedTransform &&
    value.receiverEncodedTransform &&
    value.workerAvailable &&
    value.sfuEncryptedRtpForwarding &&
    value.endpointMlsReady &&
    value.canonicalAuthorizationReady &&
    value.encryptedSenderInstalled &&
    value.encryptedReceiverInstalled;
}

export function chooseUcrBrowserMediaTransport(
  value: UcrNativeRtpReadiness,
  portableE2eeReady: boolean,
): UcrBrowserMediaTransport {
  if (ucrNativeRtpReady(value)) return "native-e2ee-rtp";
  if (portableE2eeReady && value.endpointMlsReady && value.canonicalAuthorizationReady) {
    return "portable-e2ee-datachannel";
  }
  throw new Error("no authorized encrypted browser media transport available");
}

/** Capability detection is only a hint, never a security/transport admission. */
export function probeUcrNativeRtpBrowserCapabilities(
  host: { RTCRtpSender?: {prototype?: object}; RTCRtpReceiver?: {prototype?: object}; Worker?: unknown },
): Pick<UcrNativeRtpReadiness, "senderEncodedTransform" | "receiverEncodedTransform" | "workerAvailable"> {
  return {
    senderEncodedTransform: !!host.RTCRtpSender?.prototype &&
      "transform" in host.RTCRtpSender.prototype,
    receiverEncodedTransform: !!host.RTCRtpReceiver?.prototype &&
      "transform" in host.RTCRtpReceiver.prototype,
    workerAvailable: typeof host.Worker === "function",
  };
}
