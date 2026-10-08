/**
 * Native WebRTC encoded-transform installation barrier.
 *
 * The signaling layer must install an authenticated sender AND receiver
 * transform before it can attach tracks. This module never performs its own
 * encryption, derives MLS secrets, or inserts plaintext fallback.
 *
 * The actual transform worker and canonical Rust MLS/SFrame implementation
 * MUST be supplied by the endpoint owner. A missing transform aborts setup.
 */
export interface UcrEncodedTransformWorker {
  readonly worker: Worker;
  readonly verifiedCallId: string;
  readonly verifiedGroupId: string;
  readonly verifiedEpoch: bigint;
  readonly senderReady: boolean;
  readonly receiverReady: boolean;
}

export interface UcrNativeTransformBinding {
  readonly callId: string;
  readonly groupId: string;
  readonly cryptoEpoch: bigint;
}

export interface UcrTransformCapableEndpoint {
  transform: unknown;
}

export type UcrTransformCreator = (
  worker: Worker, direction: "encrypt" | "decrypt",
  binding: UcrNativeTransformBinding,
) => unknown;

/**
 * All required transform objects must be constructed before either endpoint
 * is modified. On partial install, fail closed: caller must dispose the peer
 * connection instead of transmitting a track with incomplete E2EE.
 */
export function installUcrNativeEncryptedTransforms(
  sender: UcrTransformCapableEndpoint,
  receiver: UcrTransformCapableEndpoint,
  authenticated: UcrEncodedTransformWorker,
  binding: UcrNativeTransformBinding,
  create: UcrTransformCreator,
  isAuthorized: (binding: UcrNativeTransformBinding) => boolean,
  closePeerOnFailure: () => void,
): void {
  if (!isAuthorized(binding) || !binding.callId || !binding.groupId || binding.cryptoEpoch < 0n ||
      authenticated.verifiedCallId !== binding.callId ||
      authenticated.verifiedGroupId !== binding.groupId ||
      authenticated.verifiedEpoch !== binding.cryptoEpoch ||
      !authenticated.senderReady || !authenticated.receiverReady) {
    throw new Error("canonical MLS/SFrame endpoint transform not ready");
  }
  if (!("transform" in sender) || !("transform" in receiver) ||
      sender.transform != null || receiver.transform != null) {
    throw new Error("native RTP transforms unavailable or already installed");
  }
  const encrypt = create(authenticated.worker, "encrypt", binding);
  const decrypt = create(authenticated.worker, "decrypt", binding);
  if (!encrypt || !decrypt || encrypt === decrypt) {
    throw new Error("distinct authenticated sender/receiver transforms required");
  }
  try {
    sender.transform = encrypt;
    receiver.transform = decrypt;
  } catch (error) {
    // A partially installed transform MUST NOT be used for media transport.
    // Immediately close the peer to prevent any unprotected sender from running.
    closePeerOnFailure();
    throw new Error("native E2EE transform installation failed; peer closed", {cause: error});
  }
}
