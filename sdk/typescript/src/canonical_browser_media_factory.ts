import type {
  UcrAuthorizedMediaBootstrap,
  UcrAuthorizedMediaFactory,
} from "./authorized_browser_media.ts";
import type {
  UcrBrowserEndpointMediaOptions,
} from "./browser_endpoint_media.ts";
import type {
  UcrTrustedSourceKeys,
  UcrEncodedMediaFrame,
  UcrGroupMediaCryptoBridge,
} from "./portable_endpoint_media.ts";
import type { SfuForwardEnvelopeWire } from "./sfu_forward_wire.ts";

type Header = SfuForwardEnvelopeWire["frame"]["header"];
type Binding = UcrBrowserEndpointMediaOptions["binding"];

/** One snapshot from the *existing* canonical Call/Group/Device identity owner.
 * NOT a second browser trust directory or an unsigned, SFU-provided roster.
 */
export interface UcrCanonicalBrowserMediaAdmission {
  readonly sessionId: string;
  readonly deviceId: string;
  readonly participantId: string;
  readonly principalKindCode: number;
  readonly binding: Binding;
  /** Non-empty and equal to the current trusted device key ID. */
  readonly signingKeyId: string;
  /** Endpoint-private seed provisioned for the verified Device, NOT server MLS material. */
  readonly signingSeed: Uint8Array;
  /** The active trusted-key descriptor must match the signer's actual public key. */
  readonly trustedLocalVerifyingKey: Uint8Array;
  readonly trustedKeys: UcrTrustedSourceKeys;
  readonly audioContext: AudioContext;
  readonly remoteVideoCanvas?: HTMLCanvasElement | OffscreenCanvas;
  readonly enableCameraLayerPair?: boolean;
  readonly measureReceiveTelemetry?: UcrBrowserEndpointMediaOptions["measureReceiveTelemetry"];
  /** Synchronous and fail-closed on heartbeat, device revocation, leave and MLS rekey. */
  isCurrent(): boolean;
  authorizeFrame(header: Header): boolean | Promise<boolean>;
  authorizePublish(frame: UcrEncodedMediaFrame): boolean | Promise<boolean>;
}

/** Must fetch a fully authorized, current snapshot from the integration's
 * canonical device/identity store. The SDK cannot mint identities or trust keys.
 */
export type UcrCanonicalMediaAdmissionResolver = (
  bootstrap: UcrAuthorizedMediaBootstrap,
) => UcrCanonicalBrowserMediaAdmission | Promise<UcrCanonicalBrowserMediaAdmission>;

function expectedPrincipalKind(value: string | number): number {
  const kinds: Record<string, number> = {
    person: 1, device: 2, service_account: 3, ai_agent: 4,
    bot: 5, organization: 6, automation: 7, external_platform: 8,
  };
  const code = typeof value === "number" ? value : kinds[value];
  if (!Number.isInteger(code) || !code || code < 1 || code > 8) {
    throw new Error("canonical media principal kind unavailable");
  }
  return code;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Construct the actual WASM -> WebCodecs composition from canonical authority.
 * The MLS exporter never traverses JavaScript or an HTTP response.
 */
export function createUcrCanonicalBrowserMediaFactory(
  resolve: UcrCanonicalMediaAdmissionResolver,
): UcrAuthorizedMediaFactory {
  return async (bootstrap): Promise<UcrBrowserEndpointMediaOptions> => {
    if (typeof resolve !== "function" || !bootstrap.state ||
        typeof (bootstrap.state as {media_bridge?: unknown}).media_bridge !== "function") {
      throw new Error("endpoint-owned MLS media bridge unavailable");
    }
    const admission = await resolve(bootstrap);
    const expectedKind = expectedPrincipalKind(bootstrap.claims.participantKind);
    const binding = admission?.binding;
    const seed = admission?.signingSeed;
    const trustedKey = admission?.trustedLocalVerifyingKey;
    if (!admission || admission.sessionId !== bootstrap.claims.sessionId ||
        admission.deviceId !== bootstrap.claims.deviceId ||
        admission.participantId !== bootstrap.claims.participantId ||
        admission.principalKindCode !== expectedKind ||
        binding?.tenantId !== bootstrap.claims.tenantId ||
        binding?.namespaceId !== bootstrap.claims.namespaceId ||
        binding?.callId !== bootstrap.claims.callId ||
        binding?.groupId !== bootstrap.groupId ||
        !binding?.negotiationRef ||
        typeof binding.negotiationGeneration !== "bigint" ||
        typeof binding.cryptoEpoch !== "bigint" ||
        !admission.signingKeyId ||
        !(seed instanceof Uint8Array) || seed.length !== 32 ||
        !(trustedKey instanceof Uint8Array) || trustedKey.length !== 32 ||
        typeof admission.isCurrent !== "function" || !admission.isCurrent() ||
        typeof admission.authorizeFrame !== "function" ||
        typeof admission.authorizePublish !== "function" ||
        typeof admission.trustedKeys?.resolve !== "function" ||
        !admission.audioContext) {
      throw new Error("canonical device signing, media binding or authorization incomplete");
    }
    const epoch = (bootstrap.state as {crypto_epoch(): bigint}).crypto_epoch();
    if (BigInt(epoch) !== binding.cryptoEpoch) {
      throw new Error("endpoint MLS epoch differs from canonical media binding");
    }
    // Rust owns MLS and derives the media exporter internally; copy and erase
    // only our temporary seed buffer, never mutate the device's key vault.
    const seedCopy = seed.slice();
    let bridge: UcrGroupMediaCryptoBridge;
    try {
      bridge = (bootstrap.state as {
        media_bridge(...args: unknown[]): UcrGroupMediaCryptoBridge;
      }).media_bridge(
        bootstrap.claims.callId,
        binding.negotiationRef,
        binding.negotiationGeneration,
        bootstrap.claims.participantId,
        expectedKind,
        admission.signingKeyId,
        seedCopy,
      );
    } finally {
      seedCopy.fill(0);
    }
    try {
      const publicKey = (bridge as UcrGroupMediaCryptoBridge & {
        local_verifying_key(): Uint8Array;
      }).local_verifying_key();
      if (!(publicKey instanceof Uint8Array) || !equalBytes(publicKey, trustedKey)) {
        throw new Error("endpoint signer differs from active trusted device key");
      }
      if (!admission.isCurrent()) {
        throw new Error("canonical media authorization revoked during bridge initialization");
      }
      return {
        bridge,
        binding,
        trustedKeys: {
          resolve: async (header, keyId) => {
            if (!admission.isCurrent()) throw new Error("device media authorization revoked");
            const key = await admission.trustedKeys.resolve(header, keyId);
            // The canonical descriptor may be fetched asynchronously. Do not
            // decrypt a frame if the device or MLS epoch was retired meanwhile.
            if (!admission.isCurrent()) throw new Error("device media authorization revoked");
            return key;
          },
        },
        authorizeFrame: async (header) =>
          admission.isCurrent() && await admission.authorizeFrame(header) &&
          admission.isCurrent(),
        authorizePublish: async (frame) =>
          admission.isCurrent() && await admission.authorizePublish(frame) &&
          admission.isCurrent(),
        audioContext: admission.audioContext,
        remoteVideoCanvas: admission.remoteVideoCanvas,
        enableCameraLayerPair: admission.enableCameraLayerPair,
        measureReceiveTelemetry: admission.measureReceiveTelemetry,
      };
    } catch (error) {
      bridge.revoke();
      throw error;
    }
  };
}
