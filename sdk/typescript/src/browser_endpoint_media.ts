import type { UcrEndpointE2eeAdapterV1 } from "./endpoint_e2ee.ts";
import {
  createUcrPortableEndpointMediaAdapter,
  type UcrGroupMediaCryptoBridge,
  type UcrTrustedSourceKeys,
  type UcrEndpointPipelineOptions,
} from "./portable_endpoint_media.ts";
import {
  UcrBrowserWebCodecsConsumer,
  UcrBrowserWebCodecsProducer,
  ucrWebCodecsSupported,
} from "./browser_webcodecs_media.ts";

/**
 * Browser composition boundary. Caller MUST supply an MLS-derived Rust/WASM
 * endpoint bridge and a canonical trusted-key resolver after authorized join.
 * This factory never creates shared secrets, hardcodes verification keys,
 * disables signatures, or falls back to plaintext.
 *
 * Native apps can use the portable adapter directly with their own codecs.
 */
export interface UcrBrowserEndpointMediaOptions {
  readonly bridge: UcrGroupMediaCryptoBridge;
  readonly trustedKeys: UcrTrustedSourceKeys;
  readonly binding: NonNullable<UcrEndpointPipelineOptions["binding"]>;
  readonly authorizeFrame: NonNullable<UcrEndpointPipelineOptions["authorizeFrame"]>;
  readonly authorizePublish: NonNullable<UcrEndpointPipelineOptions["authorizePublish"]>;
  /** Use this renderer for custom UIs. The reference UCR browser resolves its own E2EE canvas. */
  readonly remoteVideoCanvas?: HTMLCanvasElement | OffscreenCanvas;
  readonly audioContext: AudioContext;
  readonly maxPendingFrames?: number;
  readonly onError?: (error: unknown) => void;
  /** Optional real downlink/network/device probe. Must report every required field
   * from measured or authoritative device state. No synthetic battery/CPU defaults.
   */
  readonly measureReceiveTelemetry?: UcrEndpointPipelineOptions["measureReceiveTelemetry"];
  /** Opt-in two encoded camera streams (actual Full HD source + 360p/12 low).
   * Only enable when the canonical Conference can select exact encrypted layer IDs.
   * Disabled by default to avoid a second encoder on phones.
   */
  readonly enableCameraLayerPair?: boolean;
}

export function createUcrBrowserEndpointMediaAdapter(
  options: UcrBrowserEndpointMediaOptions,
): UcrEndpointE2eeAdapterV1 {
  if (!ucrWebCodecsSupported()) {
    throw new Error(
      "WebCodecs audio/video capture and playback unavailable; install a supported platform codec adapter",
    );
  }
  if (!options.bridge || !options.trustedKeys ||
      typeof options.bridge.seal_wire !== "function" ||
      typeof options.bridge.open_wire !== "function" ||
      typeof options.trustedKeys.resolve !== "function" ||
      !options.binding || typeof options.authorizeFrame !== "function" ||
      typeof options.authorizePublish !== "function") {
    throw new Error("authenticated MLS endpoint bridge and trusted identity resolver required");
  }
  const onError = options.onError ?? (() => {});
  const referenceCanvas = typeof document !== "undefined" ?
    document.getElementById("remote-e2ee-canvas") : null;
  const remoteVideoCanvas = options.remoteVideoCanvas ??
    (referenceCanvas instanceof HTMLCanvasElement ? referenceCanvas : null);
  if (!remoteVideoCanvas) {
    throw new Error("authenticated endpoint-only video canvas required for decoder rendering");
  }
  return createUcrPortableEndpointMediaAdapter({
    bridge: options.bridge,
    producer: new UcrBrowserWebCodecsProducer(
      onError, options.enableCameraLayerPair === true,
    ),
    consumer: new UcrBrowserWebCodecsConsumer({
      videoCanvas: remoteVideoCanvas,
      audioContext: options.audioContext,
      onError,
    }),
    trustedKeys: options.trustedKeys,
    binding: options.binding,
    authorizeFrame: options.authorizeFrame,
    authorizePublish: options.authorizePublish,
    maxPendingFrames: options.maxPendingFrames,
    measureReceiveTelemetry: options.measureReceiveTelemetry,
    onError,
  });
}
