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
  readonly remoteVideoCanvas: HTMLCanvasElement | OffscreenCanvas;
  readonly audioContext: AudioContext;
  readonly maxPendingFrames?: number;
  readonly onError?: (error: unknown) => void;
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
      !options.binding || typeof options.authorizeFrame !== "function") {
    throw new Error("authenticated MLS endpoint bridge and trusted identity resolver required");
  }
  const onError = options.onError ?? (() => {});
  return createUcrPortableEndpointMediaAdapter({
    bridge: options.bridge,
    producer: new UcrBrowserWebCodecsProducer(onError),
    consumer: new UcrBrowserWebCodecsConsumer({
      videoCanvas: options.remoteVideoCanvas,
      audioContext: options.audioContext,
      onError,
    }),
    trustedKeys: options.trustedKeys,
    binding: options.binding,
    authorizeFrame: options.authorizeFrame,
    maxPendingFrames: options.maxPendingFrames,
    onError,
  });
}
