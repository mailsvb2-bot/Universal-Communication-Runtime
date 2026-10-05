export const UCR_ENDPOINT_E2EE_CONTRACT_VERSION = "ucr.endpoint-e2ee.v1" as const;

export interface UcrEndpointMediaSources {
  readonly stream: MediaStream;
  readonly cameraStream: MediaStream;
  readonly screenStream?: MediaStream | null;
}

export interface UcrEndpointE2eeStartInput extends UcrEndpointMediaSources {
  readonly sendEnvelope: (wireEnvelope: Uint8Array) => void;
}

export interface UcrEndpointE2eePersistenceV1 {
  restoreSealedState(snapshot: Uint8Array): boolean | void | Promise<boolean | void>;
  sealState(): Uint8Array | null | Promise<Uint8Array | null>;
}

export interface UcrEndpointE2eeAdapterV1 {
  readonly contractVersion: typeof UCR_ENDPOINT_E2EE_CONTRACT_VERSION;
  start(input: UcrEndpointE2eeStartInput): void | Promise<void>;
  onEnvelope(wireEnvelope: Uint8Array): void | Promise<void>;
  stop(): void | Promise<void>;
  updateSources?(sources: UcrEndpointMediaSources): void | Promise<void>;
  readonly persistence?: UcrEndpointE2eePersistenceV1;
}

export interface LegacyUcrEndpointE2eeAdapter {
  readonly contractVersion?: undefined;
  start(input: UcrEndpointE2eeStartInput): void | Promise<void>;
  onEnvelope(wireEnvelope: Uint8Array): void | Promise<void>;
  stop?(): void | Promise<void>;
  updateSources?(sources: UcrEndpointMediaSources): void | Promise<void>;
}

export type CompatibleUcrEndpointE2eeAdapter =
  | UcrEndpointE2eeAdapterV1
  | LegacyUcrEndpointE2eeAdapter;

export interface ResolvedUcrEndpointE2eeAdapter {
  readonly adapter: CompatibleUcrEndpointE2eeAdapter;
  readonly legacy: boolean;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

export function resolveUcrEndpointE2eeAdapter(
  value: unknown,
  options: { readonly allowLegacy?: boolean } = {},
): ResolvedUcrEndpointE2eeAdapter {
  if (!isObject(value)) {
    throw new Error("UCR endpoint E2EE adapter must be an object");
  }

  if (typeof value.start !== "function" || typeof value.onEnvelope !== "function") {
    throw new Error("UCR endpoint E2EE adapter requires start and onEnvelope hooks");
  }

  const version = value.contractVersion;
  if (version === UCR_ENDPOINT_E2EE_CONTRACT_VERSION) {
    if (typeof value.stop !== "function") {
      throw new Error("ucr.endpoint-e2ee.v1 requires a stop hook");
    }
    if (value.persistence !== undefined) {
      if (
        !isObject(value.persistence) ||
        typeof value.persistence.restoreSealedState !== "function" ||
        typeof value.persistence.sealState !== "function"
      ) {
        throw new Error(
          "ucr.endpoint-e2ee.v1 persistence requires restoreSealedState and sealState hooks",
        );
      }
    }
    return {
      adapter: value as unknown as UcrEndpointE2eeAdapterV1,
      legacy: false,
    };
  }

  if (version !== undefined) {
    throw new Error("unsupported UCR endpoint E2EE adapter contract version");
  }

  if (options.allowLegacy === false) {
    throw new Error("legacy UCR endpoint E2EE adapter is not allowed");
  }

  if (value.stop !== undefined && typeof value.stop !== "function") {
    throw new Error("legacy UCR endpoint E2EE stop hook must be a function");
  }

  return {
    adapter: value as unknown as LegacyUcrEndpointE2eeAdapter,
    legacy: true,
  };
}

export function installUcrEndpointE2eeAdapter(
  target: Record<string, unknown>,
  adapter: UcrEndpointE2eeAdapterV1,
): void {
  resolveUcrEndpointE2eeAdapter(adapter, { allowLegacy: false });
  const existing = target.ucrE2eeEndpoint;
  if (existing !== undefined && existing !== adapter) {
    throw new Error("UCR endpoint E2EE adapter is already installed");
  }
  target.ucrE2eeEndpoint = adapter;
}
