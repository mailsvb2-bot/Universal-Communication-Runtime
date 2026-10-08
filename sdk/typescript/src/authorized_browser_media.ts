import {
  createUcrBrowserEndpointMediaAdapter,
  type UcrBrowserEndpointMediaOptions,
} from "./browser_endpoint_media.ts";
import {
  installUcrEndpointE2eeAdapter,
  type UcrEndpointE2eeAdapterV1,
} from "./endpoint_e2ee.ts";

/**
 * Browser integration: canonical control plane owns admission, trusted keys,
 * current membership and negotiated crypto epoch. The endpoint owns MLS keys.
 * No extra auth RPC per media frame; the supplied authorization callback must
 * use canonical locally validated state and fail closed upon revocation.
 */
export interface UcrAuthorizedMediaBootstrap {
  readonly state: unknown;
  readonly claims: Readonly<{
    tenantId: string;
    namespaceId: string | null;
    callId: string;
    deviceId: string;
    participantId: string;
    participantKind: string;
    sessionId: string;
  }>;
  readonly groupId: string;
  readonly loadWasm: () => Promise<unknown>;
}

export type UcrAuthorizedMediaFactory = (
  bootstrap: UcrAuthorizedMediaBootstrap,
) => UcrBrowserEndpointMediaOptions | Promise<UcrBrowserEndpointMediaOptions>;

export function createUcrAuthorizedMediaInstaller(
  target: Record<string, unknown>,
  factory: UcrAuthorizedMediaFactory,
): (bootstrap: UcrAuthorizedMediaBootstrap) => Promise<UcrEndpointE2eeAdapterV1> {
  return async (bootstrap) => {
    if (!bootstrap.state || !bootstrap.claims?.deviceId || !bootstrap.groupId) {
      throw new Error("canonical device-bound MLS admission required");
    }
    const options = await factory(bootstrap);
    if (!options?.binding || !options.bridge || !options.trustedKeys ||
        typeof options.authorizeFrame !== "function") {
      throw new Error("current canonical call authority and endpoint crypto required");
    }
    if (options.binding.callId !== bootstrap.claims.callId ||
        options.binding.groupId !== bootstrap.groupId ||
        options.binding.tenantId !== bootstrap.claims.tenantId ||
        options.binding.namespaceId !== bootstrap.claims.namespaceId) {
      throw new Error("media bridge binding differs from authorized browser session");
    }
    const adapter = createUcrBrowserEndpointMediaAdapter(options);
    installUcrEndpointE2eeAdapter(target, adapter);
    return adapter;
  };
}
