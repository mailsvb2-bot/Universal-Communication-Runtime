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
    participantKind: string | number;
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
  let installationInProgress = false;
  return async (bootstrap) => {
    if (installationInProgress || target.ucrE2eeEndpoint != null) {
      throw new Error("authorized media endpoint installation already active");
    }
    installationInProgress = true;
    let options: UcrBrowserEndpointMediaOptions | null = null;
    let adapter: UcrEndpointE2eeAdapterV1 | null = null;
    try {
      if (!bootstrap.state || !bootstrap.claims?.deviceId || !bootstrap.groupId) {
        throw new Error("canonical device-bound MLS admission required");
      }
      options = await factory(bootstrap);
      if (!options?.binding || !options.bridge || !options.trustedKeys ||
          typeof options.authorizeFrame !== "function" ||
          typeof options.authorizePublish !== "function") {
        throw new Error("current canonical call authority and endpoint crypto required");
      }
      if (options.binding.callId !== bootstrap.claims.callId ||
          options.binding.groupId !== bootstrap.groupId ||
          options.binding.tenantId !== bootstrap.claims.tenantId ||
          options.binding.namespaceId !== bootstrap.claims.namespaceId) {
        throw new Error("media bridge binding differs from authorized browser session");
      }
      if (target.ucrE2eeEndpoint != null) {
        throw new Error("authorized media endpoint installed during asynchronous setup");
      }
      adapter = createUcrBrowserEndpointMediaAdapter(options);
      installUcrEndpointE2eeAdapter(target, adapter);
      return adapter;
    } catch (error) {
      // The factory may already have created an epoch signer before later
      // binding checks, browser codec checks or a competing install fail.
      // ALWAYS retire it, including failure before the adapter was created.
      try {
        if (adapter) await adapter.stop();
        else options?.bridge?.revoke();
      } catch (_) { /* primary authentication/setup error is authoritative */ }
      throw error;
    } finally {
      installationInProgress = false;
    }
  };
}
