/**
 * Security/privacy controls for endpoint WebRTC setup.
 *
 * These settings minimize network exposure but do not anonymize users from
 * their own TURN relay, signaling provider or identity authority.
 * RTP/ICE policy never replaces canonical endpoint E2EE authorization.
 */
export type UcrPrivacyMode = "secure" | "private" | "maximum";

export interface UcrPrivacyNetworkOptions {
  readonly mode: UcrPrivacyMode;
  readonly iceServers: readonly RTCIceServer[];
  /** Production control-plane trust; must not silently fall back to STUN/direct ICE. */
  readonly trustedRelayAvailable: boolean;
}

export interface UcrPrivacyNetworkPlan {
  readonly rtcConfiguration: RTCConfiguration;
  readonly requiresIndependentRelay: boolean;
  readonly dataMinimization: "strict";
}

/** Ensure a high-privacy call cannot downgrade into direct peer connectivity. */
export function planUcrPrivacyNetwork(options: UcrPrivacyNetworkOptions): UcrPrivacyNetworkPlan {
  const {mode, trustedRelayAvailable} = options;
  if (mode !== "secure" && mode !== "private" && mode !== "maximum") {
    throw new Error("unknown privacy mode");
  }
  const servers = options.iceServers.map((server) => ({...server}));
  if (mode !== "secure") {
    if (!trustedRelayAvailable) {
      throw new Error("private call requires a trusted TURN relay");
    }
    const hasTurn = servers.some(({urls}) =>
      (typeof urls === "string" ? [urls] : urls).some((url) => /^turns?:/i.test(url)));
    if (!hasTurn) throw new Error("private call needs TURN configuration");
  }
  return {
    rtcConfiguration: {
      iceServers: servers,
      iceTransportPolicy: mode === "secure" ? "all" : "relay",
      bundlePolicy: "max-bundle",
    },
    requiresIndependentRelay: mode === "maximum",
    dataMinimization: "strict",
  };
}

/**
 * No client API can make a "maximum" mode anonymous without an independently
 * deployed privacy relay. A deployment must explicitly attest to such a route.
 */
export function assertUcrPrivacyNetworkReady(
  plan: UcrPrivacyNetworkPlan,
  independentRelayReady: boolean,
): void {
  if (plan.requiresIndependentRelay && !independentRelayReady) {
    throw new Error("maximum privacy requires independently deployed relay");
  }
}
