/**
 * Operator helpers for cross-network (phone↔PC) ICE server cascades.
 *
 * UCR never invents public STUN/TURN hosts. Callers supply hostnames they
 * control. The recommended order prefers low-latency UDP, then TCP, then
 * TURNS on 443 for carrier firewalls that only permit HTTPS-like traffic.
 */

export type UcrIceCascadeOptions = {
  readonly turnHost: string;
  /** UDP/TCP TURN port (default 3478). */
  readonly turnPort?: number;
  /** TURNS port (default 443). */
  readonly turnsPort?: number;
  /** Optional STUN host; when omitted, no STUN URLs are emitted. */
  readonly stunHost?: string;
  readonly stunPort?: number;
};

function assertDnsHost(host: string): string {
  const value = host.trim().toLowerCase();
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(value) || value.includes("..")) {
    throw new Error("ICE cascade host must be a DNS hostname");
  }
  if (value === "localhost" || value.endsWith(".localhost")) {
    throw new Error("ICE cascade host cannot be localhost");
  }
  // Reject IPv4/IPv6 literals — operators must use DNS names for public ICE.
  if (/^\d+\.\d+\.\d+\.\d+$/.test(value) || value.includes(":")) {
    throw new Error("ICE cascade host must be a DNS hostname");
  }
  return value;
}

function assertPort(port: number, label: string): number {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid ${label} port`);
  }
  return port;
}

/** Build a fail-closed CSV suitable for UCR_WEBRTC_TURN_URLS. */
export function ucrRecommendedTurnCascade(options: UcrIceCascadeOptions): string {
  const host = assertDnsHost(options.turnHost);
  const turnPort = assertPort(options.turnPort ?? 3478, "TURN");
  const turnsPort = assertPort(options.turnsPort ?? 443, "TURNS");
  return [
    `turn:${host}:${turnPort}?transport=udp`,
    `turn:${host}:${turnPort}?transport=tcp`,
    `turns:${host}:${turnsPort}?transport=tcp`,
  ].join(",");
}

/** Optional STUN CSV for UCR_WEBRTC_STUN_URLS (secure mode host/srflx). */
export function ucrOptionalStunUrls(options: UcrIceCascadeOptions): string {
  if (!options.stunHost) return "";
  const host = assertDnsHost(options.stunHost);
  const port = assertPort(options.stunPort ?? 3478, "STUN");
  return `stun:${host}:${port}`;
}
