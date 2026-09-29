export type ConferenceMountMode = "iframe" | "headless";
export type ConferenceLanguage = "en" | "ru";

export interface ConferenceBranding {
  readonly name?: string;
  readonly logoUrl?: string;
  readonly accentColor?: string;
  readonly backgroundColor?: string;
  readonly language?: ConferenceLanguage;
  readonly waitingText?: string;
}

export interface ConferenceMountOptions {
  readonly joinUrl: string;
  readonly mode?: ConferenceMountMode;
  readonly container?: HTMLElement;
  readonly title?: string;
  readonly className?: string;
  readonly allow?: string;
  readonly branding?: ConferenceBranding;
}

export interface MountedConference {
  readonly joinUrl: string;
  readonly mode: ConferenceMountMode;
  readonly element: HTMLIFrameElement | null;
  unmount(): void;
}

const DEFAULT_ALLOW = "camera; microphone; display-capture; fullscreen";
const BRANDING_FRAGMENT_KEY = "ucr_brand";
const MAX_BRAND_NAME_LENGTH = 80;
const MAX_WAITING_TEXT_LENGTH = 240;
const MAX_LOGO_URL_LENGTH = 2048;
const HEX_COLOR = /^#[0-9a-fA-F]{6}$/;

function boundedText(
  value: string | undefined,
  maximumLength: number,
  field: string,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maximumLength) {
    throw new Error(`${field} must be 1..${maximumLength} characters`);
  }
  return normalized;
}

function normalizedColor(
  value: string | undefined,
  field: string,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!HEX_COLOR.test(value)) {
    throw new Error(`${field} must be a #RRGGBB color`);
  }
  return value.toLowerCase();
}

function normalizedLogoUrl(
  value: string | undefined,
  joinUrl: string,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > MAX_LOGO_URL_LENGTH) {
    throw new Error(`logoUrl must be 1..${MAX_LOGO_URL_LENGTH} characters`);
  }

  const join = new URL(joinUrl);
  const logo = new URL(normalized, join.origin);
  if (logo.username || logo.password) {
    throw new Error("logoUrl must not contain credentials");
  }
  if (logo.protocol === "https:") {
    return logo.toString();
  }

  const loopback =
    join.hostname === "localhost" ||
    join.hostname === "127.0.0.1" ||
    join.hostname === "[::1]";
  if (
    join.protocol === "http:" &&
    loopback &&
    logo.protocol === "http:" &&
    logo.origin === join.origin
  ) {
    return logo.toString();
  }
  throw new Error("logoUrl must use https, except same-origin loopback development");
}

export function normalizeConferenceJoinUrl(joinUrl: string): string {
  const trimmed = joinUrl.trim();
  if (trimmed.length === 0) {
    throw new Error("conference join URL is required");
  }

  const url = new URL(trimmed);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("conference join URL must use http or https");
  }

  const fragment = new URLSearchParams(url.hash.startsWith("#") ? url.hash.slice(1) : url.hash);
  if (!fragment.get("ucr_join")) {
    throw new Error("conference join URL must contain #ucr_join");
  }

  return url.toString();
}

export function normalizeConferenceBranding(
  branding: ConferenceBranding,
  joinUrl: string,
): ConferenceBranding {
  const normalizedJoinUrl = normalizeConferenceJoinUrl(joinUrl);
  const normalized: {
    name?: string;
    logoUrl?: string;
    accentColor?: string;
    backgroundColor?: string;
    language?: ConferenceLanguage;
    waitingText?: string;
  } = {};

  const name = boundedText(branding.name, MAX_BRAND_NAME_LENGTH, "name");
  if (name !== undefined) {
    normalized.name = name;
  }

  const logoUrl = normalizedLogoUrl(branding.logoUrl, normalizedJoinUrl);
  if (logoUrl !== undefined) {
    normalized.logoUrl = logoUrl;
  }

  const accentColor = normalizedColor(branding.accentColor, "accentColor");
  if (accentColor !== undefined) {
    normalized.accentColor = accentColor;
  }

  const backgroundColor = normalizedColor(branding.backgroundColor, "backgroundColor");
  if (backgroundColor !== undefined) {
    normalized.backgroundColor = backgroundColor;
  }

  if (branding.language !== undefined) {
    if (branding.language !== "en" && branding.language !== "ru") {
      throw new Error("language must be en or ru");
    }
    normalized.language = branding.language;
  }

  const waitingText = boundedText(
    branding.waitingText,
    MAX_WAITING_TEXT_LENGTH,
    "waitingText",
  );
  if (waitingText !== undefined) {
    normalized.waitingText = waitingText;
  }

  return normalized;
}

export function withConferenceBranding(
  joinUrl: string,
  branding?: ConferenceBranding,
): string {
  const normalizedJoinUrl = normalizeConferenceJoinUrl(joinUrl);
  if (!branding) {
    return normalizedJoinUrl;
  }

  const normalized = normalizeConferenceBranding(branding, normalizedJoinUrl);
  if (Object.keys(normalized).length === 0) {
    return normalizedJoinUrl;
  }

  const url = new URL(normalizedJoinUrl);
  const fragment = new URLSearchParams(url.hash.slice(1));
  fragment.set(BRANDING_FRAGMENT_KEY, JSON.stringify(normalized));
  url.hash = fragment.toString();
  return url.toString();
}

export function mountConference(options: ConferenceMountOptions): MountedConference {
  const joinUrl = withConferenceBranding(options.joinUrl, options.branding);
  const mode = options.mode ?? "iframe";

  if (mode === "headless") {
    return {
      joinUrl,
      mode,
      element: null,
      unmount() {},
    };
  }

  if (mode !== "iframe") {
    throw new Error("unsupported conference mount mode");
  }
  if (!options.container) {
    throw new Error("iframe conference mount requires a container");
  }

  const frame = document.createElement("iframe");
  frame.src = joinUrl;
  frame.title = options.title ?? options.branding?.name ?? "UCR conference";
  frame.allow = options.allow ?? DEFAULT_ALLOW;
  frame.referrerPolicy = "no-referrer";
  frame.setAttribute(
    "sandbox",
    "allow-scripts allow-same-origin allow-forms allow-modals allow-popups-to-escape-sandbox",
  );
  if (options.className) {
    frame.className = options.className;
  }

  options.container.replaceChildren(frame);

  let mounted = true;
  return {
    joinUrl,
    mode,
    element: frame,
    unmount() {
      if (!mounted) {
        return;
      }
      mounted = false;
      if (frame.parentNode === options.container) {
        options.container.replaceChildren();
      } else {
        frame.remove();
      }
    },
  };
}
