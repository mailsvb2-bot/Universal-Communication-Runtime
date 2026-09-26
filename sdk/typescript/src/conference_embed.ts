export type ConferenceMountMode = "iframe" | "headless";

export interface ConferenceMountOptions {
  readonly joinUrl: string;
  readonly mode?: ConferenceMountMode;
  readonly container?: HTMLElement;
  readonly title?: string;
  readonly className?: string;
  readonly allow?: string;
}

export interface MountedConference {
  readonly joinUrl: string;
  readonly mode: ConferenceMountMode;
  readonly element: HTMLIFrameElement | null;
  unmount(): void;
}

const DEFAULT_ALLOW = "camera; microphone; display-capture; fullscreen";

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

export function mountConference(options: ConferenceMountOptions): MountedConference {
  const joinUrl = normalizeConferenceJoinUrl(options.joinUrl);
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
  frame.title = options.title ?? "UCR conference";
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
