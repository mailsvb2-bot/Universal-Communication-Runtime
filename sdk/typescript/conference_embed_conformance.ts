import assert from "node:assert/strict";

import {
  mountConference,
  normalizeConferenceBranding,
  normalizeConferenceJoinUrl,
  withConferenceBranding,
} from "./src/conference_embed.ts";

const joinUrl =
  "https://conference.example.test/join#ucr_join=signed-test-grant";

assert.equal(normalizeConferenceJoinUrl(joinUrl), joinUrl);
assert.throws(
  () => normalizeConferenceJoinUrl("javascript:alert(1)#ucr_join=x"),
  /http or https/,
);
assert.throws(
  () => normalizeConferenceJoinUrl("https://conference.example.test/join"),
  /#ucr_join/,
);

const branding = normalizeConferenceBranding(
  {
    name: "Example Live",
    logoUrl: "/assets/logo.png",
    accentColor: "#ABCDEF",
    backgroundColor: "#010203",
    language: "ru",
    waitingText: "Эфир скоро начнётся",
  },
  joinUrl,
);
assert.deepEqual(branding, {
  name: "Example Live",
  logoUrl: "https://conference.example.test/assets/logo.png",
  accentColor: "#abcdef",
  backgroundColor: "#010203",
  language: "ru",
  waitingText: "Эфир скоро начнётся",
});

const brandedJoinUrl = withConferenceBranding(joinUrl, branding);
const brandedUrl = new URL(brandedJoinUrl);
const brandedFragment = new URLSearchParams(brandedUrl.hash.slice(1));
assert.equal(brandedFragment.get("ucr_join"), "signed-test-grant");
assert.deepEqual(JSON.parse(brandedFragment.get("ucr_brand") ?? "{}"), branding);

assert.throws(
  () => withConferenceBranding(joinUrl, { accentColor: "red" }),
  /#RRGGBB/,
);
assert.throws(
  () => withConferenceBranding(joinUrl, { logoUrl: "javascript:alert(1)" }),
  /logoUrl must use https/,
);
assert.throws(
  () =>
    withConferenceBranding(joinUrl, {
      logoUrl: "https://user:secret@conference.example.test/logo.png",
    }),
  /must not contain credentials/,
);
assert.throws(
  () =>
    withConferenceBranding(joinUrl, {
      language: "de" as never,
    }),
  /language must be en or ru/,
);

const headless = mountConference({
  joinUrl,
  mode: "headless",
  branding: { name: "Example Live", language: "ru" },
});
assert.equal(headless.mode, "headless");
assert.equal(headless.element, null);
assert.match(headless.joinUrl, /ucr_brand=/);
headless.unmount();

class FakeFrame {
  src = "";
  title = "";
  allow = "";
  referrerPolicy = "";
  className = "";
  parentNode: unknown = null;
  attributes = new Map<string, string>();

  setAttribute(name: string, value: string) {
    this.attributes.set(name, value);
  }

  remove() {
    this.parentNode = null;
  }
}

class FakeContainer {
  children: FakeFrame[] = [];

  replaceChildren(...children: FakeFrame[]) {
    for (const child of this.children) {
      child.parentNode = null;
    }
    this.children = children;
    for (const child of children) {
      child.parentNode = this;
    }
  }
}

const originalDocument = globalThis.document;
const documentStub = {
  createElement(name: string) {
    assert.equal(name, "iframe");
    return new FakeFrame();
  },
};
Object.defineProperty(globalThis, "document", {
  configurable: true,
  value: documentStub,
});

try {
  const container = new FakeContainer();
  const mounted = mountConference({
    joinUrl,
    container: container as unknown as HTMLElement,
    branding: {
      name: "Example Live",
      accentColor: "#336699",
      language: "en",
    },
    className: "ucr-frame",
  });

  assert.equal(mounted.mode, "iframe");
  assert.equal(container.children.length, 1);
  const frame = container.children[0];
  assert.match(frame.src, /ucr_brand=/);
  assert.equal(frame.title, "Example Live");
  assert.equal(frame.className, "ucr-frame");
  assert.equal(frame.referrerPolicy, "no-referrer");
  assert.match(frame.allow, /camera/);
  assert.match(frame.allow, /microphone/);
  assert.match(frame.allow, /display-capture/);
  assert.equal(
    frame.attributes.get("sandbox"),
    "allow-scripts allow-same-origin allow-forms allow-modals allow-popups-to-escape-sandbox",
  );

  mounted.unmount();
  assert.equal(container.children.length, 0);
  mounted.unmount();
} finally {
  if (originalDocument === undefined) {
    Reflect.deleteProperty(globalThis, "document");
  } else {
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: originalDocument,
    });
  }
}

console.log("typescript conference embed conformance ok");
