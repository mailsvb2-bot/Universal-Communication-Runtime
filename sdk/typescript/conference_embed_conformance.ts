import assert from "node:assert/strict";

import {
  mountConference,
  normalizeConferenceJoinUrl,
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

const headless = mountConference({ joinUrl, mode: "headless" });
assert.equal(headless.mode, "headless");
assert.equal(headless.element, null);
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
    title: "Demo conference",
    className: "ucr-frame",
  });

  assert.equal(mounted.mode, "iframe");
  assert.equal(container.children.length, 1);
  const frame = container.children[0];
  assert.equal(frame.src, joinUrl);
  assert.equal(frame.title, "Demo conference");
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
