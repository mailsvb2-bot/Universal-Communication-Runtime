(() => {
  "use strict";

  const params = new URLSearchParams(window.location.search);
  const requestedBrowser = params.get("ucr_mobile_probe");
  if (!requestedBrowser) return;

  const resultEndpoint = "/__mobile_probe_result";
  const bytesEqual = (value, expected) => {
    if (!ArrayBuffer.isView(value) || Object.prototype.toString.call(value) !== "[object Uint8Array]") {
      return false;
    }
    const actual = Array.from(value);
    return actual.length === expected.length && expected.every((byte, index) => actual[index] === byte);
  };

  const browserIdentityMatches = (browser, userAgent) => {
    if (browser === "android-chrome") {
      return /Android/i.test(userAgent) &&
        /Chrome\/\d/i.test(userAgent) &&
        !/(EdgA|OPR|SamsungBrowser)\//i.test(userAgent);
    }
    if (browser === "ios-safari") {
      return /(iPhone|iPad)/i.test(userAgent) &&
        /Version\/\d/i.test(userAgent) &&
        /Mobile\//i.test(userAgent) &&
        /Safari\//i.test(userAgent) &&
        !/(CriOS|FxiOS|EdgiOS|OPiOS)\//i.test(userAgent);
    }
    return false;
  };

  const postResult = async payload => {
    await fetch(resultEndpoint, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
      cache: "no-store",
    });
  };

  const run = async () => {
    const userAgent = navigator.userAgent || "";
    const failures = [];
    const checks = {
      referencePage: document.title === "UCR Conference",
      joinFunction: typeof window.join === "function",
      restartIceFunction: typeof window.restartIce === "function",
      applyMediaPolicyFunction: typeof window.applyMediaPolicy === "function",
      screenShareGuardFunction: typeof window.screenShareSupported === "function",
      rtcPeerConnection: typeof window.RTCPeerConnection === "function",
      rtcSetConfiguration: typeof window.RTCPeerConnection === "function" &&
        typeof window.RTCPeerConnection.prototype.setConfiguration === "function",
      mediaStream: typeof window.MediaStream === "function",
      mediaDevices: !!navigator.mediaDevices,
      getUserMedia: !!navigator.mediaDevices &&
        typeof navigator.mediaDevices.getUserMedia === "function",
      fetch: typeof window.fetch === "function",
      abortController: typeof window.AbortController === "function",
      textEncoder: typeof window.TextEncoder === "function",
      cryptoSubtle: !!window.crypto && !!window.crypto.subtle,
      secureContext: window.isSecureContext === true,
      indexedDb: !!window.indexedDB,
      endpointStateStore: !!window.ucrEndpointStateStore &&
        typeof window.ucrEndpointStateStore.save === "function" &&
        typeof window.ucrEndpointStateStore.load === "function" &&
        typeof window.ucrEndpointStateStore.remove === "function",
      endpointWrappingKeyVault: !!window.ucrEndpointWrappingKeyVault &&
        typeof window.ucrEndpointWrappingKeyVault.createProvider === "function",
      endpointWasmLoader: !!window.ucrEndpointWasm &&
        typeof window.ucrEndpointWasm.load === "function",
      joinControl: !!document.getElementById("join"),
      microphoneControl: !!document.getElementById("mic-toggle"),
      cameraControl: !!document.getElementById("camera-toggle"),
      screenControl: !!document.getElementById("screen-toggle"),
      localVideo: !!document.getElementById("local-video"),
      remoteVideo: !!document.getElementById("remote-video"),
      viewportConfigured: !!document.querySelector('meta[name="viewport"]'),
      touchCapable: (navigator.maxTouchPoints || 0) > 0,
      browserIdentity: browserIdentityMatches(requestedBrowser, userAgent),
    };

    for (const [name, passed] of Object.entries(checks)) {
      if (!passed) failures.push(name);
    }

    let endpointWasmExecution = {ok: false};
    try {
      const module = await window.ucrEndpointWasm.load();
      const state = new module.EndpointMlsState(
        "mobile-probe-tenant",
        "mobile-probe-namespace",
        "mobile-probe-group",
        "mobile-probe-device-" + requestedBrowser
      );
      try {
        const keyPackage = state.key_package();
        let preJoinEpochRejected = false;
        try {
          state.crypto_epoch();
        } catch (_) {
          preJoinEpochRejected = true;
        }
        const keyPackageIsBytes = ArrayBuffer.isView(keyPackage) &&
          Object.prototype.toString.call(keyPackage) === "[object Uint8Array]";
        endpointWasmExecution = {
          ok: module.endpoint_wasm_contract_version() === "ucr.endpoint-wasm.v1" &&
            keyPackageIsBytes &&
            keyPackage.length > 0 &&
            preJoinEpochRejected,
          contract: module.endpoint_wasm_contract_version(),
          keyPackageBytes: keyPackageIsBytes ? keyPackage.length : null,
          preJoinEpochRejected,
        };
      } finally {
        if (typeof state.free === "function") state.free();
      }
    } catch (error) {
      endpointWasmExecution = {ok: false, error: String(error)};
    }
    if (endpointWasmExecution.ok !== true) failures.push("endpointWasmExecution");

    const persistenceKey = "ucr-mobile-probe-" + requestedBrowser + "-" + Date.now();
    const persistenceBytes = [5, 17, 29, 41, 253];
    let endpointStatePersistence = {ok: false};
    try {
      await window.ucrEndpointStateStore.save(persistenceKey, new Uint8Array(persistenceBytes));
      const loaded = await window.ucrEndpointStateStore.load(persistenceKey);
      const roundTrip = bytesEqual(loaded, persistenceBytes);
      await window.ucrEndpointStateStore.remove(persistenceKey);
      const removed = await window.ucrEndpointStateStore.load(persistenceKey);
      endpointStatePersistence = {
        ok: roundTrip && (removed === null || removed === undefined),
        roundTrip,
        deleteVerified: removed === null || removed === undefined,
      };
    } catch (error) {
      endpointStatePersistence = {ok: false, error: String(error)};
    }
    if (endpointStatePersistence.ok !== true) failures.push("endpointStatePersistence");

    const payload = {
      schema: "ucr.mobile-browser-probe.v1",
      browser_requested: requestedBrowser,
      user_agent: userAgent,
      platform: navigator.platform || null,
      max_touch_points: navigator.maxTouchPoints || 0,
      viewport: {
        width: window.innerWidth,
        height: window.innerHeight,
        device_pixel_ratio: window.devicePixelRatio || 1,
      },
      checks,
      endpoint_wasm_execution: endpointWasmExecution,
      endpoint_state_persistence: endpointStatePersistence,
      display_capture_api_observed: !!navigator.mediaDevices &&
        typeof navigator.mediaDevices.getDisplayMedia === "function",
      failures,
      passed: failures.length === 0,
    };

    document.documentElement.dataset.ucrMobileProbe =
      payload.passed ? "passed" : "failed";
    await postResult(payload);
  };

  run().catch(async error => {
    const payload = {
      schema: "ucr.mobile-browser-probe.v1",
      browser_requested: requestedBrowser,
      user_agent: navigator.userAgent || "",
      failures: ["probeException"],
      error: String(error),
      passed: false,
    };
    try {
      await postResult(payload);
    } catch (_) {
      // The host-side timeout remains the fail-closed signal if reporting itself fails.
    }
  });
})();