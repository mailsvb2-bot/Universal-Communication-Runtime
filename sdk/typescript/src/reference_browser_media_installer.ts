import {
  createUcrAuthorizedMediaInstaller,
  type UcrAuthorizedMediaBootstrap,
  type UcrAuthorizedMediaFactory,
} from "./authorized_browser_media.ts";
import type { UcrEndpointE2eeAdapterV1 } from "./endpoint_e2ee.ts";
import {
  createUcrCanonicalBrowserMediaFactory,
  type UcrCanonicalMediaAdmissionResolver,
} from "./canonical_browser_media_factory.ts";

/**
 * The only entrypoint loaded by the reference browser. Bundled once as ESM.
 *
 * The canonical application must inject its device-authenticated authority
 * implementation before a call starts. This is NOT a second identity store:
 * that authority must resolve live device trust, negotiated media binding,
 * endpoint-owned signing material and per-frame publication/reception policy
 * from the already-authorized Call/Group/Device/MLS session.
 *
 * Never invent a signing key, trust an unverified in-band public key, create an
 * unauthenticated epoch, or send plaintext if the authority isn't available.
 */
interface UcrReferenceMediaWindow extends Record<string, unknown> {
  ucrCanonicalAuthorizedMediaFactory?: UcrAuthorizedMediaFactory;
  ucrCanonicalMediaAdmissionResolver?: UcrCanonicalMediaAdmissionResolver;
}

const target = globalThis as unknown as UcrReferenceMediaWindow;
const createInstaller = createUcrAuthorizedMediaInstaller(
  target,
  async (bootstrap) => {
    // The canonical host may expose its existing, authenticated admission
    // resolver directly. Compose the proven MLS/device/media factory here,
    // without a separate manual window factory installation step.
    const existingFactory = target.ucrCanonicalAuthorizedMediaFactory;
    const resolver = target.ucrCanonicalMediaAdmissionResolver;
    const factory = typeof existingFactory === "function"
      ? existingFactory
      : typeof resolver === "function"
        ? createUcrCanonicalBrowserMediaFactory(resolver)
        : null;
    if (typeof factory !== "function") {
      throw new Error(
        "Canonical device media signing/trust authority is not wired; refusing endpoint media",
      );
    }
    const options = await factory(bootstrap);
    // Independent sanity checks happen inside createUcrAuthorizedMediaInstaller.
    // The trusted factory never receives or asks for a server MLS exporter.
    return options;
  },
);

export async function installUcrReferenceBrowserMedia(
  bootstrap: UcrAuthorizedMediaBootstrap,
): Promise<UcrEndpointE2eeAdapterV1> {
  return createInstaller(bootstrap);
}

// The authenticated host can import this directly from the same ESM bundle.
// It still MUST supply its canonical identity/key owner; the SDK mints none.
export { createUcrCanonicalBrowserMediaFactory } from "./canonical_browser_media_factory.ts";
