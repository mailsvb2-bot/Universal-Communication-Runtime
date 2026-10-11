/**
 * Transport-neutral bridge for the host's *existing* Device lifecycle,
 * trusted signing-key owner, and endpoint key vault. This is not an identity
 * authority and creates no second store or permanent telephone directory.
 * The host must authenticate the user independently of a realtime join URL.
 * First enrollment belongs BEFORE issuing that URL; Call/Session are optional.
 */
export interface UcrDeviceEnrollmentBinding {
  readonly tenantId: string;
  readonly namespaceId: string | null;
  readonly deviceId: string;
  readonly participantId: string;
  /** Optional realtime context. Device trust MUST exist independently of a Call. */
  readonly callId?: string;
  readonly sessionId?: string;
}

export interface UcrLocalDeviceSigner {
  readonly keyId: string;
  readonly publicKey: Uint8Array;
}

export interface UcrCanonicalDeviceTrust {
  readonly deviceActive: boolean;
  readonly deviceRevoked: boolean;
  readonly activeKey: UcrLocalDeviceSigner | null;
}

/** The protected private signer is tied to canonical Device, never Call/Session. */
export interface UcrDeviceVaultScope {
  readonly tenantId: string;
  readonly namespaceId: string | null;
  readonly deviceId: string;
}

/** Only the existing endpoint-owned vault may keep the Device signing secret. */
export interface UcrCanonicalDeviceKeyVault {
  load(binding: UcrDeviceVaultScope): Promise<UcrLocalDeviceSigner | null>;
  stageNew(binding: UcrDeviceVaultScope): Promise<UcrLocalDeviceSigner>;
  /** Sign the supplied unpredictable challenge with the existing protected private key. */
  signChallenge(binding: UcrDeviceVaultScope, challenge: Uint8Array): Promise<Uint8Array>;
}

/** Calls the canonical, independently authenticated Device/Trust backend. */
export interface UcrCanonicalDeviceEnrollmentAuthority {
  inspect(binding: UcrDeviceEnrollmentBinding): Promise<UcrCanonicalDeviceTrust>;
  /** Server must independently authorize Device registration and trust provisioning. */
  approveNewDevice(
    binding: UcrDeviceEnrollmentBinding,
    signer: UcrLocalDeviceSigner,
  ): Promise<void>;
}

function equalPublicKeys(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== 32 || b.length !== 32) return false;
  let difference = 0;
  for (let i = 0; i < 32; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

function validateSigner(value: UcrLocalDeviceSigner | null): asserts value is UcrLocalDeviceSigner {
  if (!value?.keyId || !(value.publicKey instanceof Uint8Array) ||
      value.publicKey.length !== 32) {
    throw new Error("canonical local device signer is absent or malformed");
  }
}

async function provePrivateKeyPossession(
  binding: UcrDeviceVaultScope,
  signer: UcrLocalDeviceSigner,
  vault: UcrCanonicalDeviceKeyVault,
): Promise<void> {
  const cryptoProvider = globalThis.crypto;
  if (!cryptoProvider?.subtle || typeof cryptoProvider.getRandomValues !== "function") {
    throw new Error("secure Ed25519 verification is unavailable");
  }
  const challenge = new Uint8Array(48);
  cryptoProvider.getRandomValues(challenge);
  // Challenge binds this operation to the scoped Device; no reusable proof is cached.
  // Snapshot the independently trusted key before awaiting untrusted vault code.
  const approvedPublicKey = signer.publicKey.slice();
  const publicKey = await cryptoProvider.subtle.importKey(
    "raw", approvedPublicKey as Uint8Array<ArrayBuffer>, {name: "Ed25519"}, false, ["verify"],
  );
  const signature = await vault.signChallenge(binding, challenge);
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new Error("protected Device key possession proof is missing");
  }
  if (!await cryptoProvider.subtle.verify(
    "Ed25519", publicKey, signature as Uint8Array<ArrayBuffer>, challenge,
  )) {
    throw new Error("protected Device private key does not match trusted signer");
  }
}

function validateBinding(binding: UcrDeviceEnrollmentBinding): void {
  if (!binding?.tenantId || !binding.deviceId || !binding.participantId) {
    throw new Error("independently authenticated canonical Device identity is required");
  }
  // A new Device must be prepared BEFORE a Call or join URL exists. A caller
  // may optionally bind a later inspection to an exact call/session pair,
  // but must not fabricate one to create permanent trust.
  if ((binding.callId === undefined) !== (binding.sessionId === undefined) ||
      binding.callId === "" || binding.sessionId === "") {
    throw new Error("realtime Call and Session must both be supplied or both omitted");
  }
}

/**
 * Idempotent login-time handshake. Neither a URL grant nor a local key can
 * approve its own trust. No private signing seed crosses the network boundary.
 *
 * The host's vault stages/retains private material; the canonical server
 * authorizes the public descriptor and must confirm its active persisted state
 * on the second read. A revoked device cannot self-reenroll; missing local
 * material for an already registered device requires explicit recovery.
 */
export function createUcrCanonicalDevicePreparation(
  authority: UcrCanonicalDeviceEnrollmentAuthority,
  vault: UcrCanonicalDeviceKeyVault,
): (binding: UcrDeviceEnrollmentBinding, requireExistingTrust?: boolean) => Promise<void> {
  if (!authority || typeof authority.inspect !== "function" ||
      typeof authority.approveNewDevice !== "function" ||
      !vault || typeof vault.load !== "function" ||
      typeof vault.stageNew !== "function" || typeof vault.signChallenge !== "function") {
    throw new Error("canonical Device/Trust authority and protected key vault required");
  }
  let pending: Promise<void> = Promise.resolve();
  return (binding, requireExistingTrust = false) => {
    const prepare = async (item: UcrDeviceEnrollmentBinding): Promise<void> => {
      validateBinding(item);
      // Deliberately omit principal, Call and Session from the private-key
      // vault key. Those identifiers must never trigger a second signing key.
      const vaultScope: UcrDeviceVaultScope = Object.freeze({
        tenantId: item.tenantId, namespaceId: item.namespaceId, deviceId: item.deviceId,
      });
      const before = await authority.inspect(item);
      if (!before || before.deviceRevoked) {
        throw new Error("canonical Device revoked or trust unavailable");
      }
      // Once a Call/Session grant has been issued, trust revalidation MUST
      // never turn missing server trust into an enrollment operation. Losing
      // the record is an authorization loss, not consent to re-register.
      if (requireExistingTrust && (!before.deviceActive || !before.activeKey)) {
        throw new Error("canonical Device revoked or trust unavailable");
      }
      const existing = await vault.load(vaultScope);
      if (before.activeKey) {
        // The untrusted vault and a mutable authority adapter may share byte
        // buffers. Snapshot the independently approved descriptor before awaits.
        const approved = {
          keyId: before.activeKey.keyId,
          publicKey: before.activeKey.publicKey.slice(),
        };
        validateSigner(existing);
        if (!before.deviceActive || existing.keyId !== approved.keyId ||
            !equalPublicKeys(existing.publicKey, approved.publicKey)) {
          throw new Error("local signer differs from active trusted Device key");
        }
        await provePrivateKeyPossession(vaultScope, approved, vault);
        // Re-check canonical trust AFTER the asynchronous key operation: a
        // revoked/rotated Device cannot complete a previously started login.
        const current = await authority.inspect(item);
        if (!current?.deviceActive || current.deviceRevoked || !current.activeKey ||
            current.activeKey.keyId !== approved.keyId ||
            !equalPublicKeys(current.activeKey.publicKey, approved.publicKey)) {
          throw new Error("canonical Device trust changed during signing");
        }
        return;
      }
      if (before.deviceActive) {
        throw new Error("existing Device requires independently approved key recovery");
      }
      // Reuse a staged but not-yet-approved local signer after transport failure.
      // The canonical server still independently authorizes registration.
      const staged = existing ?? await vault.stageNew(vaultScope);
      validateSigner(staged);
      const pendingSigner = {
        keyId: staged.keyId,
        publicKey: staged.publicKey.slice(),
      };
      await provePrivateKeyPossession(vaultScope, pendingSigner, vault);
      // Approve only the snapshot actually proven by the protected signer.
      await authority.approveNewDevice(item, pendingSigner);
      const after = await authority.inspect(item);
      if (!after?.deviceActive || after.deviceRevoked || !after.activeKey ||
          after.activeKey.keyId !== pendingSigner.keyId ||
          !equalPublicKeys(after.activeKey.publicKey, pendingSigner.publicKey)) {
        throw new Error("canonical Device trust registration not confirmed");
      }
    };
    const running = pending.then(() => prepare(binding));
    pending = running.catch(() => {});
    return running;
  };
}
