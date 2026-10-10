/**
 * Transport-neutral bridge for a host's *existing* Device lifecycle, signing
 * key store and protected endpoint key vault. It is not an identity authority.
 * The host must authenticate the user independently of a realtime join URL.
 */
export interface UcrDeviceEnrollmentBinding {
  readonly tenantId: string;
  readonly namespaceId: string | null;
  readonly deviceId: string;
  readonly participantId: string;
  readonly callId: string;
  readonly sessionId: string;
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

/** Only the existing device-owned key vault can store and retrieve private material. */
export interface UcrCanonicalDeviceKeyVault {
  load(binding: UcrDeviceEnrollmentBinding): Promise<UcrLocalDeviceSigner | null>;
  stageNew(binding: UcrDeviceEnrollmentBinding): Promise<UcrLocalDeviceSigner>;
  /** Sign the supplied unpredictable challenge with the existing protected private key. */
  signChallenge(binding: UcrDeviceEnrollmentBinding, challenge: Uint8Array): Promise<Uint8Array>;
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
  binding: UcrDeviceEnrollmentBinding,
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
  if (!binding?.tenantId || !binding.deviceId || !binding.participantId ||
      !binding.callId || !binding.sessionId) {
    throw new Error("authenticated, device-bound realtime session is required");
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
): (binding: UcrDeviceEnrollmentBinding) => Promise<void> {
  if (!authority || typeof authority.inspect !== "function" ||
      typeof authority.approveNewDevice !== "function" ||
      !vault || typeof vault.load !== "function" ||
      typeof vault.stageNew !== "function" || typeof vault.signChallenge !== "function") {
    throw new Error("canonical Device/Trust authority and protected key vault required");
  }
  let pending: Promise<void> = Promise.resolve();
  return (binding) => {
    const prepare = async (item: UcrDeviceEnrollmentBinding): Promise<void> => {
      validateBinding(item);
      const before = await authority.inspect(item);
      if (!before || before.deviceRevoked) {
        throw new Error("canonical Device revoked or trust unavailable");
      }
      const existing = await vault.load(item);
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
        await provePrivateKeyPossession(item, approved, vault);
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
      const staged = existing ?? await vault.stageNew(item);
      validateSigner(staged);
      const pendingSigner = {
        keyId: staged.keyId,
        publicKey: staged.publicKey.slice(),
      };
      await provePrivateKeyPossession(item, pendingSigner, vault);
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
