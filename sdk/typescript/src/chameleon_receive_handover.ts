/**
 * Chameleon receive-only handover for a prepared authenticated ciphertext path.
 *
 * The canonical Call/Conference/MLS owners select and authorize candidates.
 * This object never creates sessions, authorizes publishing, holds crypto keys,
 * decodes plaintext, or chooses a room type. No parallel route authority.
 */
export interface UcrReceivePathBinding {
  readonly callId: string;
  readonly sessionId: string;
  readonly cryptoEpoch: bigint;
}

export interface UcrVerifiedReceiveReadiness {
  /** Exact route and crypto epoch of the authenticated, decodable keyframe. */
  readonly pathId: string;
  readonly cryptoEpoch: bigint;
  readonly authenticatedKeyframe: boolean;
  readonly decoderReady: boolean;
}

export interface UcrEncryptedReceivePath {
  readonly pathId: string;
  readonly binding: UcrReceivePathBinding;
  /** Prepare in parallel with old receive path, without publishing new media. */
  prepare(): Promise<UcrVerifiedReceiveReadiness>;
  /** Activation must call guard synchronously at the actual commit point. */
  activate(guard: () => void): Promise<void>;
  /** Stop ciphertext reception and release the prepared receiver. Idempotent. */
  retire(): Promise<void>;
}

/** The canonical owner authorizes the exact candidate path, not merely the Call ID. */
export type UcrReceivePathAuthority = (candidate: UcrEncryptedReceivePath) => boolean;

/**
 * A per-receiver presentation handover, not a transport planner.
 * The current receiver continues uninterrupted until the new authenticated
 * path has supplied a decodable keyframe and the endpoint authorizes commit.
 * Stop/revocation wins against an in-flight prepare. The sole publishing path
 * remains under the canonical media adapter and is never touched.
 */
export class UcrChameleonReceiveHandover {
  readonly #authorized: UcrReceivePathAuthority;
  #active: UcrEncryptedReceivePath;
  #generation = 0;
  #closed = false;
  #changing = false;

  constructor(active: UcrEncryptedReceivePath, authorized: UcrReceivePathAuthority) {
    if (!active.pathId || !active.binding.callId || !active.binding.sessionId ||
        active.binding.cryptoEpoch < 0n) {
      throw new Error("authenticated existing receive path required");
    }
    this.#active = active;
    this.#authorized = authorized;
  }

  get activePathId(): string {
    return this.#active.pathId;
  }

  /** A secure transport replacement for exactly this receiving session and MLS epoch.
   * @returns true if the receiving presentation was changed.
   */
  async handover(next: UcrEncryptedReceivePath): Promise<boolean> {
    if (this.#closed) throw new Error("receive session retired");
    if (this.#changing) throw new Error("receive handover already in progress");
    if (!next.pathId || next.pathId === this.#active.pathId) {
      throw new Error("distinct new receive path required");
    }
    const prior = this.#active;
    if (next.binding.callId !== prior.binding.callId ||
        next.binding.sessionId !== prior.binding.sessionId ||
        next.binding.cryptoEpoch !== prior.binding.cryptoEpoch) {
      throw new Error("receive path must retain canonical session and crypto epoch");
    }
    this.#changing = true;
    const generation = ++this.#generation;
    let activated = false;
    const assertCurrent = () => {
      if (this.#closed || generation !== this.#generation ||
          !this.#authorized(next)) {
        throw new Error("receive handover cancelled or authorization revoked");
      }
    };
    try {
      assertCurrent();
      const readiness = await next.prepare();
      assertCurrent();
      if (readiness.pathId !== next.pathId ||
          readiness.cryptoEpoch !== next.binding.cryptoEpoch ||
          readiness.authenticatedKeyframe !== true || readiness.decoderReady !== true) {
        throw new Error("new encrypted receive path cannot decode an authenticated keyframe");
      }
      // The host MUST invoke assertCurrent at its atomic UI receive switch,
      // after its last asynchronous operation and BEFORE presenting the new path.
      await next.activate(assertCurrent);
      activated = true;
      assertCurrent();
      this.#active = next;
      try {
        await prior.retire();
      } catch {
        // Already switched; stale ciphertext forwarding must be stopped by the host.
        // Report but do not lie about which path is visibly active.
        throw new Error("old encrypted receive path cleanup failed");
      }
      assertCurrent();
      return true;
    } catch (error) {
      if (!activated) {
        try { await next.retire(); } catch { /* retain primary failure */ }
      } else if (this.#active !== next) {
        // A late revoke/close can race activation. Retire the candidate;
        // never silently replace the old authorized receiver.
        try { await next.retire(); } catch { /* closed/revoked */ }
      }
      throw error;
    } finally {
      this.#changing = false;
    }
  }

  async stop(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    ++this.#generation;
    await this.#active.retire();
  }
}
