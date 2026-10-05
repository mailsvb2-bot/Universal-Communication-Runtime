import type { UcrEndpointE2eePersistenceV1 } from "./endpoint_e2ee.ts";

export interface UcrEndpointMlsStateLike {
  seal_snapshot(wrappingKey: Uint8Array): Uint8Array;
}

export interface UcrEndpointMlsStateStaticLike<TState extends UcrEndpointMlsStateLike> {
  restore(
    tenantId: string,
    namespaceId: string | undefined,
    groupId: string,
    deviceId: string,
    wrappingKey: Uint8Array,
    snapshot: Uint8Array,
    cryptoEpoch: bigint | number,
    cryptoStateRef: string,
  ): TState;
}

export interface UcrEndpointMlsStateHolder<TState extends UcrEndpointMlsStateLike> {
  current: TState;
}

export interface UcrEndpointMlsCanonicalState {
  readonly cryptoEpoch: bigint | number;
  readonly cryptoStateRef: string;
}

export interface UcrEndpointMlsPersistenceContext {
  readonly tenantId: string;
  readonly namespaceId?: string;
  readonly groupId: string;
  readonly deviceId: string;
}

export interface UcrEndpointWrappingKeyProvider {
  /**
   * Return one fresh mutable 32-byte view containing the endpoint wrapping key.
   * Callers erase the returned buffer after each WASM operation.
   */
  getWrappingKey(): Uint8Array | Promise<Uint8Array>;
}

const nonEmpty = (value: string, field: string): string => {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${field} must be non-empty`);
  }
  return value;
};

const wrappingKey = async (
  provider: UcrEndpointWrappingKeyProvider,
): Promise<Uint8Array> => {
  const key = await provider.getWrappingKey();
  if (!(key instanceof Uint8Array) || key.byteLength !== 32) {
    throw new Error("endpoint wrapping key must be exactly 32 bytes");
  }
  if (key.every((value) => value === 0)) {
    throw new Error("endpoint wrapping key must not be all-zero");
  }
  return key;
};

export function createUcrEndpointWasmPersistence<
  TState extends UcrEndpointMlsStateLike,
>(
  stateHolder: UcrEndpointMlsStateHolder<TState>,
  stateStatic: UcrEndpointMlsStateStaticLike<TState>,
  context: UcrEndpointMlsPersistenceContext,
  canonicalState: () =>
    | UcrEndpointMlsCanonicalState
    | Promise<UcrEndpointMlsCanonicalState>,
  keyProvider: UcrEndpointWrappingKeyProvider,
): UcrEndpointE2eePersistenceV1 {
  const tenantId = nonEmpty(context.tenantId, "tenantId");
  const groupId = nonEmpty(context.groupId, "groupId");
  const deviceId = nonEmpty(context.deviceId, "deviceId");
  const namespaceId =
    context.namespaceId === undefined
      ? undefined
      : nonEmpty(context.namespaceId, "namespaceId");

  return {
    async restoreSealedState(snapshot: Uint8Array): Promise<boolean> {
      if (!(snapshot instanceof Uint8Array) || snapshot.byteLength === 0) {
        return false;
      }
      const expected = await canonicalState();
      nonEmpty(expected.cryptoStateRef, "cryptoStateRef");
      const key = await wrappingKey(keyProvider);
      try {
        stateHolder.current = stateStatic.restore(
          tenantId,
          namespaceId,
          groupId,
          deviceId,
          key,
          snapshot,
          expected.cryptoEpoch,
          expected.cryptoStateRef,
        );
        return true;
      } catch {
        return false;
      } finally {
        key.fill(0);
      }
    },

    async sealState(): Promise<Uint8Array> {
      const key = await wrappingKey(keyProvider);
      try {
        const sealed = stateHolder.current.seal_snapshot(key);
        if (!(sealed instanceof Uint8Array) || sealed.byteLength === 0) {
          throw new Error("EndpointMlsState.seal_snapshot returned no bytes");
        }
        return sealed;
      } finally {
        key.fill(0);
      }
    },
  };
}
