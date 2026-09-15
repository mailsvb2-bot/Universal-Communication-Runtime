export const CREDENTIAL_ID_METADATA_KEY = "ucr-service-credential-id-bin" as const;
export const CREDENTIAL_SECRET_METADATA_KEY = "ucr-service-credential-secret-bin" as const;

export interface BinaryMetadataEntry {
  readonly key: string;
  readonly value: Uint8Array;
}

/** Opaque Service Principal credential for generated ucr.v1 clients. */
export class ServiceCredential {
  readonly #credentialId: Uint8Array;
  readonly #secret: Uint8Array;

  constructor(credentialId: Uint8Array, secret: Uint8Array) {
    this.#credentialId = credentialId.slice();
    this.#secret = secret.slice();
  }

  binaryMetadata(): readonly BinaryMetadataEntry[] {
    return [
      { key: CREDENTIAL_ID_METADATA_KEY, value: this.#credentialId.slice() },
      { key: CREDENTIAL_SECRET_METADATA_KEY, value: this.#secret.slice() },
    ];
  }

  toString(): string {
    return `ServiceCredential(credential_id_len=${this.#credentialId.length}, secret=[REDACTED])`;
  }
}
