import {
  CREDENTIAL_ID_METADATA_KEY,
  CREDENTIAL_SECRET_METADATA_KEY,
  ServiceCredential,
} from "./src/auth.ts";

function requireCondition(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const credentialId = new Uint8Array([0x00, 0x01, 0xfe, 0xff]);
const secret = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
const credential = new ServiceCredential(credentialId, secret);
const metadata = credential.binaryMetadata();

requireCondition(metadata.length === 2, "TypeScript SDK emitted unexpected metadata entries");
requireCondition(metadata[0].key === CREDENTIAL_ID_METADATA_KEY, "credential id key drifted");
requireCondition(metadata[1].key === CREDENTIAL_SECRET_METADATA_KEY, "credential secret key drifted");
requireCondition(
  Buffer.from(metadata[0].value).equals(Buffer.from(credentialId)),
  "credential id bytes drifted",
);
requireCondition(
  Buffer.from(metadata[1].value).equals(Buffer.from(secret)),
  "credential secret bytes drifted",
);

metadata[0].value[0] = 0x7f;
requireCondition(
  credential.binaryMetadata()[0].value[0] === credentialId[0],
  "returned TypeScript metadata mutated stored credential bytes",
);
const rendered = credential.toString();
requireCondition(rendered.includes("[REDACTED]"), "TypeScript credential diagnostics lost redaction");
requireCondition(!rendered.toLowerCase().includes("deadbeef"), "TypeScript diagnostics exposed secret bytes");

console.log("UCR_PHASE41_TYPESCRIPT_OK");
