let credentialID: [UInt8] = [0x00, 0x01, 0xfe, 0xff]
let secret: [UInt8] = [0xde, 0xad, 0xbe, 0xef]
let credential = ServiceCredential(credentialID: credentialID, secret: secret)
let metadata = credential.binaryMetadata()

precondition(metadata.count == 2, "Swift SDK emitted unexpected metadata entries")
precondition(metadata[0].key == credentialIDMetadataKey, "credential id key drifted")
precondition(metadata[1].key == credentialSecretMetadataKey, "credential secret key drifted")
precondition(metadata[0].value == credentialID, "credential id bytes drifted")
precondition(metadata[1].value == secret, "credential secret bytes drifted")

let rendered = credential.description
precondition(rendered.contains("[REDACTED]"), "Swift credential diagnostics lost redaction")
precondition(!rendered.lowercased().contains("deadbeef"), "Swift diagnostics exposed secret bytes")

print("UCR_PHASE41_SWIFT_OK")
