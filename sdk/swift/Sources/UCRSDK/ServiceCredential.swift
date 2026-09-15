public let credentialIDMetadataKey = "ucr-service-credential-id-bin"
public let credentialSecretMetadataKey = "ucr-service-credential-secret-bin"

public struct BinaryMetadataEntry: Sendable {
    public let key: String
    public let value: [UInt8]

    public init(key: String, value: [UInt8]) {
        self.key = key
        self.value = value
    }
}

public struct ServiceCredential: Sendable, CustomStringConvertible {
    private let credentialID: [UInt8]
    private let secret: [UInt8]

    public init(credentialID: [UInt8], secret: [UInt8]) {
        self.credentialID = credentialID
        self.secret = secret
    }

    public func binaryMetadata() -> [BinaryMetadataEntry] {
        [
            BinaryMetadataEntry(key: credentialIDMetadataKey, value: credentialID),
            BinaryMetadataEntry(key: credentialSecretMetadataKey, value: secret),
        ]
    }

    public var description: String {
        "ServiceCredential(credential_id_len=\(credentialID.count), secret=[REDACTED])"
    }
}
