package org.ucr.sdk

const val CREDENTIAL_ID_METADATA_KEY: String = "ucr-service-credential-id-bin"
const val CREDENTIAL_SECRET_METADATA_KEY: String = "ucr-service-credential-secret-bin"

data class BinaryMetadataEntry(val key: String, val value: ByteArray)

/** Opaque Service Principal credential for generated ucr.v1 clients. */
class ServiceCredential(credentialId: ByteArray, secret: ByteArray) {
    private val credentialId = credentialId.copyOf()
    private val secret = secret.copyOf()

    fun binaryMetadata(): List<BinaryMetadataEntry> = listOf(
        BinaryMetadataEntry(CREDENTIAL_ID_METADATA_KEY, credentialId.copyOf()),
        BinaryMetadataEntry(CREDENTIAL_SECRET_METADATA_KEY, secret.copyOf()),
    )

    override fun toString(): String =
        "ServiceCredential(credential_id_len=${credentialId.size}, secret=[REDACTED])"
}
