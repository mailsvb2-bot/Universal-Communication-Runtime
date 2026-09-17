package org.ucr.sdk

fun main() {
    val credentialId = byteArrayOf(0x00, 0x01, 0x7e, 0x7f)
    val secret = byteArrayOf(0x6e, 0x5d, 0x4c, 0x3b)
    val credential = ServiceCredential(credentialId, secret)
    val metadata = credential.binaryMetadata()

    check(metadata.size == 2) { "Kotlin SDK emitted unexpected metadata entries" }
    check(metadata[0].key == CREDENTIAL_ID_METADATA_KEY) { "credential id key drifted" }
    check(metadata[1].key == CREDENTIAL_SECRET_METADATA_KEY) { "credential secret key drifted" }
    check(metadata[0].value.contentEquals(credentialId)) { "credential id bytes drifted" }
    check(metadata[1].value.contentEquals(secret)) { "credential secret bytes drifted" }

    metadata[0].value[0] = 0x55
    check(credential.binaryMetadata()[0].value[0] == credentialId[0]) {
        "returned Kotlin metadata mutated stored credential bytes"
    }
    val rendered = credential.toString()
    check(rendered.contains("[REDACTED]")) { "Kotlin credential diagnostics lost redaction" }
    check(!rendered.lowercase().contains("6e5d4c3b")) { "Kotlin diagnostics exposed secret bytes" }

    println("UCR_PHASE41_KOTLIN_OK")
}
