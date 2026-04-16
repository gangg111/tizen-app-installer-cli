package com.tizen.installer.sdb

data class SdbFrame(
    val command: SdbCommand,
    val arg0: UInt,
    val arg1: UInt,
    val payload: ByteArray = ByteArray(0)
) {
    val dataLength: UInt get() = payload.size.toUInt()
    val dataChecksum: UInt get() = SdbChecksum.sum32(payload)
    val magic: UInt get() = command.value xor 0xFFFFFFFFu

    fun validateHeader(rawMagic: UInt): Boolean = rawMagic == magic

    fun validateChecksum(rawChecksum: UInt, rawLength: UInt): Boolean =
        rawLength == dataLength && rawChecksum == dataChecksum

    companion object {
        fun stringToAsciiPayload(s: String): ByteArray = s.toByteArray(Charsets.US_ASCII)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SdbFrame) return false
        return command == other.command && arg0 == other.arg0 && arg1 == other.arg1 &&
                payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = command.hashCode()
        result = 31 * result + arg0.hashCode()
        result = 31 * result + arg1.hashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }
}
