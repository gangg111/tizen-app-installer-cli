package com.tizen.installer.sdb

object SdbChecksum {
    fun sum32(payload: ByteArray): UInt {
        var sum = 0u
        for (b in payload) sum += b.toUByte()
        return sum
    }
}
