package com.tizen.installer.sdb

enum class SdbCommand(val value: UInt) {
    CNXN(0x4E584E43u),
    AUTH(0x48545541u),
    OPEN(0x4E45504Fu),
    OKAY(0x59414B4Fu),
    WRTE(0x45545257u),
    CLSE(0x45534C43u);

    companion object {
        fun fromValue(value: UInt): SdbCommand? = entries.find { it.value == value }
    }
}
