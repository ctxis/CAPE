rule QtBot
{
    meta:
        author = "kevoreilly"
        description = "QtBot Payload"
        cape_type = "QtBot Payload"
    strings:
        $a1 = "_WinHttpEventMarshaller51"
        $a2 = "_DRAINING_DATA"
        $a3 = "Supported Schemes = 0x%X; First Scheme = 0x%X; Auth Target = 0x%X\n"
        $a4 = "DALogin" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
