rule Hancitor
{
    meta:
        author = "kevoreilly"
        description = "Hancitor Payload"
        cape_type = "Hancitor Payload"
    strings:
        $decrypt = {33 C9 03 D6 C7 45 FC ?? ?? ?? ?? 8B 70 10 85 F6 74 12 90 8B C1 83 E0 03 8A 44 05 FC 30 04 11 41 3B CE 72 EF}
    condition:
        uint16(0) == 0x5A4D and all of them
}
