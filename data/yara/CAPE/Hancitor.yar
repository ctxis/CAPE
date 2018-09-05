rule Hancitor
{
    meta:
        author = "kevoreilly"
        description = "Hancitor Payload"
        cape_type = "Hancitor Payload"
    strings:
        $decrypt1 = {33 C9 03 D6 C7 45 FC ?? ?? ?? ?? 8B 70 10 85 F6 74 12 90 8B C1 83 E0 03 8A 44 05 FC 30 04 11 41 3B CE 72 EF}
        $decrypt2 = {B9 08 00 00 00 8B 75 08 83 C4 04 8B F8 3B D1 76 10 8B C1 83 E0 07 8A 04 30 30 04 31 41 3B CA 72 F0 8D 45 FC}
    condition:
        uint16(0) == 0x5A4D and (any of ($decrypt*))
}
