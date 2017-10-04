rule Ursnif
{
    meta:
        author = "kevoreilly"
        description = "Ursnif Payload"
        cape_type = "Ursnif Payload"
    strings:
        $a1 = {35 FC 58 85 CF A3 ?? ?? 40 00 E8}
        $a2 = {8D 44 24 2C 50 C7 44 24 30 14 00 00 00 FF 15 ?? ?? 40 00 8B 44 24 3C 2B ?? 2B C7 03 44 24 38 50 E8 ?? ?? 00 00 8B 7C 24 38 8B}
        $a3 = {33 C0 33 DB 88 5D E4 8D 7D E5 AB 66 AB 6A 08 AA 68 ?? ?? 40 00 8D 45 E4 50 89 75 F0 89 5D F8 FF 15 ?? ?? 40 00 8B 46 3C 03 C6 0F B7 50 14 0F B7 48 06 8D 44 02 18}
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
