rule Gootkit
{
    meta:
        author = "kevoreilly"
        description = "Gootkit Payload"
        cape_type = "Gootkit Payload"
    strings:
        $code1 = {C7 45 ?? ?? ?? 41 00 C7 45 ?? ?? 10 40 00 C7 45 E? D8 C9 01 00 C7 45 ?? 00 00 00 00 C7 45 ?? 00 00 00 00 8B 15 00 10 40 00 89 55 F? A1 ?? ?? 43 00 89 45 ?? 68 E8 80 00 00 FF 15}
    condition:
        uint16(0) == 0x5A4D and all of them
}
