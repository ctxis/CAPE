rule RCSession
{
    meta:
        author = "kevoreilly"
        description = "RCSession Payload"
        cape_type = "RCSession Payload"
    strings:
        $a1 = {56 33 F6 39 74 24 08 7E 4C 53 57 8B F8 2B FA 8B C6 25 03 00 00 80 79 05 48 83 C8 FC 40 83 E8 00 74 19 48 74 0F 48 74 05 6B C9 09 EB 15 8B C1 C1 E8 02 EB 03 8D 04 09 2B C8}
    condition:
        uint16(0) == 0x5A4D and (any of ($a*))
}
