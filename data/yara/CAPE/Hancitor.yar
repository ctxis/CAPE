rule Hancitor
{
    meta:
        author = "kevoreilly"
        description = "Hancitor Payload"
        cape_type = "Hancitor Payload"
    strings:
        $decrypt = {B9 6C C5 58 54 EB 2A 8B 55 E0 8B 52 04 8B 75 EC 0F B6 14 32 8B 75 E4 0F B7 36 31 F2 C1 EE 08 8B 5D EC 31 D3 31 F3 8B 55 EC 88 1C 10 0F B7 55 F2 42 BE 6C 20 DB D8}
    condition:
        uint16(0) == 0x5A4D and all of them
}
