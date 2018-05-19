rule DridexDropper
{
    meta:
        author = "kevoreilly"
        description = "Dridex v4 dropper C2 parsing function"
        cape_type = "DridexDropper Payload"

    strings:
        $c2parse = {57 0F 95 C0 89 35 ?? ?? ?? ?? 88 46 04 33 FF 80 3D ?? ?? ?? ?? 00 76 54 8B 04 FD ?? ?? ?? ?? 8D 4D EC 83 65 F4 00 89 45 EC 66 8B 04 FD ?? ?? ?? ?? 66 89 45 F0 8D 45 F8 50}
    
    condition:
        uint16(0) == 0x5A4D and $c2parse
}
