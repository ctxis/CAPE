rule TrickBot
{
    meta:
        author = "sysopfb & kevoreilly"
        description = "TrickBot Payload"
        cape_type = "TrickBot Payload"
    strings:
        $ua1 = "TrickLoader" ascii wide
        $ua2 = "TrickBot" ascii wide
        $ua3 = "BotLoader" ascii wide
        $str1 = "<moduleconfig>*</moduleconfig>" ascii wide
        $str2 = "group_tag" ascii wide
        $str3 = "client_id" ascii wide
        $code1 = {8A 11 88 54 35 F8 46 41 4F 89 4D F0 83 FE 04 0F 85 7E 00 00 00 8A 1D ?? ?? ?? ?? 33 F6 8D 49 00 33 C9 84 DB 74 1F 8A 54 35 F8 8A C3 8D 64 24 00}
        $code2 = {8B 4D FC 8A D1 02 D2 8A C5 C0 F8 04 02 D2 24 03 02 C2 88 45 08 8A 45 FE 8A D0 C0 FA 02 8A CD C0 E1 04 80 E2 0F 32 D1 8B 4D F8 C0 E0 06 02 45 FF 88 55 09 66 8B 55 08 66 89 11 88 41 02}
        $code3 = {0F B6 54 24 49 0F B6 44 24 48 48 83 C6 03 C0 E0 02 0F B6 CA C0 E2 04 C0 F9 04 33 DB 80 E1 03 02 C8 88 4C 24 40 0F B6 4C 24 4A 0F B6 C1 C0 E1 06 02 4C 24 4B C0 F8 02 88 4C 24 42 24 0F}
    condition:
        any of ($ua*) or all of ($str*) or any of ($code*)
}
