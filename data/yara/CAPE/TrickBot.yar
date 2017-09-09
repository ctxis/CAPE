rule TrickBot
{
    meta:
        author = "sysopfb"
        description = "TrickBot Payload"
        cape_type = "TrickBot Payload"
    strings:
        $ua1 = "TrickLoader" ascii wide
        $ua2 = "TrickBot" ascii wide
        $ua3 = "BotLoader" ascii wide
        $str1 = "<moduleconfig>*</moduleconfig>" ascii wide
        $str2 = "group_tag" ascii wide
        $str3 = "client_id" ascii wide
        $code1 = {8A 11 88 54 35 F8 46 41 4F 89 4D F0 83 FE 04 0F 85 7E 00 00 00 8A 1D A8 5C 15 02 33 F6 8D 49 00 33 C9 84 DB 74 1F 8A 54 35 F8 8A C3 8D 64 24 00}
    condition:
        any of ($ua*) or all of ($str*) or all of ($code*)
}
