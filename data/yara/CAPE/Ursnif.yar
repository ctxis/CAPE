rule Ursnif
{
    meta:
        author = "kevoreilly & enzo"
        description = "Ursnif Payload"
        cape_type = "Ursnif Payload"
    strings:
        $a1 = {35 FC 58 85 CF A3 ?? ?? 40 00 E8}
        $a2 = {8D 44 24 2C 50 C7 44 24 30 14 00 00 00 FF 15 ?? ?? 40 00 8B 44 24 3C 2B ?? 2B C7 03 44 24 38 50 E8 ?? ?? 00 00 8B 7C 24 38 8B}
        $a3 = {33 C0 33 DB 88 5D E4 8D 7D E5 AB 66 AB 6A 08 AA 68 ?? ?? 40 00 8D 45 E4 50 89 75 F0 89 5D F8 FF 15 ?? ?? 40 00 8B 46 3C 03 C6 0F B7 50 14 0F B7 48 06 8D 44 02 18}

        $b1 = "CBmWzIJQqV"
        $b2 = "Software\\Microsoft\\WAB\\DLLPath"

        $c1 = {48 8B C4 53 55 56 57 41 54 41 55 41 56 41 57 48 83 EC 48 48 8B 51 30 48 8B F9 48 85 D2 48 89 50 10}
        $c2 = {8B 70 EC 33 70 F8 33 70 08 33 30 83 C0 04 33 F1 81 F6 B9 79 37 9E C1 C6 0B 89 70 08 41 81 F9 84 00 00 00 72 DB}
        
        $d1 = "MSVCcvidMRLE"
 
        $decrypt32_1 = {A3 28 B2 ?? ?? 3D 4E 3B 55 EE 74 29 8B 53 0C 8B 43 10 6A 01 56 03 D7 E8 61 21 00 00 C7 45 FC 0C 00 00 00 EB 10}
        $decrypt64_1 = {89 0D C6 57 03 00 81 F9 4E 3B 55 EE 74 28 8B 4F 0C 8B 57 10 44 8D 45 0D 48 03 CE 45 8B CE E8 F9 6D 02 00 BB 0C 00 00 00 EB 0C}
        $decrypt64_2 = {44 89 1D 4C 67 03 00 41 81 FB 70 6C 68 73 74 28 8B 4F 0C 8B 57 10 44 8D 45 0E 48 03 CE 45 8B CE E8 6E 77 02 00 BB 0C 00 00 00 EB 0C}
        
    condition:
        uint16(0) == 0x5A4D and (any of ($decrypt32*)) or (any of ($decrypt64*)) or (all of ($a*)) or ((all of ($b*)) and (all of ($c*)) or (all of ($d*)))
}