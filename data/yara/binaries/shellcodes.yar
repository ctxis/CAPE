// Copyright (C) 2010-2014 Cuckoo Foundation.
// This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
// See the file 'docs/LICENSE' for copying permission.

rule shellcode_patterns
{
    meta:
        author = "nex"
        description = "Matched shellcode byte patterns"

    strings:
        $mz = { 4d 5a }
        $shell1 = { 64 8b 64 }
        $shell2 = { 64 a1 30 }
        $shell3 = { 64 8b 15 30 }
        $shell4 = { 64 8b 35 30 }
        $shell5 = { 55 8b ec 83 c4 }
        $shell6 = { 55 8b ec 81 ec }
        $shell7 = { 55 8b ec e8 }
        $shell8 = { 55 8b ec e9 }
    condition:
        not ($mz at 0) and
        any of ($shell*)
}

rule shellcode_get_eip
{
    meta:
        author = "William Ballenthin"
        email = "william.ballenthin@fireeye.com"
        license = "Apache 2.0"
        copyright = "FireEye, Inc"
        description = "Match x86 that appears to fetch $PC."

    strings:
       // 0:  e8 00 00 00 00          call   5 <_main+0x5>
       // 5:  58                      pop    eax
       // 6:  5b                      pop    ebx
       // 7:  59                      pop    ecx
       // 8:  5a                      pop    edx
       // 9:  5e                      pop    esi
       // a:  5f                      pop    edi
       $x86 = { e8 00 00 00 00 (58 | 5b | 59 | 5a | 5e | 5f) }

    condition:
       $x86
}

rule shellcode_peb_parsing
{
    meta:
        author = "William Ballenthin"
        email = "william.ballenthin@fireeye.com"
        license = "Apache 2.0"
        copyright = "FireEye, Inc"
        description = "Match x86 that appears to manually traverse the TEB/PEB/LDR data."

    strings:
       //                                                         ;; TEB->PEB
       // (64 a1 30 00 00 00 |                                    ; mov eax, fs:30
       //  64 8b (1d | 0d | 15 | 35 | 3d) 30 00 00 00 |           ; mov $reg, DWORD PTR fs:0x30
       //  31 (c0 | db | c9 | d2 | f6 | ff) [0-8] 64 8b ?? 30 )   ; xor $reg; mov $reg, DWORD PTR fs:[$reg+0x30]
       // [0-8]                                                   ; up to 8 bytes of interspersed instructions
       //                                                         ;; PEB->LDR_DATA
       // 8b ?? 0c                                                ; mov eax,DWORD PTR [eax+0xc]
       // [0-8]                                                   ; up to 8 bytes of interspersed instructions
       //                                                         ;; LDR_DATA->OrderLinks
       // 8b ?? (0c | 14 | 1C)                                    ; mov edx, [edx+0Ch]
       // [0-8]                                                   ; up to 8 bytes of interspersed instructions
       //                                                         ;; _LDR_DATA_TABLE_ENTRY.DllName.Buffer
       // 8b ?? (28 | 30)                                         ; mov esi, [edx+28h]
       $peb_parsing = { (64 a1 30 00 00 00 | 64 8b (1d | 0d | 15 | 35 | 3d) 30 00 00 00 | 31 (c0 | db | c9 | d2 | f6 | ff) [0-8] 64 8b ?? 30 ) [0-8] 8b ?? 0c [0-8] 8b ?? (0c | 14 | 1C) [0-8] 8b ?? (28 | 30) }

       $peb_parsing64 = { (48 65 A1 60 00 00 00 00 00 00 00 | 65 (48 | 4C) 8B ?? 60 00 00 00 | 65 A1 60 00 00 00 00 00 00 00 | 65 8b ?? ?? 00 FF FF | (48 31 (c0 | db | c9 | d2 | f6 | ff) | 4D 31 (c0 | c9))  [0-16] 65 (48 | 4d | 49 | 4c) 8b ?? 60) [0-16] (48 | 49 | 4C) 8B ?? 18 [0-16] (48 | 49 | 4C) 8B ?? (10 | 20 | 30) [0-16] (48 | 49 | 4C) 8B ?? (50 | 60) }

    condition:
       $peb_parsing or $peb_parsing64
}
