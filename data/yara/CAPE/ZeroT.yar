rule ZeroT
{
    meta:
        author = "kevoreilly"
        description = "ZeroT Payload"
        cape_type = "ZeroT Payload"
    strings:
        $string1 = "NoNet%c%c%c"
        $string2 = "\\StringFileInfo\\%08lx\\FileVersion" wide
        $string3 = "Build%d"
        $string4 = "cmd /c ipconfig ata & tasklist >/all >"
        $string5 = "Zero.T"
    condition:
        uint16(0) == 0x5A4D and all of them
}

