rule Azzy
{
    meta:
        author = "kev"
        description = "Azzy encrypt function entry"
        cape_type = "Azzy Payload"
    strings:
        $encrypt = {55 8B EC 83 EC 2C 53 56 8B F2 57 8B 7D 08 B8 AB AA AA AA}

    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D 

        and 

        $encrypt
}
