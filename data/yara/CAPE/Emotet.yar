rule Emotet
{
    meta:
        author = "kevoreilly"
        description = "Emotet Payload"
        cape_type = "Emotet Payload"
    strings:
        $string1 = "%s\\es.l.k"
        $string2 = "%s\\es\\%3.ex%"
        $string3 = "AlllAsclAttlBac"
        $decrypt = {69 C9 3F 00 01 00 8D 52 01 0F BE C0 03 C8 8A 02 84 C0 75 EC 33 4D 0C 33 F6 85 FF}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and all of them
}

