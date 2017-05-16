rule Cerber
{
    meta:
        author = "kevoreilly"
        description = "Cerber Payload"
        cape_type = "Cerber Payload"
    strings:
        $code1 = {33 C0 66 89 45 88 8D 7D 8A AB AB AB AB AB 66 AB 8D 45 88 E8 54 60 00 00 C7 04 24 90 37}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D 

        and 
        
        all of them
}

