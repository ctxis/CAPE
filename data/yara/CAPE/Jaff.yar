rule Jaff
{
    meta:
        author = "kevoreilly"
        description = "Jaff Payload"
        cape_type = "Jaff Payload"
    strings:
        $string1 = "CryptGenKey"
        $string2 = "353260540318613681395633061841341670181307185694827316660016508"
        $string3 = "2~1c0q4t7"
    condition:
        uint16(0) == 0x5A4D 
        and 
        all of them
}
