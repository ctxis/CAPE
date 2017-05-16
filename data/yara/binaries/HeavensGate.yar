rule HeavensGate
{
    meta:
        author = "kevoreilly"
        description = "Heaven's Gate: Switch from 32-bit to 64-mode"
        cape_type = "Heaven's Gate"

    strings:
        $gate_v1 = {6A 33 E8 00 00 00 00 83 04 24 05 CB}
        $gate_v2 = {9A 00 00 00 00 33 00 89 EC 5D C3 48 83 EC 20 E8 00 00 00 00 48 83 C4 20 CB}
    
    condition:
        ($gate_v1 or $gate_v2)
}
