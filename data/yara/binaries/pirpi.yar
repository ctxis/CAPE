rule Pirpi_cmdline_password
// Pirpi shell trojan requires a command line password for configuration and execution. This password is
// the last argument, four characters long, and is checked one byte at a time. Previous passwords seen
// include: ty89, MS13, N110

/*
.text:0040C1E5 83 F9 04      cmp     ecx, 4
.text:0040C1E8 75 4B         jnz     short loc_40C235
.text:0040C1EA 8B 4D 08      mov     ecx, [ebp+argc]
.text:0040C1ED 8B 55 0C      mov     edx, [ebp+argv]
.text:0040C1F0 8B 44 8A FC   mov     eax, [edx+ecx*4-4]
.text:0040C1F4 0F BE 08      movsx   ecx, byte ptr [eax]
.text:0040C1F7 83 F9 4E      cmp     ecx, 'N'
.text:0040C1FA 75 39         jnz     short loc_40C235
.text:0040C1FC 8B 55 08      mov     edx, [ebp+argc]
.text:0040C1FF 8B 45 0C      mov     eax, [ebp+argv]
.text:0040C202 8B 4C 90 FC   mov     ecx, [eax+edx*4-4]
.text:0040C206 0F BE 51 01   movsx   edx, byte ptr [ecx+1]
.text:0040C20A 83 FA 31      cmp     edx, '1'
.text:0040C20D 75 26         jnz     short loc_40C235
.text:0040C20F 8B 45 08      mov     eax, [ebp+argc]
.text:0040C212 8B 4D 0C      mov     ecx, [ebp+argv]
.text:0040C215 8B 54 81 FC   mov     edx, [ecx+eax*4-4]
.text:0040C219 0F BE 42 02   movsx   eax, byte ptr [edx+2]
.text:0040C21D 83 F8 31      cmp     eax, '1'
.text:0040C220 75 13         jnz     short loc_40C235
.text:0040C222 8B 4D 08      mov     ecx, [ebp+argc]
.text:0040C225 8B 55 0C      mov     edx, [ebp+argv]
.text:0040C228 8B 44 8A FC   mov     eax, [edx+ecx*4-4]
.text:0040C22C 0F BE 48 03   movsx   ecx, byte ptr [eax+3]
.text:0040C230 83 F9 30      cmp     ecx, '0'
.text:0040C233 74 0A         jz      short loc_40C23F
*/
{
    meta:
        author = "Brian Baskin - RSA/IR"
        date = "Jul 2014"
        type = "APT"

   strings:
	   $arg_check = { 83 F? 04 75 ?? 8B [2] 8B [2] 8B [2-4] 0F [2] 83 [2] 75 ?? 8B [2] 8B [2] 8B [2-4] 0F [2-4] 83 [2] 75 ?? 8B [2] 8B [2] 8B [2-4] 0F [2-4] 83 [2] 75 ?? 8B [2] 8B [2] 8B [2-4] 0F [2-4] 83 F9 ?? 74}
   condition:
       $arg_check and uint16(0) == 0x5A4D
}