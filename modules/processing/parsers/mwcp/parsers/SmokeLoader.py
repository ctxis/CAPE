# Copyright (C) 2018 Kevin O'Reilly (kevin.oreilly@contextis.co.uk)
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from mwcp.parser import Parser
import struct, socket
import pefile
import yara

rule_source = '''
rule SmokeLoader
{
    meta:
        author = "kev"
        description = "SmokeLoader C2 decryption function"
        cape_type = "SmokeLoader Payload"
    strings:
        $decrypt1 = {44 0F B6 CF 48 8B D0 49 03 D9 4C 2B D8 8B 4B 01 41 8A 04 13 41 BA 04 00 00 00 0F C9 32 C1 C1 F9 08 49 FF CA 75 F6 F6 D0 88 02 48 FF C2 49 FF C9 75 DB 49 8B C0 48 8B 5C 24 30 48 83 C4 20 5F C3}
        $ref1 = {40 53 48 83 EC 20 8B 05 ?? ?? ?? ?? 83 F8 ?? 75 27 33 C0 89 05 ?? ?? ?? ?? 84 C9 74 1B BB E8 03 00 00 B9 58 02 00 00 FF 15 ?? ?? ?? ?? 48 FF CB 75 F0 8B 05 ?? ?? ?? ?? 48 63 C8 48 8D 05}
        $ref2 = {8B 05 ?? ?? ?? ?? 33 C9 83 F8 04 0F 44 C1 48 63 C8 89 05 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 8B 0C C8 E9}
    condition:
        $decrypt1 and (any of ($ref*))
}
'''

def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == 'SmokeLoader':
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
                    return addresses
                
def xor_decode(buffer, key):
    byte_key = 0xff
    for i in range(0, 4):
        byte_key = byte_key^(key >> (i * 8) & 0xff)
    return ''.join(chr(ord(x)^byte_key) for x in buffer)
    
class SmokeLoader(Parser):
    def __init__(self, reporter=None):
        Parser.__init__(self, description='SmokeLoader configuration parser.', author='kevoreilly', reporter=reporter)

    def run(self):
        filebuf = self.reporter.data
        
        try:
            pe = pefile.PE(data=filebuf, fast_load=False)
            image_base = pe.OPTIONAL_HEADER.ImageBase
        except:
            image_base = 0

        table_ref = yara_scan(filebuf, '$ref1')
        if table_ref:
            table_ref_offset = int(table_ref['$ref1'])
            table_delta = struct.unpack('i', filebuf[table_ref_offset+62:table_ref_offset+66])[0]
            table_offset = table_ref_offset + table_delta + 66

            table_loop = True
            while table_loop:
                c2_offset = 0
                if image_base:
                    c2_rva = struct.unpack('Q', filebuf[table_offset:table_offset+8])[0] - image_base
                    if c2_rva < 0x8000:
                        c2_offset = pe.get_offset_from_rva(c2_rva)
                    else:
                        table_loop = False
                else:
                    c2_offset = struct.unpack('I', filebuf[table_offset:table_offset+4])[0] & 0xffff
                c2_size = struct.unpack('B', filebuf[c2_offset:c2_offset+1])[0]
                c2_key = struct.unpack('I', filebuf[c2_offset+c2_size+1:c2_offset+c2_size+5])[0]
                if c2_offset < 0x8000:
                    try:
                        c2_url = xor_decode(filebuf[c2_offset+1:c2_offset+c2_size+1], c2_key).decode('ascii')
                        if c2_url:
                            self.reporter.add_metadata('address', c2_url)
                    except:
                        table_loop = False
                else:
                    table_loop = False
                table_offset = table_offset + 8
            return
        else:
            table_ref = yara_scan(filebuf, '$ref2')
        if table_ref:
            table_ref_offset = int(table_ref['$ref2'])
            table_delta = struct.unpack('i', filebuf[table_ref_offset+26:table_ref_offset+30])[0]
            table_offset = table_ref_offset + table_delta + 30

            for index in range(0, 2):
                if image_base:
                    c2_rva = struct.unpack('Q', filebuf[table_offset:table_offset+8])[0] - image_base
                    c2_offset = pe.get_offset_from_rva(c2_rva)
                else:
                    c2_offset = struct.unpack('I', filebuf[table_offset:table_offset+4])[0] & 0xffff
                c2_size = struct.unpack('B', filebuf[c2_offset:c2_offset+1])[0]
                c2_key = struct.unpack('I', filebuf[c2_offset+c2_size+1:c2_offset+c2_size+5])[0]
                try:
                    c2_url = xor_decode(filebuf[c2_offset+1:c2_offset+c2_size+1], c2_key).decode('ascii')
                    if c2_url:
                        self.reporter.add_metadata('address', c2_url)
                except:
                    pass
                table_offset = table_offset + 8
            return
