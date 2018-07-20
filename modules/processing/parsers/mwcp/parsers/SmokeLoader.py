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
    
from mwcp.malwareconfigparser import malwareconfigparser
import struct, socket
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
        $ref1 = {3D 00 10 00 00 0F 8E ?? ?? 00 00 39 07 0F 85 ?? 02 00 00 8B 4F 04 81 F1 ?? ?? ?? ?? 0F 85 ?? 02 00 00 44 8A 67 0C 44 88 65 78 45 84 E4 0F 84 CD 02 00 00 48 8D 0D ?? E4 FF FF E8}
        $ref2 = {3D 00 10 00 00 0F 8E ?? ?? 00 00 39 07 0F 85 ?? 02 00 00 8B 4F 04 81 F1 ?? ?? ?? ?? 0F 85 ?? 02 00 00 44 8A 67 0C 45 84 E4 0F 84 C7 02 00 00 48 8D 0D}
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
    
class SmokeLoader(malwareconfigparser):
    def __init__(self, reporter=None):
        malwareconfigparser.__init__(self, description='SmokeLoader configuration parser.', author='kevoreilly', reporter=reporter)

    def run(self):
        filebuf = self.reporter.data
        c2ref = yara_scan(filebuf, '$ref1')
        if c2ref:
            c2ref_offset = int(c2ref['$ref1'])
            c2_delta = struct.unpack('i', filebuf[c2ref_offset+54:c2ref_offset+58])[0]
            c2_offset = c2ref_offset + c2_delta + 58
            # First C2 URL
            c2_size = struct.unpack('B', filebuf[c2_offset:c2_offset+1])[0]
            c2_key = struct.unpack('I', filebuf[c2_offset+c2_size+1:c2_offset+c2_size+5])[0]
            c2_url = xor_decode(filebuf[c2_offset+1:c2_offset+c2_size+1], c2_key)
            if c2_url:
                self.reporter.add_metadata('address', c2_url)
            # Second C2 URL
            c2_offset = c2_offset + c2_size + 9
            c2_size = struct.unpack('B', filebuf[c2_offset:c2_offset+1])[0]
            c2_key = struct.unpack('I', filebuf[c2_offset+c2_size+1:c2_offset+c2_size+5])[0]
            c2_url = xor_decode(filebuf[c2_offset+1:c2_offset+c2_size+1], c2_key)
            if c2_url:
                self.reporter.add_metadata('address', c2_url)
            return
        else:
            c2ref = yara_scan(filebuf, '$ref2')
        if c2ref:
            c2ref_offset = int(c2ref['$ref2'])
            c2_delta = struct.unpack('i', filebuf[c2ref_offset+50:c2ref_offset+54])[0]
            c2_offset = c2ref_offset + c2_delta + 54
            # First C2 URL
            c2_size = struct.unpack('B', filebuf[c2_offset:c2_offset+1])[0]
            c2_key = struct.unpack('I', filebuf[c2_offset+c2_size+1:c2_offset+c2_size+5])[0]
            c2_url = xor_decode(filebuf[c2_offset+1:c2_offset+c2_size+1], c2_key)
            if c2_url:
                self.reporter.add_metadata('address', c2_url)
            # Second C2 URL
            c2_offset = c2_offset + c2_size + 9
            c2_size = struct.unpack('B', filebuf[c2_offset:c2_offset+1])[0]
            c2_key = struct.unpack('I', filebuf[c2_offset+c2_size+1:c2_offset+c2_size+5])[0]
            c2_url = xor_decode(filebuf[c2_offset+1:c2_offset+c2_size+1], c2_key)
            if c2_url:
                self.reporter.add_metadata('address', c2_url)
            return