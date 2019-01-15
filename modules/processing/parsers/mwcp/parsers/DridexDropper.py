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
import os.path

rule_source = '''
rule DridexDropper
{
    meta:
        author = "kevoreilly"
        description = "Dridex v4 dropper C2 parsing function"
        cape_type = "DridexDropper Payload"

    strings:
        $c2parse = {57 0F 95 C0 89 35 ?? ?? ?? ?? 88 46 04 33 FF 80 3D ?? ?? ?? ?? 00 76 54 8B 04 FD ?? ?? ?? ?? 8D 4D EC 83 65 F4 00 89 45 EC 66 8B 04 FD ?? ?? ?? ?? 66 89 45 F0 8D 45 F8 50}
    
    condition:
        uint16(0) == 0x5A4D and $c2parse
}

'''

MAX_IP_STRING_SIZE = 16       # aaa.bbb.ccc.ddd\0

def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == 'DridexDropper':
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
                    return addresses

class DridexDropper(Parser):
    def __init__(self, reporter=None):
        Parser.__init__(self, description='DridexDropper configuration parser.', author='kevoreilly', reporter=reporter)

    def run(self):
        filebuf = self.reporter.data
        pe = pefile.PE(data=self.reporter.data, fast_load=False)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        
        c2parse = yara_scan(filebuf, '$c2parse')
        
        if c2parse:
            c2va_offset = int(c2parse['$c2parse'])
        else:
            return

        c2_rva = struct.unpack('i', filebuf[c2va_offset+27:c2va_offset+31])[0] - image_base
        c2_offset = pe.get_offset_from_rva(c2_rva)
        
        for i in range(0, 4):
            ip = struct.unpack('>I', filebuf[c2_offset:c2_offset+4])[0]
            c2_address = socket.inet_ntoa(struct.pack('!L', ip))
            port = str(struct.unpack('H', filebuf[c2_offset+4:c2_offset+6])[0])

            if c2_address and port:
                self.reporter.add_metadata('address', c2_address+':' + port)
            
            c2_offset += 8
            
        return
        