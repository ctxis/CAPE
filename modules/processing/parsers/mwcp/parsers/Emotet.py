# Copyright (C) 2017 Kevin O'Reilly (kevin.oreilly@contextis.co.uk)
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
import pefile
import yara
import os.path

rule_source = '''
rule Emotet
{
    meta:
        author = "kevoreilly"
        description = "Emotet Payload"
        cape_type = "Emotet Payload"
    strings:
        $snippet1 = {FF 15 ?? ?? ?? ?? 83 C4 0C 68 40 00 00 F0 6A 18}
        $snippet2 = {6A 13 68 01 00 01 00 FF 15 ?? ?? ?? ?? 85 C0}
        $c2list = {?? ?? ?? ?? ?? (01|1F) 00 00 ?? ?? ?? ?? ?? (01|1F) 00 00 ?? ?? ?? ?? ?? (01|1F) 00 00 ?? ?? ?? ?? ?? (01|1F) 00 00}
    condition:
        //check for MZ Signature at offset 0
        uint16(0) == 0x5A4D and all of them
}

'''

MAX_IP_STRING_SIZE = 16       # aaa.bbb.ccc.ddd\0

def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == 'Emotet':
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
                    return addresses

class Emotet(malwareconfigparser):
    def __init__(self, reporter=None):
        malwareconfigparser.__init__(self, description='Emotet configuration parser.', author='kevoreilly', reporter=reporter)

    def run(self):
        filebuf = self.reporter.data
        pe = pefile.PE(data=self.reporter.data, fast_load=False)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        
        c2list = yara_scan(filebuf, '$c2list')
        
        if c2list:
            ips_offset = int(c2list['$c2list'])
        else:
            return        
                
        ip = struct.unpack('I', filebuf[ips_offset:ips_offset+4])[0]
        
        while ip:
            c2_address = socket.inet_ntoa(struct.pack('!L', ip))
            port = str(struct.unpack('h', filebuf[ips_offset+4:ips_offset+6])[0])

            if c2_address and port:
                self.reporter.add_metadata('address', c2_address+':'+port)
            
            ips_offset += 8
            ip = struct.unpack('I', filebuf[ips_offset:ips_offset+4])[0]
        
        return