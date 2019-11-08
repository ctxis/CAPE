# Copyright (C) 2019 Kevin O'Reilly (kevoreilly@gmail.com)
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
import struct
import string
import socket
import pefile
import yara
from Crypto.Cipher import ARC4

rule_source = '''
rule DridexLoader
{
    meta:
        author = "kevoreilly"
        description = "Dridex v4 dropper C2 parsing function"
        cape_type = "DridexLoader Payload"

    strings:
        $c2parse_1 = {57 0F 95 C0 89 35 ?? ?? ?? ?? 88 46 04 33 FF 80 3D ?? ?? ?? ?? 00 76 54 8B 04 FD ?? ?? ?? ?? 8D 4D EC 83 65 F4 00 89 45 EC 66 8B 04 FD ?? ?? ?? ?? 66 89 45 F0 8D 45 F8 50}
        $c2parse_2 = {89 45 00 0F B7 53 04 89 10 0F B6 4B 0C 83 F9 0A 7F 03 8A 53 0C 0F B6 53 0C 85 D2 7E B7 8D 74 24 0C C7 44 24 08 00 00 00 00 8D 04 7F 8D 8C 00}
        $c2parse_3 = {89 08 66 39 1D ?? ?? ?? ?? A1 ?? ?? ?? ?? 0F 95 C1 88 48 04 80 3D ?? ?? ?? ?? 0A 77 05 A0 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 56 8B F3 76 4E 66 8B 04 F5}
        $botnet_id = {C7 00 00 00 00 00 8D 00 6A 04 50 8D 4C ?? ?? E8 ?? ?? ?? ?? 0F B7 05}
    condition:
        uint16(0) == 0x5A4D and any of them
}

'''

MAX_IP_STRING_SIZE = 16       # aaa.bbb.ccc.ddd\0
LEN_BLOB_KEY = 40
LEN_BOT_KEY = 107

def convert_char(c):
    if c in (string.letters + string.digits + string.punctuation + " \t\r\n"):
        return c
    else:
        return "\\x%02x" % ord(c)

def decrypt_rc4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def yara_scan(raw_data, rule_name):
    addresses = {}
    yara_rules = yara.compile(source=rule_source)
    matches = yara_rules.match(data=raw_data)
    for match in matches:
        if match.rule == 'DridexLoader':
            for item in match.strings:
                if item[1] == rule_name:
                    addresses[item[1]] = item[0]
                    return addresses

def extract_rdata(pe):
    for section in pe.sections:
        if '.rdata' in section.Name:
            return section.get_data(section.VirtualAddress, section.SizeOfRawData)
    return None

class DridexLoader(Parser):
    def __init__(self, reporter=None):
        Parser.__init__(self, description='DridexLoader configuration parser.', author='kevoreilly', reporter=reporter)

    def run(self):
        filebuf = self.reporter.data
        pe = pefile.PE(data=self.reporter.data, fast_load=False)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        delta = 0

        c2parse = yara_scan(filebuf, '$c2parse_1')
        if c2parse:
            c2va_offset = int(c2parse['$c2parse_1'])
            c2_rva = struct.unpack('i', filebuf[c2va_offset+27:c2va_offset+31])[0] - image_base
            delta = 2
        else:
            c2parse = yara_scan(filebuf, '$c2parse_2')
            if c2parse:
                c2va_offset = int(c2parse['$c2parse_2'])
                c2_rva = struct.unpack('i', filebuf[c2va_offset+47:c2va_offset+51])[0] - image_base
            else:
                c2parse = yara_scan(filebuf, '$c2parse_3')
                if c2parse:
                    c2va_offset = int(c2parse['$c2parse_3'])
                    c2_rva = struct.unpack('i', filebuf[c2va_offset+60:c2va_offset+64])[0] - image_base
                    delta = 2
                else:
                    return

        c2_offset = pe.get_offset_from_rva(c2_rva)

        for i in range(0, 4):
            ip = struct.unpack('>I', filebuf[c2_offset:c2_offset+4])[0]
            c2_address = socket.inet_ntoa(struct.pack('!L', ip))
            port = str(struct.unpack('H', filebuf[c2_offset+4:c2_offset+6])[0])

            if c2_address and port:
                self.reporter.add_metadata('address', c2_address+':' + port)

            c2_offset += (6 + delta)

        botnet_scan = yara_scan(filebuf, '$botnet_id')
        if botnet_scan:
            botnet_code = int(botnet_scan['$botnet_id'])
            botnet_va = struct.unpack('i', filebuf[botnet_code+23:botnet_code+27])[0] - image_base
            botnet_offset = pe.get_offset_from_rva(botnet_va)
            botnet_id = struct.unpack('H', filebuf[botnet_offset:botnet_offset+2])[0]
            self.reporter.add_metadata('other', {'Botnet ID': str(botnet_id)})

        blobs = filter(None, [x.strip("\x00\x00\x00\x00") for x in extract_rdata(pe).split("\x00\x00\x00\x00")])
        for blob in blobs:
            if len(blob) < LEN_BLOB_KEY:
                continue
            raw = decrypt_rc4(blob[:LEN_BLOB_KEY][::-1], blob[LEN_BLOB_KEY:])
            if not raw:
                continue
            for item in raw.split("\x00"):
                data = "".join(convert_char(c) for c in item)
                if len(data) == LEN_BOT_KEY:
                    self.reporter.add_metadata('other', {'RC4 key': data.split(';')[0]})
        return
