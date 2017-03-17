# CAPE - Config And Payload Extraction
# Copyright(C) 2015, 2016 Context Information Security. (kevin.oreilly@contextis.com)
# 
# This program is free software : you can redistribute it and / or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.If not, see <http://www.gnu.org/licenses/>.

import struct
from lib.cuckoo.common.abstracts import Signature

IMAGE_DOS_SIGNATURE             = 0x5A4D
IMAGE_NT_SIGNATURE              = 0x00004550
OPTIONAL_HEADER_MAGIC_PE        = 0x10b
OPTIONAL_HEADER_MAGIC_PE_PLUS   = 0x20b
IMAGE_FILE_EXECUTABLE_IMAGE     = 0x0002
PE_HEADER_LIMIT                 = 0x200

PLUGX_SIGNATURE		            = 0x5658
EXTRACTION_MIN_SIZE             = 0x2000

class CAPE_PlugX(Signature):
    name = "CAPE PlugX"
    description = "CAPE detection: PlugX"
    severity = 3
    categories = ["chinese", "malware"]
    families = ["plugx"]
    authors = ["kev"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["RtlDecompressBuffer", "memcpy"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.compressed_binary = False
        self.config_copy = False
        self.plugx = False

    def on_call(self, call, process):
        if call["api"] == "RtlDecompressBuffer":
            buf = self.get_raw_argument(call, "UncompressedBuffer")
            dos_header = buf[:64]
            if struct.unpack("<H", dos_header[0:2])[0] == IMAGE_DOS_SIGNATURE:
                self.compressed_binary = True
            elif struct.unpack("<H", dos_header[0:2])[0] == PLUGX_SIGNATURE:
                self.compressed_binary = True

        if call["api"] == "memcpy":
            count = self.get_raw_argument(call, "count")
            if (count == 0xae4)  or \
               (count == 0xbe4)  or \
               (count == 0x150c) or \
               (count == 0x1510) or \
               (count == 0x1516) or \
               (count == 0x170c) or \
               (count == 0x1b18) or \
               (count == 0x1d18) or \
               (count == 0x2540) or \
               (count == 0x254c) or \
               (count == 0x2d58) or \
               (count == 0x36a4) or \
               (count == 0x4ea4):
                self.config_copy = True

    def on_complete(self):
        if self.config_copy == True and self.compressed_binary == True:
            self.plugx = True
            return True

class CAPE_PlugX_fuzzy(Signature):
    name = "CAPE PlugX fuzzy"
    description = "CAPE detection: PlugX (fuzzy match)"
    severity = 3
    categories = ["chinese", "malware"]
    families = ["plugx"]
    authors = ["kev"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["RtlDecompressBuffer", "memcpy"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.compressed_binary = False
        self.config_copy = False
        self.plugx = False

    def on_call(self, call, process):
        if call["api"] == "RtlDecompressBuffer":
            buf = self.get_raw_argument(call, "UncompressedBuffer")
            dos_header = buf[:64]
            if struct.unpack("<H", dos_header[0:2])[0] == IMAGE_DOS_SIGNATURE:
                self.compressed_binary = True
            elif struct.unpack("<H", dos_header[0:2])[0] == PLUGX_SIGNATURE:
                self.plugx = True

    def on_complete(self):
        if self.config_copy == True and self.compressed_binary == True:
            self.plugx = True
        if self.plugx == True:
            return True

class CAPE_Compression(Signature):
    name = "CAPE Compression"
    description = "CAPE detection: Compression"
    severity = 3
    categories = ["malware"]
    authors = ["kev"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["RtlDecompressBuffer"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.compressed_binary = False

    def on_call(self, call, process):
        if call["api"] == "RtlDecompressBuffer":
            buf = self.get_raw_argument(call, "UncompressedBuffer")
            dos_header = buf[:64]

            if struct.unpack("<H", dos_header[0:2])[0] == IMAGE_DOS_SIGNATURE:
                self.compressed_binary = True

            # Check for sane value in e_lfanew
            e_lfanew, = struct.unpack("<L", dos_header[60:64])
            if not e_lfanew or e_lfanew > PE_HEADER_LIMIT:
                return
            
            nt_headers = buf[e_lfanew:e_lfanew+256]

            #if ((pNtHeader->FileHeader.Machine == 0) || (pNtHeader->FileHeader.SizeOfOptionalHeader == 0 || pNtHeader->OptionalHeader.SizeOfHeaders == 0)) 
            if struct.unpack("<H", nt_headers[4:6]) == 0 or struct.unpack("<H", nt_headers[20:22]) == 0 or struct.unpack("<H", nt_headers[84:86]) == 0:
                return

            #if (!(pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) 
            if (struct.unpack("<H", nt_headers[22:24])[0] & IMAGE_FILE_EXECUTABLE_IMAGE) == 0:
                return

            #if (pNtHeader->FileHeader.SizeOfOptionalHeader & (sizeof (ULONG_PTR) - 1)) 
            if struct.unpack("<H", nt_headers[20:22])[0] & 3 != 0:
                return

            #if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
            if struct.unpack("<H", nt_headers[24:26])[0] != OPTIONAL_HEADER_MAGIC_PE and struct.unpack("<H", nt_headers[24:26])[0] != OPTIONAL_HEADER_MAGIC_PE_PLUS:
                return
 
            # To pass the above tests it should now be safe to assume it's a PE image
            self.compressed_binary = True            
            
    def on_complete(self):
        if self.compressed_binary == True:
            return True
            
class CAPE_Derusbi(Signature):
    name = "CAPE Derusbi"
    description = "CAPE detection: Derusbi"
    severity = 3
    categories = ["chinese", "malware"]
    families = ["derusbi"]
    authors = ["kev"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["srand", "memcpy"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.srand = False
        self.config_copy = False
        self.derusbi = False

    def on_call(self, call, process):
        if call["api"] == "srand":
            self.srand = True

        if call["api"] == "memcpy":
            count = self.get_raw_argument(call, "count")
            if (count == 0x50)  or \
               (count == 0x1A8) or \
               (count == 0x2B4):    
               self.config_copy = True

    def on_complete(self):
        if self.config_copy == True and self.srand == True:
            self.derusbi = True
            #return True
        return False

class CAPE_EvilGrab(Signature):
    name = "CAPE EvilGrab"
    description = "CAPE detection: EvilGrab"
    severity = 3
    categories = ["malware"]
    authors = ["kev"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.reg_evilgrab_keyname = False
        self.reg_binary = False

    def on_call(self, call, process):
        if call["api"] == "RegCreateKeyExA" or call["api"] == "RegCreateKeyExW":
            buf = self.get_argument(call, "SubKey")
            if buf == "Software\\rar":
                self.reg_evilgrab_keyname = True
            
        if call["api"] == "RegSetValueExA" or call["api"] == "RegSetValueExW":
            length = self.get_raw_argument(call, "BufferLength")
            if length > 0x10000 and self.reg_evilgrab_keyname == True:
                self.reg_binary = True

    def on_complete(self):
        if self.reg_binary == True:
            return True
        else:
            return False
            
class ExtractionRWX(Signature):
    name = "extraction_rwx"
    description = "CAPE detection: Extraction"
    severity = 1
    categories = ["allocation"]
    authors = ["Context"]
    minimum = "1.2"
    evented = True
    
    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["NtAllocateVirtualMemory","NtProtectVirtualMemory","VirtualProtectEx"])

    # PAGE_EXECUTE_READWRITE = 0x00000040
    
    def on_call(self, call, process):
        if call["api"] == "NtAllocateVirtualMemory":
            protection = self.get_argument(call, "Protection")
            regionsize = int(self.get_raw_argument(call, "RegionSize"), 0)
            handle = self.get_argument(call, "ProcessHandle")
            if handle == "0xffffffff" and protection == "0x00000040" and regionsize >= EXTRACTION_MIN_SIZE:
                return True
        if call["api"] == "VirtualProtectEx":
            protection = self.get_argument(call, "Protection")
            size = int(self.get_raw_argument(call, "Size"), 0)
            handle = self.get_argument(call, "ProcessHandle")
            if handle == "0xffffffff" and protection == "0x00000040" and size >= EXTRACTION_MIN_SIZE:
                return True
        elif call["api"] == "NtProtectVirtualMemory":
            protection = self.get_argument(call, "NewAccessProtection")
            size = int(self.get_raw_argument(call, "NumberOfBytesProtected"), 0)
            handle = self.get_argument(call, "ProcessHandle")
            if handle == "0xffffffff" and protection == "0x00000040" and size >= EXTRACTION_MIN_SIZE:
                return True
