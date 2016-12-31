from lib.cuckoo.common.abstracts import Signature

EXTRACTION_MIN_SIZE = 0x2000

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
            buf = self.get_argument(call, "UncompressedBuffer")
            if "XV" in buf:
                self.compressed_binary = True
            if "MZ" in buf:
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
            buf = self.get_argument(call, "UncompressedBuffer")
            if "XV" in buf:
                self.plugx = True
            if "MZ" in buf:
                self.compressed_binary = True

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
            buf = self.get_argument(call, "UncompressedBuffer")
            if "MZ" in buf:
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
