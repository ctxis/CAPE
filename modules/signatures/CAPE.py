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

EXECUTABLE_FLAGS                = 0x10 | 0x20 | 0x40 | 0x80
EXTRACTION_MIN_SIZE             = 0x1001

PLUGX_SIGNATURE		            = 0x5658

class CAPE_Compression(Signature):
    name = "Compression"
    description = "CAPE detection: Compression (or decompression)"
    severity = 1
    categories = ["malware"]
    authors = ["kevoreilly"]
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

class CAPE_Extraction(Signature):
    name = "Extraction"
    description = "CAPE detection: Executable code extraction"
    severity = 1
    categories = ["allocation"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True
    
    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["NtAllocateVirtualMemory","NtProtectVirtualMemory","VirtualProtectEx"])

    def on_call(self, call, process):
    
        if process["process_name"] == "WINWORD.EXE" or process["process_name"] == "EXCEL.EXE" or process["process_name"] == "POWERPNT.EXE":
            return False
        if call["api"] == "NtAllocateVirtualMemory":
            protection = int(self.get_raw_argument(call, "Protection"), 0)
            regionsize = int(self.get_raw_argument(call, "RegionSize"), 0)
            handle = self.get_argument(call, "ProcessHandle")
            if handle == "0xffffffff" and protection & EXECUTABLE_FLAGS and regionsize >= EXTRACTION_MIN_SIZE:
                return True
        if call["api"] == "VirtualProtectEx":
            protection = int(self.get_raw_argument(call, "Protection"), 0)
            size = int(self.get_raw_argument(call, "Size"), 0)
            handle = self.get_argument(call, "ProcessHandle")
            if handle == "0xffffffff" and protection & EXECUTABLE_FLAGS and size >= EXTRACTION_MIN_SIZE:
                return True
        elif call["api"] == "NtProtectVirtualMemory":
            protection = int(self.get_raw_argument(call, "NewAccessProtection"), 0)
            size = int(self.get_raw_argument(call, "NumberOfBytesProtected"), 0)
            handle = self.get_argument(call, "ProcessHandle")
            if handle == "0xffffffff" and protection & EXECUTABLE_FLAGS and size >= EXTRACTION_MIN_SIZE:
                return True

class CAPE_InjectionCreateRemoteThread(Signature):
    name = "InjectionCreateRemoteThread"
    description = "CAPE detection: Injection with CreateRemoteThread in a remote process"
    severity = 1
    categories = ["injection"]
    authors = ["JoseMi Holguin", "nex", "Optiv", "kevoreilly", "KillerInstinct"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None
        self.write_detected = False
        self.remote_thread = False

    filter_categories = set(["process","threading"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.process_handles = set()
            self.process_pids = set()
            self.lastprocess = process

        if call["api"] == "OpenProcess" and call["status"] == True:
            if self.get_argument(call, "ProcessId") != process["process_id"]:
                self.process_handles.add(call["return"])
                self.process_pids.add(self.get_argument(call, "ProcessId"))
        elif call["api"] == "NtOpenProcess" and call["status"] == True:
            if self.get_argument(call, "ProcessIdentifier") != process["process_id"]:
                self.process_handles.add(self.get_argument(call, "ProcessHandle"))
                self.process_pids.add(self.get_argument(call, "ProcessIdentifier"))
        elif call["api"] == "CreateProcessInternalW":
            if self.get_argument(call, "ProcessId") != process["process_id"]:
                self.process_handles.add(self.get_argument(call, "ProcessHandle"))
                self.process_pids.add(self.get_argument(call, "ProcessId"))
        elif (call["api"] == "NtMapViewOfSection"):
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.write_detected = True
        elif (call["api"] == "VirtualAllocEx" or call["api"] == "NtAllocateVirtualMemory"):
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.write_detected = True
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "NtWow64WriteVirtualMemory64" or call["api"] == "WriteProcessMemory"):
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.write_detected = True
                addr = int(self.get_argument(call, "BaseAddress"), 16)
                buf = self.get_argument(call, "Buffer")
                if addr >= 0x7c900000 and addr < 0x80000000 and buf.startswith("\\xe9"):
                    self.description = "Code injection via WriteProcessMemory-modified NTDLL code in a remote process"
                    #procname = self.get_name_from_pid(self.handle_map[handle])
                    #desc = "{0}({1}) -> {2}({3})".format(process["process_name"], str(process["process_id"]),
                    #                                     procname, self.handle_map[handle])
                    self.data.append({"Injection": desc})
                    return True
        elif (call["api"] == "CreateRemoteThread" or call["api"].startswith("NtCreateThread") or call["api"].startswith("NtCreateThreadEx")):
            handle = self.get_argument(call, "ProcessHandle")
            if handle in self.process_handles:
                #procname = self.get_name_from_pid(self.handle_map[handle])
                #desc = "{0}({1}) -> {2}({3})".format(process["process_name"], str(process["process_id"]),
                #                                     procname, self.handle_map[handle])
                #self.data.append({"Injection": desc})
                self.remote_thread = True
        elif call["api"].startswith("NtQueueApcThread"):
            if str(self.get_argument(call, "ProcessId")) in self.process_pids:
                #self.description = "Code injection with NtQueueApcThread in a remote process"
                #desc = "{0}({1}) -> {2}({3})".format(self.lastprocess["process_name"], str(self.lastprocess["process_id"]),
                #                                     process["process_name"], str(process["process_id"]))
                #self.data.append({"Injection": desc})
                self.remote_thread = True

    def on_complete(self):
        if self.write_detected == True and self.remote_thread == True:
            return True

class CAPE_InjectionProcessHollowing(Signature):
    name = "InjectionProcessHollowing"
    description = "CAPE detection: Injection (Process Hollowing)"
    severity = 1
    categories = ["injection"]
    authors = ["glysbaysb", "Optiv", "KillerInstinct"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    filter_categories = set(["process","threading"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.sequence = 0
            # technically we should have a separate state machine for each created process, but since this
            # code doesn't deal with handles properly as it is, this is sufficient
            self.process_handles = set()
            self.thread_handles = set()
            self.process_map = dict()
            self.thread_map = dict()
            self.lastprocess = process

        if call["api"] == "CreateProcessInternalW":
            phandle = self.get_argument(call, "ProcessHandle")
            thandle = self.get_argument(call, "ThreadHandle")
            pid = self.get_argument(call, "ProcessId")
            self.process_handles.add(phandle)
            self.process_map[phandle] = pid
            self.thread_handles.add(thandle)
            self.thread_map[thandle] = pid
        elif (call["api"] == "NtUnmapViewOfSection" or call["api"] == "NtAllocateVirtualMemory") and self.sequence == 0:
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.sequence = 1
        elif call["api"] == "NtGetContextThread" and self.sequence == 0:
           if self.get_argument(call, "ThreadHandle") in self.thread_handles:
                self.sequence = 1
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "NtWow64WriteVirtualMemory64" or call["api"] == "WriteProcessMemory" or call["api"] == "NtMapViewOfSection") and (self.sequence == 1 or self.sequence == 2):
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.sequence = self.sequence + 1
        elif (call["api"] == "NtSetContextThread") and (self.sequence == 1 or self.sequence == 2):
            if self.get_argument(call, "ThreadHandle") in self.thread_handles:
                self.sequence = self.sequence + 1
        elif call["api"] == "NtResumeThread" and (self.sequence == 2 or self.sequence == 3):
            handle = self.get_argument(call, "ThreadHandle")
            if handle in self.thread_handles:
                desc = "{0}({1}) -> {2}({3})".format(process["process_name"], str(process["process_id"]),
                                                     self.get_name_from_pid(self.thread_map[handle]), self.thread_map[handle])
                self.data.append({"Injection": desc})
                return True
        elif call["api"] == "NtResumeProcess" and (self.sequence == 2 or self.sequence == 3):
            handle = self.get_argument(call, "ProcessHandle")
            if handle in self.process_handles:
                desc = "{0}({1}) -> {2}({3})".format(process["process_name"], str(process["process_id"]),
                                                     self.get_name_from_pid(self.process_map[handle]), self.process_map[handle])
                self.data.append({"Injection": desc})
                return True
      
class CAPE_InjectionSetWindowLong(Signature):
    name = "InjectionSetWindowLong"
    description = "CAPE detection: Injection with SetWindowLong in a remote process"
    severity = 1
    categories = ["injection"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None
        self.sharedsections = ["\\basenamedobjects\\shimsharedmemory",
                                "\\basenamedobjects\\windows_shell_global_counters",
                                "\\basenamedobjects\\msctf.shared.sfm.mih",
                                "\\basenamedobjects\\msctf.shared.sfm.amf",
                                "\\basenamedobjects\\urlzonessm_administrator",
                                "\\basenamedobjects\\urlzonessm_system"]

    filter_apinames = set(["NtMapViewOfSection", "NtOpenSection", "NtCreateSection", "FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW", "PostMessageA", "PostMessageW", "SendNotifyMessageA", "SendNotifyMessageW", "SetWindowLongA", "SetWindowLongW", "SetWindowLongPtrA", "SetWindowLongPtrW"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.lastprocess = process
            self.window_handles = set()
            self.sharedmap = False
            self.windowfound = False

        if (call["api"] == ("NtMapViewOfSection")):
            handle = self.get_argument(call, "ProcessHandle")
            if handle != "0xffffffff":
                self.sharedmap = True
        elif call["api"] == "NtOpenSection" or call["api"] == "NtCreateSection":
            name = self.get_argument(call, "ObjectAttributes")
            if name.lower() in self.sharedsections:
                self.sharedmap = True
        elif call["api"].startswith("FindWindow") and call["status"] == True:
            self.windowfound = True
        elif call["api"].startswith("SetWindowLong") and call["status"] == True:
            if self.sharedmap == True and self.windowfound == True:
                return True
                
class CAPE_Injection(Signature):
    name = "InjectionInterProcess"
    description = "CAPE detection: Injection (inter-process)"
    severity = 1
    categories = ["injection"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    filter_categories = set(["process"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.process_handles = set()
            self.lastprocess = process

        if call["api"] == "CreateProcessInternalW":
            phandle = self.get_argument(call, "ProcessHandle")
            pid = self.get_argument(call, "ProcessId")
            self.process_handles.add(phandle)
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "NtWow64WriteVirtualMemory64" or call["api"] == "WriteProcessMemory" or call["api"] == "NtMapViewOfSection"):
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                return True
      
class CAPE_EvilGrab(Signature):
    name = "EvilGrab"
    description = "CAPE detection: EvilGrab"
    severity = 1
    categories = ["malware"]
    authors = ["kevoreilly"]
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

class CAPE_PlugX(Signature):
    name = "PlugX"
    description = "CAPE detection: PlugX"
    severity = 1
    categories = ["chinese", "malware"]
    families = ["plugx"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["RtlDecompressBuffer", "memcpy"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.compressed_binary = False
        self.config_copy = False

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
            return True

class CAPE_Doppelganging(Signature):
    name = "Doppelganging"
    description = "CAPE detection: Process Doppelganging"
    severity = 1
    categories = ["injection"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None
        
    filter_categories = set(["process", "thread", "filesystem",])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.section_handles = set()
            self.lastprocess = process
            self.filehandle = None
            self.sectionhandle = None

        if call["api"] == "CreateFileTransactedA" or call["api"] == "CreateFileTransactedW":
            self.filehandle = self.get_argument(call, "FileHandle")
        elif call["api"] == "NtCreateSection":
            if self.filehandle and self.filehandle == self.get_argument(call, "FileHandle"):
                self.sectionhandle = self.get_argument(call, "SectionHandle")
        elif call["api"] == "NtCreateProcessEx":
            if self.get_argument(call, "SectionHandle") == self.sectionhandle:
                return True
      

class CAPE_AntiDebugSetUnhandledExceptionFilter(Signature):
    name = "SetUnhandledExceptionFilter"
    description = "CAPE detection: Anti-Debug SetUnhandledExceptionFilter"
    severity = 1
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["SetUnhandledExceptionFilter"])

    def on_call(self, call, process):
        if call["api"] == "SetUnhandledExceptionFilter":
           return True
      
            
class CAPE_AntiDebugAddVectoredExceptionHandler(Signature):
    name = "AddVectoredExceptionHandler"
    description = "CAPE detection: Anti-Debug AddVectoredExceptionHandler"
    severity = 1
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["AddVectoredExceptionHandler"])

    def on_call(self, call, process):
        if call["api"] == "AddVectoredExceptionHandler":
           return True
      
# XXX: not sure this will work since NtSetInformationThread is looked up via LdrDll       
# also needs hooking and logging inside capemon
"""
class CAPE_AntiDebugNtSetInformationThread(Signature):
    name = "NtSetInformationThread"
    description = "CAPE detection: Anti-Debug NtSetInformationThread"
    severity = 2
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["NtSetInformationThread"])

    def on_call(self, call, process):
        if call["api"] == "NtSetInformationThread":
	   # check arg 2 if it equals 0x11, if so then trigger
           return True
"""


# XXX: Currently does not work, needs hook monitor around NtCreateThreadEx
"""
class CAPE_AntiDebugNtCreateThreadEx(Signature):
    name = "NtCreateThreadEx"
    description = "CAPE detection: Anti-Debug NtCreateThreadEx"
    severity = 1
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["NtCreateThreadEx"])

    def on_call(self, call, process):
        if call["api"] == "NtCreateThreadEx":
           # check arg  CreateFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER == TRUE then we're hiding from the debugger
           return True
"""


class CAPE_AntiDebugDebugActiveProcess(Signature):
    name = "DebugActiveProcess"
    description = "CAPE detection: Anti-Debug DebugActiveProcess"
    severity = 2
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["DebugActiveProcess"])

    def on_call(self, call, process):
        if call["api"] == "DebugActiveProcess":
           return True

# XXX: THIS IS INCOMPLETE, SEE MISSING HOOK ON NtQueryInformationProcess
class CAPE_AntiDebugCheckRemoteDebuggerPresent(Signature):
    # https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software
    name = "CheckRemoteDebuggerPresent"
    description = "CAPE detection: Anti-Debug CheckRemoteDebuggerPresent"
    severity = 3
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["CheckRemoteDebuggerPresent", "NtQueryInformationProcess"])

    def on_call(self, call, process):
        if call["api"] == "CheckRemoteDebuggerPresent":
           return True
        elif call["api"] == "NtQueryInformationProcess":
	   # looks like capemon is missing hook on this function to inspect arguments
	   # need to verify the argument (_In_      UINT             ProcessInformationClass,) equals 7
	   # would like to also verify argument 3 ( _Out_     PVOID            ProcessInformation) is not null 

	   # other examples to monitor are:
	   # - ProcessDebugObjectHandle 0x1E
	   # - ProcessDebugFlags 0x1F
	   # - ProcessBasicInformation 0x00

	   # dont trigger false positive
           return False



"""
XXX: MISSING CHECK - redsand
CONTEXT ctx = {};
ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
SetThreadContext(GetCurrentThread(), &ctx);

Check if Malware is clearing debug registers.  This function should be hooked and monitored as well
Also hook NtSetContextThread as this is the underlying Nt WINAPI function.

"""


class CAPE_AntiDebugGetTickCount(Signature):
    name = "GetTickCount"
    description = "CAPE detection: Anti-Debug GetTickCount"
    severity = 1
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["GetTickCount"])

    def on_call(self, call, process):
        if call["api"] == "GetTickCount":
           return True

class CAPE_AntiDebugOutputDebugString(Signature):
    name = "OutputDebugString"
    description = "CAPE detection: Anti-Debug OutputDebugString"
    severity = 2
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
	self.set_err = False
	self.output = False

    filter_apinames = set(["OutputDebugStringA", "OutputDebugStringW", "SetLastError", "GetLastError"])

    def on_call(self, call, process):
        if call["api"] == "OutputDebugStringA" or call["api"] == "OutputDebugStringW":
	   if self.set_err: 
		   self.output = True
	   else:
		self.output = False
        elif call["api"] == "SetLastError": 
	  self.output = False
	  self.set_err = True
        elif call["api"] == "GetLastError": 
	  if not self.set_err or not self.output:
		self.set_err = self.output = False
	  elif self.set_err and self.output:
		return True
		

class CAPE_AnomalousDynamicFunctionLoading(Signature):
    name = "AnomalousDynamicFunctionLoading"
    description = "CAPE detection: Anomalous Dynamic Function Loading"
    severity = 1
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
	self.dll_loaded = False
        self.loadctr = 0
	self.list = [ ]

    filter_apinames = set(["LdrGetProcedureAddress", "LdrLoadDll"])

    def on_call(self, call, process):
        if call["api"] == "LdrLoadDll":
	   self.dll_loaded = True
	elif self.dll_loaded and call["api"] == "LdrGetProcedureAddress":
		self.loadctr += 1
		self.data.append({"DynamicLoader" : "%s/%s" % (self.get_argument(call, "ModuleName"), self.get_argument(call, "FunctionName")) })

    def on_complete(self):
	if self.loadctr < 8:
		return False
	elif self.loadctr > 20:
		self.severity = 2
	return True

class CAPE_MaliciousDynamicFunctionLoading(Signature):
    name = "MaliciousDynamicFunctionLoading"
    description = "CAPE detection: Possible Malicious Dynamic Function Loading"
    severity = 1
    categories = ["malware"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True
    malicious_functions = [ "LookupAccountNameLocalW", "LookupAccountNameLocalA", "LookupAccountSidW", "LookupAccountSidA",
			    "LookupAccountSidLocalW", "LookupAccountSidLocalA", "CoTaskMemAlloc", "CoTaskMemFree", 
			    "LookupAccountNameW", "LookupAccountNameA", "NetLocalGroupGetMembers", "SamConnect", "SamLookupNamesInDomain",
			    "OpenProcessToken", "SetThreadToken", "DuplicateTokenEx", "AdjustTokenPrivileges", "OpenThreadToken",
			   ]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
	self.dll_loaded = False
        self.loadctr = 0
	self.list = [ ]

    filter_apinames = set(["LdrGetProcedureAddress", "LdrLoadDll"])

    def on_call(self, call, process):
        if call["api"] == "LdrLoadDll":
	   self.dll_loaded = True
	elif self.dll_loaded and call["api"] == "LdrGetProcedureAddress":
		arg = self.get_argument(call, "FunctionName")
		if arg in self.malicious_functions:
			self.data.append({"SuspiciousDynamicFunction" : "%s/%s" % (self.get_argument(call, "ModuleName"), self.get_argument(call, "FunctionName")) })

    def on_complete(self):
	if self.loadctr > 0:
		return True


class CAPE_AnomalousDeleteFile(Signature):
    name = "AnomalousDeleteFile"
    description = "CAPE detection: Anomalous File Deletion Behavior (10+)"
    severity = 2
    categories = ["malware"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.loadctr = 0
	self.list = [ ]

    filter_apinames = set(["NtDeleteFile", "DeleteFileA", "DeleteFileW"])

    def on_call(self, call, process):
        if call["api"] == "NtDeleteFile" or call["api"] == "DeleteFileA" or call["api"] == "DeleteFileW":
		self.loadctr += 1
		self.data.append({"DynamicLoader" : "%s/%s" % (self.get_argument(call, "ModuleName"), self.get_argument(call, "FunctionName")) })
    def on_complete(self):
	if self.loadctr > 10:
		return True


class CAPE_ThemeInitApiHookInject(Signature):
    name = "ThemeInitApiHookInject"
    description = "CAPE detection: Possible ThemeInitApiHook Injection"
    severity = 1
    categories = ["injection"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.loadctr = 0
	self.list = [ ]

    filter_apinames = set(["ThemeInitApiHook"])

    def on_call(self, call, process):
        if call["api"] == "ThemeInitApiHook":
		self.loadctr += 1
		self.data.append({"Injection" : "%s/%s" % (self.get_argument(call, "ModuleName"), self.get_argument(call, "FunctionName")) })
    def on_complete(self):
	if self.loadctr > 0:
		return True


class CAPE_MoveFileOnReboot(Signature):
    name = "MoveFileOnReboot"
    description = "CAPE detection: Scheduled File Move On Reboot"
    severity = 1
    categories = ["malware"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
	self.match = False

    filter_apinames = set(["MoveFileWithProgressTransactedW", "MoveFileWithProgressTransactedA"])

    def on_call(self, call, process):
        if call["api"] == "MoveFileWithProgressTransactedW" or call["api"] == "MoveFileWithProgressTransactedA":
		if self.get_raw_argument(call, "Flags") == 0x4: # 0x00000004
			self.data.append({"File Move on Reboot" : "Old: %s -> New: %s" % (self.get_argument(call, "ExistingFileName"), self.get_argument(call, "NewFileName")) })
			self.match = True
    def on_complete(self):
	return self.match


