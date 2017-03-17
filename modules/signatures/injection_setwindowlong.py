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
# 
# import struct
# from lib.cuckoo.common.abstracts import Signature

from lib.cuckoo.common.abstracts import Signature

class InjectionSWL(Signature):
    name = "injection_setwindowlong"
    description = "CAPE detection: Injection with SetWindowLong in a remote process"
    severity = 3
    categories = ["injection"]
    authors = ["kevoreilly"]
    minimum = "1.0"
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
