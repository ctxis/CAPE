# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
#
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

from lib.cuckoo.common.abstracts import Signature

class StackPivot(Signature):
    name = "stack_pivot"
    description = "Stack pivoting was detected when using a critical API"
    severity = 3
    confidence = 100
    categories = ["exploit"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.procs = set()
        self.processes = [
            "acrobat.exe",
            "acrord32.exe",
            "chrome.exe",
            "eqnedt32.exe",
            "excel.exe",
            "firefox.exe",
            "hwp.exe",
            "iexplore.exe",
            "outlook.exe",
            "powerpnt.exe",
            "winword.exe",
        ]

    filter_apinames = set(["NtCreateFile", "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "VirtualProtectEx", "NtWriteVirtualMemory", "NtWow64WriteVirtualMemory64", "WriteProcessMemory", "NtMapViewOfSection", "CreateProcessInternalW", "URLDownloadToFileW"])

    def on_call(self, call, process):
        if process["process_name"].lower() in self.processes:
            pivot = self.get_argument(call, "StackPivoted")
            if pivot == None:
                return
            if pivot == "yes":
                self.procs.add(process["process_name"] + ":" + str(process["process_id"]))

    def on_complete(self):
        for proc in self.procs:
            self.data.append({"process" : proc})

        if self.data:
            return True
        else:
            return False
