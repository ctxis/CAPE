# Copyright (C) 2014 glysbays, Accuvant, Inc. (bspengler@accuvant.com)
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

class InjectionRUNPE(Signature):
    name = "injection_runpe"
    description = "CAPE detection: Injection (Process Hollowing)"
    severity = 3
    categories = ["injection"]
    authors = ["glysbaysb", "Accuvant"]
    minimum = "1.2"
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
            self.lastprocess = process

        if call["api"] == "CreateProcessInternalW":
            self.process_handles.add(self.get_argument(call, "ProcessHandle"))
            self.thread_handles.add(self.get_argument(call, "ThreadHandle"))
        elif (call["api"] == "NtUnmapViewOfSection" or call["api"] == "NtAllocateVirtualMemory") and self.sequence == 0:
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.sequence = 1
        elif call["api"] == "NtGetContextThread" and self.sequence == 0:
           if self.get_argument(call, "ThreadHandle") in self.thread_handles:
                self.sequence = 1
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "WriteProcessMemory" or call["api"] == "NtMapViewOfSection") and (self.sequence == 1 or self.sequence == 2):
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.sequence = self.sequence + 1
        elif (call["api"] == "NtSetContextThread") and (self.sequence == 1 or self.sequence == 2):
            if self.get_argument(call, "ThreadHandle") in self.thread_handles:
                self.sequence = self.sequence + 1
        elif call["api"] == "NtResumeThread" and (self.sequence == 2 or self.sequence == 3):
            if self.get_argument(call, "ThreadHandle") in self.thread_handles:
                return True
        elif call["api"] == "NtResumeProcess" and (self.sequence == 2 or self.sequence == 3):
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                return True
