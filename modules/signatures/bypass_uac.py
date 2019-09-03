# Copyright (C) 2019 Kevin Ross
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

class UACBypassEventvwr(Signature):
    name = "uac_bypass_eventvwr"
    description = "Uses eventvwr technique to bypass User Access Control (UAC)"
    severity = 3
    confidence = 100
    categories = ["uac"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    references = ["https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/"]
    ttp = ["T1088"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.eventvrw = False
        self.ret = False

    filter_apinames = set(["CreateProcessInternalW", "RegQueryValueExA", "RegQueryValueExW"])

    def on_call(self, call, process):
        if call["api"].startswith("RegQueryValueEx"):
            pname = process["process_name"]
            if pname.lower() == "eventvwr.exe":
                fullname = self.get_argument(call, "FullName")
                data = self.get_argument(call, "Data")
                if "\classes\mscfile\shell\open\command" in fullname.lower():
                    self.eventvrw = True
                    self.data.append({"reg_query_name": fullname })
                    self.data.append({"reg_query_data": data })

        if call["api"] == "CreateProcessInternalW":
            pname = process["process_name"]
            if pname.lower() == "eventvwr.exe" and self.eventvrw:
                cmdline = self.get_argument(call, "CommandLine")
                if ("mmc " in cmdline.lower() or "mmc.exe" in cmdline.lower()) and "eventvwr.msc" in cmdline.lower():
                    self.data.append({"cmdline": cmdline })
                    self.ret = True   

    def on_complete(self):
        return self.ret
