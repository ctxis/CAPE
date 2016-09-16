# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class AntiDBGWindows(Signature):
    name = "antidbg_windows"
    description = "Checks for the presence of known windows from debuggers and forensic tools"
    severity = 3
    categories = ["anti-debug"]
    authors = ["nex", "KillerInstinct"]
    minimum = "1.2"
    evented = True

    filter_categories = set(["windows"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = dict()

    def on_call(self, call, process):
        indicators = [
            "OLLYDBG",
            "WinDbgFrameClass",
            "pediy06",
            "GBDYLLO",
            "RegmonClass",
            "FilemonClass",
            "Regmonclass",
            "Filemonclass",
            "PROCMON_WINDOW_CLASS",
            "File Monitor - Sysinternals: www.sysinternals.com",
            "Process Monitor - Sysinternals: www.sysinternals.com",
            "Registry Monitor - Sysinternals: www.sysinternals.com",
            "18467-41",
        ]

        for indicator in indicators:
            if self.check_argument_call(call, pattern=indicator, category="windows"):
                if process["process_name"] not in self.ret.keys():
                    self.ret[process["process_name"]] = list()
                window = self.get_argument(call, "ClassName")
                if window == "0":
                    window = self.get_argument(call, "WindowName")
                if window not in self.ret[process["process_name"]]:
                    self.ret[process["process_name"]].append(window)
                return None

    def on_complete(self):
        if self.ret:
            for proc in self.ret.keys():
                for value in self.ret[proc]:
                    self.data.append({"Window": value})
            return True
        return False
