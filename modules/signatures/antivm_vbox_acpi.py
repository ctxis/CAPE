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

class VBoxDetectACPI(Signature):
    name = "antivm_vbox_acpi"
    description = "Detects VirtualBox using ACPI tricks"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    filter_apinames = set(["RegOpenKeyExA", "RegOpenKeyExW", "RegEnumKeyExA", "RegEnumKeyExW"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.opened = False
            self.handle = ""
            self.lastprocess = process

        # First I check if the malware opens the releavant registry key.
        if call["api"].startswith("RegOpenKeyEx"):
            # Store the number of arguments matched.
            args_matched = 0
            # Store the handle used to open the key.
            self.handle = ""
            # Check if the registry is HKEY_LOCAL_MACHINE.
            if self.get_argument(call,"Registry") == "0x80000002":
                args_matched += 1
            # Check if the subkey opened is the correct one.
            elif self.get_argument(call,"SubKey")[:14].upper() == "HARDWARE\\ACPI\\":
                # Since it could appear under different paths, check for all of them.
                if self.get_argument(call,"SubKey")[14:18] in ["DSDT", "FADT", "RSDT"]:
                    if self.get_argument(call,"SubKey")[18:] == "\\VBOX__":
                        return True
                    else:
                        args_matched += 1
            # Store the generated handle.
            else:
                self.handle = self.get_argument(call,"Handle")
            
            # If both arguments are matched, I consider the key to be successfully opened.
            if args_matched == 2:
                self.opened = True
        # Now I check if the malware verified the value of the key.
        elif call["api"].startswith("RegEnumKeyEx"):
            # Verify if the key was actually opened.
            if not self.opened:
                return

            # Verify the arguments.
            args_matched = 0
            if self.get_argument(call,"Handle") == self.handle:
                args_matched += 1
            elif self.get_argument(call,"Name") == "VBOX__":
                args_matched += 1

            # Finally, if everything went well, I consider the signature as matched.
            if args_matched == 2:
                return True
