# Copyright (C) 2016 Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesWindowsDefender(Signature):
    name = "disables_windows_defender"
    description = "Attempts to disable Windows Defender"
    severity = 3
    categories = ["generic"]
    authors = ["Brad Spengler"]
    minimum = "1.2"

    def run(self):
        keys = [
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Windows\\ Defender\\\\.*",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Windows\\ Defender\\\\.*",
            ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\services\\\\WinDefend\\\\.*",
        ]
        for check in keys:
            if self.check_write_key(pattern=check, regex=True):
                return True

        return False

