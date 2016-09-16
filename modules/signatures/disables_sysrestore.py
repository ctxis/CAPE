# Copyright (C) 2015 Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesSystemRestore(Signature):
    name = "disables_system_restore"
    description = "Attempts to disable System Restore"
    severity = 3
    categories = ["ransomware"]
    authors = ["Kevin Ross"]
    minimum = "1.2"

    def run(self):
        if self.check_write_key(pattern=".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\SystemRestore\\\\DisableSR$", regex=True):
            return True

        return False

