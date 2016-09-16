# Copyright (C) 2015 Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ModifySecurityCenterWarnings(Signature):
    name = "modify_security_center_warnings"
    description = "Attempts to modify or disable Security Center warnings"
    severity = 3
    categories = ["stealth"]
    authors = ["Kevin Ross"]
    minimum = "1.2"

    def run(self):
        if self.check_write_key(pattern=".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Security\\ Center\\\\.*", regex=True):
            return True

        return False
