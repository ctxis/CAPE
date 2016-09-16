# Copyright (C) 2015 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class StealthHiddenReg(Signature):
    name = "stealth_hiddenreg"
    description = "Attempts to modify Explorer settings to prevent hidden files from being displayed"
    severity = 3
    categories = ["stealth"]
    authors = ["Accuvant"]
    minimum = "1.2"

    def run(self):
        reg_indicators = [
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced\\\\Hidden$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Advanced\\\\ShowSuperHidden$",
        ]

        for indicator in reg_indicators:
            reg_match = self.check_write_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                return True
        return False
