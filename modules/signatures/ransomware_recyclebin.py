# Copyright (C) 2015 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class RansomwareRecyclebin(Signature):
    name = "ransomware_recyclebin"
    description = "Empties the Recycle Bin, indicative of ransomware"
    severity = 3
    categories = ["ransomware"]
    authors = ["Accuvant"]
    minimum = "1.2"

    def run(self):
        if self.check_delete_file(pattern="C:\\\\RECYCLER\\\\.*", regex=True):
            return True
        return False