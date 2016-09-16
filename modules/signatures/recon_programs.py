# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class InstalledApps(Signature):
    name = "recon_programs"
    description = "Collects information about installed applications"
    severity = 3
    categories = ["recon"]
    authors = ["Accuvant"]
    minimum = "1.2"

    def run(self):
        if self.check_read_key(pattern= ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall.*", regex=True):
            return True

        return False