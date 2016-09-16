# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Authenticode(Signature):
    name = "static_authenticode"
    description = "Presents an Authenticode digital signature"
    severity = 1
    categories = ["static"]
    authors = ["Accuvant"]
    minimum = "1.2"

    def run(self):
        found_sig = False

        if "static" in self.results:
            if "digital_signers" in self.results["static"]:
                for sign in self.results["digital_signers"]:
                    self.data.append(sign)
                    found_sig = True

        return found_sig