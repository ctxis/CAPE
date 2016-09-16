# Copyright (C) 2015 KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re
from lib.cuckoo.common.abstracts import Signature

class EncryptedIOC(Signature):
    name = "encrypted_ioc"
    description = "At least one IP Address, Domain, or File Name was found in a crypto call"
    severity = 2
    categories = ["crypto"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.iocs = []

    # May add to this later
    filter_apinames = set(["CryptHashData"])

    def on_call(self, call, process):
        if call["api"] == "CryptHashData":
            self.iocs.append(self.get_raw_argument(call, "Buffer"))
        return None

    def on_complete(self):
        matches = [
            r'(https?:\/\/)?([\da-z\.-]+)\.([0-9a-z\.]{2,6})(:\d{1,5})?([\/\w\.-]*)\/?',
        ]
        dedup = list()
        extracted_config = False
        for potential_ioc in self.iocs:
            for entry in matches:
                all_matches = re.findall(entry, potential_ioc)
                if all_matches:
                    extracted_config = True
                    for buf in all_matches:
                        ioc = ""
                        idx = 0
                        for tmp in buf:
                            idx += 1
                            if tmp == '':
                                pass
                            # Account for match groups and the second
                            # (or third depending on match) period as a
                            # delimiter. We need to add it in manually.
                            if idx == 2:
                                ioc += tmp + "."
                            else:
                                ioc += tmp
                        if ioc not in dedup:
                            dedup.append(ioc)
        if dedup:
            for ioc in dedup:
                self.data.append({"ioc": ioc})

        return extracted_config
