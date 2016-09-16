# Copyright (C) 2015 Kevin Ross
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class BitcoinWallet(Signature):
    name = "infostealer_bitcoin"
    description = "Attempts to access bitcoin wallets"
    severity = 3
    categories = ["infostealer"]
    authors = ["Kevin Ross"]
    minimum = "0.5"

    def run(self):
        indicators = [
            ".*\\\\wallet\.dat$"
        ]
        for indicator in indicators:
            file_match = self.check_file(pattern=indicator, regex=True)
            if file_match:
                return True
        return False
