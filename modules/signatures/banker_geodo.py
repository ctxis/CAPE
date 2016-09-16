# Copyright (C) 2014 Accuvant, Inc. (bspengler@accuvant.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class Geodo(Signature):
    name = "geodo_banking_trojan"
    description = "Geodo Banking Trojan"
    severity = 3
    categories = ["Banking", "Trojan"]
    families = ["Geodo","Emotet"]
    authors = ["Accuvant"]
    minimum = "1.2"
    evented = True

    def run(self):
        ip_indicators = [
                "204.93.183.196",
                "50.31.146.109",
                "5.135.208.53",
                "103.25.59.120",
                "50.97.99.2",
                "173.203.112.215",
                "27.124.127.10",
                "78.129.181.191",
                "204.197.254.94",
                "50.31.146.134",
        ]

        match_file = self.check_file(pattern=".*\\\\Application\\ Data\\\\Microsoft\\\\[a-z]{3}(api32|audio|bios|boot|cap32|common|config|crypt|edit32|error|mgr32|serial|setup|share|sock|system|update|video|windows)\.exe$", regex=True, all=True)
        match_batch_file = self.check_file(pattern=".*\\\\Application\\ Data\\\\\d{1,10}\.bat$", regex=True, all=True)
        match_runkey = self.check_key(pattern=".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\[a-z]{3}(api32|audio|bios|boot|cap32|common|config|crypt|edit32|error|mgr32|serial|setup|share|sock|system|update|video|windows)\.exe$", regex=True, all=True)
        match_otherkey = self.check_key(pattern=".*\\\\Microsoft\\\\Office\\\\Common\\\\(?P<hex>[A-F0-9]+)\\\\(?P=hex)(CS|PS|SS|RS)", regex=True, all=True)
        match_mutex = self.check_mutex(pattern="^[A-F0-9]{1,8}(I|M|RM)$", regex=True, all=True)
        found_match_ip = False
        found_match_url = False
        if match_file:
            for match in match_file:
                self.data.append({"file": match})
        if match_batch_file:
            for match in match_batch_file:
                self.data.append({"batchfile": match})
        if match_runkey:
            for match in match_runkey:
                self.data.append({"runkey": match})
        if match_otherkey:
            for match in match_otherkey:
                self.data.append({"otherkey": match})
        if match_mutex:
            for match in match_mutex:
                self.data.append({"mutex": match})
        for ip_indicator in ip_indicators:
            match_ip = self.check_ip(pattern=ip_indicator)
            if match_ip:
                self.data.append({"ip": match_ip})
                found_match_ip = True
            match_url = self.check_url(pattern="http://" + re.escape(ip_indicator) + ":8080/[a-f0-9]{1,8}/[a-f0-9]{1,8}/", regex=True,all=True)
            if match_url:
                for match in match_url:
                    self.data.append({"url": match})
                found_match_url = True

        if match_file or match_batch_file or match_mutex or found_match_ip or found_match_url or match_runkey or match_otherkey:
                return True

        return False
