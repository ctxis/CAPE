# Copyright (C) 2015 Accuvant, Inc. (bspengler@accuvant.com), KillerInstinct
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import re

from lib.cuckoo.common.abstracts import Signature

class Dyre_APIs(Signature):
    name = "dyre_behavior"
    description = "Exhibits behavior characteristic of Dyre malware"
    severity = 3
    confidence = 90
    categories = ["banker", "trojan"]
    families = ["dyre", "mini-dyre"]
    authors = ["Accuvant", "KillerInstinct"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.cryptoapis = False
        self.networkapis = set()

    filter_apinames = set(["CryptHashData", "HttpOpenRequestA"])

    def on_call(self, call, process):
        if call["api"] == "CryptHashData":
            buf = self.get_argument(call, "Buffer")
            if buf == "qwererthwebfsdvjaf+\\x00":
                self.cryptoapis = True
        elif call["api"] == "HttpOpenRequestA":
            buf = self.get_argument(call, "Path")
            if len(buf) > 10:
                self.networkapis.add(buf)

        return None

    def on_complete(self):
        cryptoret = False
        networkret = False
        campaign = set()

        # Crypto API check
        if self.cryptoapis:
            cryptoret = True
        # C2 Beacon check
        if self.networkapis:
            # Gather computer names (should only ever be one honestly)
            compnames = set()
            if "behavior" in self.results:
                if "processes" in self.results["behavior"]:
                    for proc in self.results["behavior"]["processes"]:
                        if "environ" in proc:
                            if proc["environ"] and "ComputerName" in proc["environ"]:
                                compnames.add(proc["environ"]["ComputerName"])
            for httpreq in self.networkapis:
                # Generate patterns (should only ever be one per indicator)
                for cname in compnames:
                    indicators = [
                        "/(\d{4}[a-z]{2}\d{2})/" + cname + "_",
                        "/([^/]+)/" + cname + "/\d+/\d+/\d+/$",
                    ]
                    for indicator in indicators:
                        buf = re.match(indicator, httpreq)
                        if buf:
                            networkret = True
                            campaign.add(buf.group(1))

        # Check if there are any winners
        if cryptoret or networkret:
            if cryptoret and networkret:
                self.confidence = 100
                self.description = "Exhibits behaviorial and network characteristics of Upatre+Dyre/Mini-Dyre malware"
                for camp in campaign:
                    self.data.append({"Campaign": camp})
                return True

            elif networkret:
                self.description = "Exhibits network behavior characteristic of Upatre+Dyre/Mini-Dyre malware"
                for camp in campaign:
                    self.data.append({"Campaign": camp})
                return True

            elif cryptoret:
                return True

        return False
