# Copyright (C) 2012, 2015 Michael Boman (@mboman), Accuvant, Inc. (bspengler@accuvant.com)
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

from lib.cuckoo.common.abstracts import Signature

class KnownVirustotal(Signature):
    name = "antivirus_virustotal"
    description = "File has been identified by at least one Antivirus on VirusTotal as malicious"
    confidence = 50
    severity = 2
    categories = ["antivirus"]
    authors = ["Michael Boman", "nex"]
    minimum = "0.5"

    def run(self):
        if "virustotal" in self.results:
            if "positives" in self.results["virustotal"]:
                positives = self.results["virustotal"]["positives"]
                if positives > 0:
                    if positives > 10:
                        self.description = "File has been identified by at least ten Antiviruses on VirusTotal as malicious"
                        self.severity = 3
                        self.confidence = 100
                        self.weight = positives
                    for engine, signature in self.results["virustotal"]["scans"].items():
                        if signature["detected"]:
                            self.data.append({engine : signature["result"]})
                    return True

        return False
