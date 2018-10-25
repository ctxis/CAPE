# Copyright (C) 2018 Kevin Ross
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

class RTFExploitStatic(Signature):
    name = "rtf_exploit_static"
    description = "The RTF file contains an object with potential exploit code"
    severity = 3
    confidence = 100
    categories = ["exploit", "office", "rtf", "static"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        ret = False
        if "office_rtf" in self.results["static"]:
            for key in self.results["static"]["office_rtf"]:
                for block in self.results["static"]["office_rtf"][key]:
                    if "CVE" in block:
                        index = block["index"]
                        cve = block["CVE"]
                        if len(cve) > 0:
                            self.data.append({"cve" : "Object %s index %s contains %s" % (key,index,cve)})
                            ret = True
                    
        return ret
