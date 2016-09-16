# Copyright (C) 2012-2015 KillerInstinct
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

class Office_Suspicious(Signature):
    name = "office_suspicious"
    description = "The office file created a suspicious child process."
    severity = 3
    categories = ["office"]
    authors = ["KillerInstinct"]
    minimum = "0.5"

    def run(self):
        ret = False

        if "static" in self.results:
            if "Metadata" in self.results["static"]:
                if self.results["static"]["Metadata"]["HasMacros"] == "Yes":
                    if "behavior" in self.results:
                        if "processtree" in self.results["behavior"]:
                            parent = self.results["behavior"]["processtree"][0]
                            parentmod = parent["module_path"]
                            if "children" in parent:
                                c1 = parent["children"]
                                for child in c1:
                                    output = ""
                                    if child["module_path"] != parentmod:
                                        ret = True
                                        output += parent["name"] + " -> " + child["name"]
                                        if "children" in child and child["children"]:
                                            output += " -> " + child["children"][0]["name"]
                                        self.data.append({"Processes": output})

        return ret
