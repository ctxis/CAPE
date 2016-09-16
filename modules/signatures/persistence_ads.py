# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class ADS(Signature):
    name = "persistence_ads"
    description = "Attempts to interact with an Alternate Data Stream (ADS)"
    severity = 3
    categories = ["persistence", "ads"]
    authors = ["nex"]
    minimum = "0.5"

    def run(self):
        result = False
        for file_path in self.results["behavior"]["summary"]["files"]:
            if len(file_path) <= 3:
                continue

            if ":" in file_path.split("\\")[-1]:
                if not file_path.lower().startswith("c:\\dosdevices\\") or not file_path[:-1] == ":":
                    self.data.append({"file" : file_path})
                    result = True

        return result
