# Copyright (C) 2019 ditekshen
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

class RemcosFiles(Signature):
    name = "remcos_files"
    description = "Creates known Remcos directories and/or files"
    severity = 3
    categories = ["RAT"]
    families = ["Remcos"]
    authors = ["ditekshen"]
    minimum = "0.5"

    def run(self):
        remcos_files = False
        
        indicators = [
            ".*\\\\AppData\\\\Roaming\\\\remcos\\\\",
            ".*\\\\AppData\\\\Roaming\\\\remcos\\\\logs\.dat$",
        ]

        for indicator in indicators:
            file_match = self.check_file(pattern=indicator, regex=True)
            if file_match:
                for match in file_match:
                    self.data.append({"file": match})
                remcos_files = True

        return remcos_files