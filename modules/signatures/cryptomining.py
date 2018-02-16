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

class CryptominingStratumCommand(Signature):
    name = "cyrptomining_stratum_command"
    description = "A cryptomining command containing a stratum protocol address was executed"
    severity = 3
    confidence = 90
    categories = ["cryptomining"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    references = ["blog.talosintelligence.com/2018/01/malicious-xmr-mining.html"]

    def run(self):
        ret = False
        for cmdline in self.results["behavior"]["summary"]["executed_commands"]:
            if "stratum+tcp://" in cmdline.lower():
                self.data.append({"command" : cmdline })
                ret = True

        return ret

class CryptominingCommand(Signature):
    name = "cyrptomining_command"
    description = "A possible cryptomining command was executed"
    severity = 3
    confidence = 50
    categories = ["cryptomining"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    references = ["blog.talosintelligence.com/2018/01/malicious-xmr-mining.html"]

    def run(self):
        commands = [
            "--donate-level=",
            "--max-cpu-usage=",
        ]

        ret = False
        for cmdline in self.results["behavior"]["summary"]["executed_commands"]:
            lower = cmdline.lower()
            if "-o " in lower and "-u " in lower and "-p " in lower:
                self.data.append({"command" : cmdline })
                ret = True
            else:
                for command in commands:
                    if command in lower:
                        self.data.append({"command" : cmdline })
                        ret = True

        return ret
