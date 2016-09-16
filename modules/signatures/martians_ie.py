# Copyright (C) 2015 Will Metcalf (william.metcalf@gmail.com)#
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
import re

class MartiansIE(Signature):
    name = "ie_martian_children"
    description = "Martian Subprocess Started By IE"
    severity = 3
    categories = ["martians"]
    authors = ["Will Metcalf"]
    minimum = "0.5"

    def go_deeper(self, pdict, result=None):
        if result is None:
            result = []
        result.append(pdict["module_path"].lower())
        for e in pdict["children"]:
            self.go_deeper(e, result)
        return result

    def find_martians(self,ptree,pwlist):
       result = []
       if ptree[0]["children"]:
           children = self.go_deeper(ptree[0])
           for child in children:
               match_found = False
               for entry in pwlist:
                   if entry.match(child):
                       match_found = True
               if not match_found:
                   result.append(child)
       return result

    def run(self):
        self.ie_paths_re = re.compile(r"^c:\\program files\\internet explorer(?:\s\(x86\))?\\iexplore.exe$",re.I)
        #run through re.escape()
        self.white_list_re = ["^C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Adobe\\\\Reader\\ \\d+\\.\\d+\\\\Reader\\\\AcroRd32\\.exe$",
                         "^C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Java\\\\jre\\d+\\\\bin\\\\j(?:avaw?|p2launcher)\\.exe$",
                         "^C\\:\\\\Program Files(?:\s\\(x86\\))?\\\\Microsoft SilverLight\\\\(?:\\d+\\.)+\\d\\\\agcp.exe$",
                         "^C\\:\\\\Windows\\\\System32\\\\ntvdm.exe$",
                        ]
        #means we can be evaded but also means we can have relatively tight paths between 32-bit and 64-bit
        self.white_list_re_compiled = []
        for entry in self.white_list_re:
            self.white_list_re_compiled.append(re.compile(entry,re.I))
        self.white_list_re_compiled.append(self.ie_paths_re)

        # get the path of the initial monitored executable
        self.initialpath = None
        processes = self.results["behavior"]["processtree"]
        if len(processes):
            self.initialpath = processes[0]["module_path"].lower()
        if self.initialpath and self.ie_paths_re.match(self.initialpath) and processes[0].has_key("children"):
           self.martians = self.find_martians(processes,self.white_list_re_compiled)
           if len(self.martians) > 0:
               for martian in self.martians:
                   self.data.append({"ie_martian": martian})
               return True 
        return False
