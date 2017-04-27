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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class Office_Macro(Signature):
    name = "office_macro"
    description = "The office file has a macro."
    severity = 2
    categories = ["office"]
    authors = ["KillerInstinct","Kevin Ross"]
    minimum = "1.3"

    def run(self):
        package = self.results["info"]["package"]

        ret = False
        if "static" in self.results and "office" in self.results["static"]:
            # 97-2003 OLE and 2007+ XML macros
            if "Macro" in self.results["static"]["office"]:
                if "Code" in self.results["static"]["office"]["Macro"]:
                    ret = True
                    total = len(self.results["static"]["office"]["Macro"]["Code"])
                    if total > 1:
                        self.description = "The office file has %s macros." % str(total)
            # 97-2003 XML macros
            if not ret and "strings" in self.results:
                header = False
                for line in self.results["strings"]:
                    if "<?xml" in line:
                        header = True
                    if header and 'macrosPresent="yes"' in line:
                        ret = True
                        self.description = "The office file has an MSO/ActiveMime based macro."
                        self.severity = 3
                        break

        # Check for known lures
        if ret and "strings" in self.results:
            lures = ["bank account",
                     "enable content",
                     "tools > macro",
                     "macros must be enabled",
                     "enable macro",
                    ]
            positives = list()
            for string in self.results["strings"]:
                for lure in lures:
                    if lure in string.lower():
                        if string not in positives:
                            positives.append(string)
                            self.weight += 1

            if positives != []:
                self.severity = 3
                self.description += " The file also appears to have strings indicating common phishing lures."
                for positive in positives:
                    self.data.append({"Lure": positive})

        # Increase severity on office documents with suspicious characteristics
        if ret and package != "xls" and "static" in self.results and "office" in self.results["static"]:
            if "Metadata" in self.results["static"]["office"]:
                if "SummaryInformation" in self.results["static"]["office"]["Metadata"]:
                    words = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["num_words"]
                    if words == "0" or words == "None":
                        self.severity = 3
                        self.weight += 2
                        self.data.append({"content" : "The file appears to have no content."})
                        
        if ret and package != "xls" and "static" in self.results and "office" in self.results["static"]:
            if "Metadata" in self.results["static"]["office"]:
                if "SummaryInformation" in self.results["static"]["office"]["Metadata"]:
                    pages = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["num_pages"]
                    if pages == "0" or pages == "None":
                        self.severity = 3
                        self.weight += 2
                        self.data.append({"no_pages" : "The file appears to have no pages potentially caused by it being malformed or intentionally corrupted"})

        if ret and "static" in self.results and "office" in self.results["static"]:
            if "Metadata" in self.results["static"]["office"]:
                if "SummaryInformation" in self.results["static"]["office"]["Metadata"]:
                    author = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["author"]
                    lastauthor = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["last_saved_by"]
                    known_authors = ["Alex","Microsoft Office","Adder"]
                    numerical_author = re.compile("^[0-9]{1,}$")
                    for known_authors in known_authors:
                        if author == known_authors:
                            self.severity = 3
                            self.weight += 2
                            self.data.append({"malicious_author" : "The file appears to have been created by a known fake author indicative of an automated document creation kit."})

                    if numerical_author.match(author):
                        self.severity = 3
                        self.weight += 2
                        self.data.append({"numerical_author" : "The file author is numerical rather than a word/name indicative of an automated document creation kit."})

                    if re.search("[0-9]{1}", author) and re.search("[A-Z]{1}", author):
                        if len(author) < 6 and re.match("^[a-zA-Z0-9]{1,5}$", author):
                            self.severity = 3
                            self.weight += 2
                            self.data.append({"short_author_format" : "The file author is a short text string yet contains numerical and upper case characters indicative of an automated document creation kit."})
                        if len(author) > 5 and re.match("^[a-zA-Z0-9].*[A-Z].*$", author):
                           if re.match("^[a-zA-Z0-9]{6,}$", author):
                               self.data.append({"author_format" : "The file author contains a mix of numerical and upper case characters in an unlikely pattern indicative of an automated document creation kit."})

                    if numerical_author.match(lastauthor):
                        self.severity = 3
                        self.weight += 2
                        self.data.append({"numerical_last_saved" : "The file was last saved by a numerical author rather than a word/name indicative of an automated document creation kit."})

                    if re.search("[0-9]{1}", lastauthor) and re.search("[A-Z]{1}", lastauthor):
                        if len(lastauthor) < 6 and re.match("^[a-zA-Z0-9]{1,5}$", lastauthor):
                            self.severity = 3
                            self.weight += 2
                            self.data.append({"short_last_saved_format" : "The file was last saved by an author with short text string containing numerical and upper case characters indicative of an automated document creation kit."})

                        if len(lastauthor) > 5 and re.match("^[a-zA-Z0-9].*[A-Z].*$", lastauthor):
                           if re.match("^[a-zA-Z0-9]{6,}$", lastauthor):
                               self.data.append({"last_saved_format" : "The file was last saved by an author containing a mix of numerical and upper case characters in an unlikely pattern indicative of an automated document creation kit."})

        return ret
