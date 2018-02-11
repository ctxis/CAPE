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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class OfficeAnamalousFeature(Signature):
    name = "office_anomalous_feature"
    description = "The office file contains anomalous features"
    severity = 2
    categories = ["office"]
    authors = ["Kevin Ross"]
    minimum = "1.3"

    def run(self):

        known_malicious_authors = [
            "Adder",
            "Alex",
            "Microsoft Office",
            "nigan",
            "Nigan",
        ]

        package = self.results["info"]["package"]

        ret = False

        if package != "xls" and "static" in self.results and "office" in self.results["static"]:
            if "Metadata" in self.results["static"]["office"]:
                if "SummaryInformation" in self.results["static"]["office"]["Metadata"]:
                    words = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["num_words"]
                    if words == "0" or words == "None":
                        self.data.append({"content" : "The file appears to have no content."})
                        
        if package != "xls" and "static" in self.results and "office" in self.results["static"]:
            if "Metadata" in self.results["static"]["office"]:
                if "SummaryInformation" in self.results["static"]["office"]["Metadata"]:
                    pages = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["num_pages"]
                    if pages == "0" or pages == "None":
                        self.data.append({"no_pages" : "The file appears to have no pages potentially caused by it being malformed or intentionally corrupted"})

        if "static" in self.results and "office" in self.results["static"]:
            if "Metadata" in self.results["static"]["office"]:
                if "SummaryInformation" in self.results["static"]["office"]["Metadata"]:
                    edittime = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["total_edit_time"]
                    createtime = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["create_time"]
                    lastsaved = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["last_saved_time"]
                    if edittime > 0 and createtime == "None" and lastsaved == "None":
                        self.data.append({"creation_anomaly" : "The file appears to have an edit time yet has no creation time or last saved time. This can be a sign of an automated document creation kit."})

        if "static" in self.results and "office" in self.results["static"]:
            if "Metadata" in self.results["static"]["office"]:
                if "SummaryInformation" in self.results["static"]["office"]["Metadata"]:
                    author = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["author"]
                    lastauthor = self.results["static"]["office"]["Metadata"]["SummaryInformation"]["last_saved_by"]
                    numerical_author = re.compile("^[0-9]{1,}$")
                    for malicious_author in known_malicious_authors:
                        if author == malicious_author:
                            self.data.append({"malicious_author" : "The file appears to have been created by a known fake author indicative of an automated document creation kit."})

                    if numerical_author.match(author):
                        self.data.append({"numerical_author" : "The file author is numerical rather than a word/name indicative of an automated document creation kit."})

                    if re.search("[0-9]{1}", author) and re.search("[A-Z]{1}", author):
                        if len(author) < 6 and re.match("^[a-zA-Z0-9]{1,5}$", author):
                            self.data.append({"short_author_format" : "The file author is a short text string yet contains numerical and upper case characters indicative of an automated document creation kit."})
                        if len(author) > 5 and re.match("^[a-zA-Z0-9].*[A-Z].*$", author):
                           if re.match("^[a-zA-Z0-9]{6,}$", author):
                               self.data.append({"author_format" : "The file author contains a mix of numerical and upper case characters in an unlikely pattern indicative of an automated document creation kit."})

                    if numerical_author.match(lastauthor):
                        self.data.append({"numerical_last_saved" : "The file was last saved by a numerical author rather than a word/name indicative of an automated document creation kit."})

                    if re.search("[0-9]{1}", lastauthor) and re.search("[A-Z]{1}", lastauthor):
                        if len(lastauthor) < 6 and re.match("^[a-zA-Z0-9]{1,5}$", lastauthor):
                            self.data.append({"short_last_saved_format" : "The file was last saved by an author with short text string containing numerical and upper case characters indicative of an automated document creation kit."})

                        if len(lastauthor) > 5 and re.match("^[a-zA-Z0-9].*[A-Z].*$", lastauthor):
                           if re.match("^[a-zA-Z0-9]{6,}$", lastauthor):
                               self.data.append({"last_saved_format" : "The file was last saved by an author containing a mix of numerical and upper case characters in an unlikely pattern indicative of an automated document creation kit."})

            
        if self.data:
            ret = True

        return ret
