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

class CheckIP(Signature):
    name = "network_doh"
    description = "Queries or connects to DNS-Over-HTTP domain or IP address"
    severity = 2
    categories = ["network"]
    authors = ["ditekshen"]
    minimum = "1.2"

    def run(self):
        domain_indicators = [
            "cloudflare-dns.com",
            "dns9.quad9.net",
            "dns10.quad9.net",
            "doh.cleanbrowsing.org",
            "dns.dnsoverhttps.net",
            "doh.crypto.sx",
            "doh.powerdns.org",
            "doh-jp.blahdns.com",
            "dns.dns-over-https.com",
            "doh.securedns.eu",
            "dns.rubyfish.cn",
            "doh.dnswarden.com",
            "doh.captnemo.in",
            "doh.tiar.app",
            "one.one.one.one",
        ]

        ip_indicators = [
            "1.0.0.1",
            "1.1.1.1",
            "104.16.248.249",
            "104.16.249.249",
            "104.236.178.232",
            "104.28.0.106",
            "104.28.1.106",
            "108.61.201.119",
            "116.203.35.255",
            "116.203.70.156",
            "118.89.110.78",
            "136.144.215.158",
            "139.59.48.222",
            "146.185.167.43",
            "149.112.112.10",
            "149.112.112.9",
            "185.228.168.10",
            "185.228.168.168",
            "45.32.105.4",
            "45.32.253.116",
            "45.77.124.64",
            "47.96.179.163",
            "9.9.9.10",
            "9.9.9.9",
        ]

        found_matches = False
        
        for indicator in domain_indicators:
            if self.check_domain(pattern=indicator):
                self.data.append({"domain" : indicator})
                found_matches = True

        for indicator in ip_indicators:
            if self.check_ip(pattern=indicator):
                self.data.append({"ip" : indicator})
                found_matches = True

        return found_matches
