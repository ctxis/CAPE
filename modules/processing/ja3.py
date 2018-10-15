import logging, json
import subprocess

from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

__author__  = "@FernandoDoming"
__version__ = "1.0.0"

class JA3(Processing):

    def run(self):
        self.key = "JA3"

        ja3_cmd  = ["ja3", "-a", "-j", "%s/dump.pcap" % (self.analysis_path)]
        ja3s_cmd = ["ja3s", "-a", "-j", "%s/dump.pcap" % (self.analysis_path)]
        result   = {}

        try:
            p = subprocess.Popen(
                ja3_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            out, err = p.communicate()
            result["client"] = json.loads(out)

        except Exception:
            log.error(
                "Unable to get output from ja3. Command: %s" % " ".join(ja3_cmd)
            )
            result["client"] = {}

        try:
            p = subprocess.Popen(
                ja3s_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            out, err = p.communicate()
            result["server"] = json.loads(out)

        except Exception:
            log.error(
                "Unable to get output from ja3s. Command: %s" % " ".join(ja3s_cmd)
            )
            result["server"] = {}

        return result