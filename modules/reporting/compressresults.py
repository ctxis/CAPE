# Copyright (C) 2017 Marirs.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
from bson import ObjectId
from bson.binary import Binary
import zlib
from lib.cuckoo.common.abstracts import Report
import logging

log = logging.getLogger(__name__)

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)

class CompressResults(Report):
    """Compresses certain results in the json dict before
        saving into MongoDB. This helps with the restriction 
        of MongoDB document size of 16MB.
    """
    order = 9997
    # the order will change here when the order of
    # elastic & mongo python files order changes

    def run(self, results):

        # compress CAPE
        if "CAPE" in results:
            cape_json = json.dumps(results["CAPE"]).encode('utf8')
            compressed_CAPE = zlib.compress(cape_json)
            results["CAPE"] = Binary(compressed_CAPE)

        # compress procdump
        if "procdump" in results:
            procdump_json = json.dumps(results["procdump"]).encode('utf8')
            compressed_procdump = zlib.compress(procdump_json)
            results["procdump"] = Binary(compressed_procdump)

        # compress behaviour analysis (enhanced & summary)
        if "enhanced" in results["behavior"]:
            compressed_behavior_enhanced = zlib.compress(JSONEncoder().encode(results["behavior"]["enhanced"]).encode('utf8'))
            results["behavior"]["enhanced"] = Binary(compressed_behavior_enhanced)

        if "summary" in results["behavior"]:
            compressed_behavior_summary = zlib.compress(JSONEncoder().encode(results["behavior"]["summary"]).encode('utf8'))
            results["behavior"]["summary"] = Binary(compressed_behavior_summary)
