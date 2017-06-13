# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import json
import six
import imagehash
import zlib

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File
from bson import ObjectId
from bson.binary import Binary
from PIL import Image

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure, InvalidDocument
    HAVE_MONGO = True
except ImportError:
    HAVE_MONGO = False

log = logging.getLogger(__name__)

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)

def deduplicate_images(userpath, hashfunc = imagehash.average_hash):
    """
    remove duplicate images from a path
    :userpath: path of the image files
    :hashfunc: type of image hashing method
    """
    def is_image(filename):
        img_ext = [".jpg", ".png", ".gif", ".bmp", ".gif"]
        f = filename.lower()
        return any(f.endswith(ext) for ext in img_ext)

    #log.debug("Deduplicate images...{}".format(userpath))
    """
    Available hashs functions:
        ahash:      Average hash
        phash:      Perceptual hash
        dhash:      Difference hash
        whash-haar: Haar wavelet hash
        whash-db4:  Daubechies wavelet hash
    """
    dd_img_set = []

    image_filenames = [os.path.join(userpath, path) for path in os.listdir(userpath) if is_image(path)]
    images = {}
    for img in sorted(image_filenames):
        hash = hashfunc(Image.open(img))
        images[hash] = images.get(hash, []) + [img]
    for k, img_list in six.iteritems(images):
        #if len(img_list) > 1:
        dd_img_set.append(os.path.basename(img_list[0]))
            #print(",".join(img_list))
    dd_img_set.sort()
    return dd_img_set

class MongoDB(Report):
    """Stores report in MongoDB."""
    order = 9999

    # Mongo schema version, used for data migration.
    SCHEMA_VERSION = "1"

    def connect(self):
        """Connects to Mongo database, loads options and set connectors.
        @raise CuckooReportError: if unable to connect.
        """
        host = self.options.get("host", "127.0.0.1")
        port = self.options.get("port", 27017)
        db = self.options.get("db", "cuckoo")

        try:
            self.conn = MongoClient(host, port)
            self.db = self.conn[db]
        except TypeError:
            raise CuckooReportError("Mongo connection port must be integer")
        except ConnectionFailure:
            raise CuckooReportError("Cannot connect to MongoDB")

    def debug_dict_size(self, dct):
        if type(dct) == list:
            dct = dct[0]

        totals = dict((k, 0) for k in dct)
        def walk(root, key, val):
            if isinstance(val, dict):
                for k, v in val.iteritems():
                    walk(root, k, v)

            elif isinstance(val, (list, tuple, set)):
                for el in val:
                    walk(root, None, el)

            elif isinstance(val, basestring):
                totals[root] += len(val)

        for key, val in dct.iteritems():
            walk(key, key, val)

        return sorted(totals.items(), key=lambda item: item[1], reverse=True)

    def run(self, results):
        """Writes report.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if fails to connect or write to MongoDB.
        """
        # We put the raise here and not at the import because it would
        # otherwise trigger even if the module is not enabled in the config.
        if not HAVE_MONGO:
            raise CuckooDependencyError("Unable to import pymongo "
                                        "(install with `pip install pymongo`)")

        self.connect()

        # Set mongo schema version.
        # TODO: This is not optimal becuase it run each analysis. Need to run
        # only one time at startup.
        if "cuckoo_schema" in self.db.collection_names():
            if self.db.cuckoo_schema.find_one()["version"] != self.SCHEMA_VERSION:
                CuckooReportError("Mongo schema version not expected, check data migration tool")
        else:
            self.db.cuckoo_schema.save({"version": self.SCHEMA_VERSION})

        # Create a copy of the dictionary. This is done in order to not modify
        # the original dictionary and possibly compromise the following
        # reporting modules.
        report = dict(results)

        if not "network" in report:
            report["network"] = {}

        # Add screenshot paths
        report["shots"] = []
        report["deduplicated_shots"] = []

        hashmethod = "whash-db4"
        if hashmethod == 'ahash':
            hashfunc = imagehash.average_hash
        elif hashmethod == 'phash':
            hashfunc = imagehash.phash
        elif hashmethod == 'dhash':
            hashfunc = imagehash.dhash
        elif hashmethod == 'whash-haar':
            hashfunc = imagehash.whash
        elif hashmethod == 'whash-db4':
            hashfunc = lambda img: imagehash.whash(img, mode='db4')     # sg_052017

        shots_path = os.path.join(self.analysis_path, "shots")
        if os.path.exists(shots_path):
            report["deduplicated_shots"] = [f.replace(".jpg","") for f in deduplicate_images(userpath=shots_path, hashfunc=hashfunc)] #sg_052017
            shots = [shot for shot in os.listdir(shots_path)
                     if shot.endswith(".jpg")]
            for shot_file in sorted(shots):
                shot_path = os.path.join(self.analysis_path, "shots",
                                         shot_file)
                screenshot = File(shot_path)
                if screenshot.valid():
                    # Strip the extension as it's added later 
                    # in the Django view
                    report["shots"].append(shot_file.replace(".jpg", ""))

        # Store chunks of API calls in a different collection and reference
        # those chunks back in the report. In this way we should defeat the
        # issue with the oversized reports exceeding MongoDB's boundaries.
        # Also allows paging of the reports.
        if "behavior" in report and "processes" in report["behavior"]:
            new_processes = []
            for process in report["behavior"]["processes"]:
                new_process = dict(process)

                chunk = []
                chunks_ids = []
                # Loop on each process call.
                for index, call in enumerate(process["calls"]):
                    # If the chunk size is 100 or if the loop is completed then
                    # store the chunk in MongoDB.
                    if len(chunk) == 100:
                        to_insert = {"pid": process["process_id"],
                                     "calls": chunk}
                        chunk_id = self.db.calls.insert(to_insert)
                        chunks_ids.append(chunk_id)
                        # Reset the chunk.
                        chunk = []

                    # Append call to the chunk.
                    chunk.append(call)

                # Store leftovers.
                if chunk:
                    to_insert = {"pid": process["process_id"], "calls": chunk}
                    chunk_id = self.db.calls.insert(to_insert)
                    chunks_ids.append(chunk_id)

                # Add list of chunks.
                new_process["calls"] = chunks_ids
                new_processes.append(new_process)

            # Store the results in the report.
            report["behavior"] = dict(report["behavior"])
            report["behavior"]["processes"] = new_processes

        # Calculate the mlist_cnt for display if present to reduce db load
        if "signatures" in results:
            for entry in results["signatures"]:
                if entry["name"] == "ie_martian_children":
                    report["mlist_cnt"] = len(entry["data"])
                if entry["name"] == "office_martian_children":
                    report["f_mlist_cnt"] = len(entry["data"])

        #Other info we want Quick access to from the web UI
        if results.has_key("virustotal") and results["virustotal"] and results["virustotal"].has_key("positives") and results["virustotal"].has_key("total"):
            report["virustotal_summary"] = "%s/%s" % (results["virustotal"]["positives"],results["virustotal"]["total"])
        if results.has_key("suricata") and results["suricata"]:
            if results["suricata"].has_key("tls") and len(results["suricata"]["tls"]) > 0:
                report["suri_tls_cnt"] = len(results["suricata"]["tls"])
            if results["suricata"].has_key("alerts") and len(results["suricata"]["alerts"]) > 0:
                report["suri_alert_cnt"] = len(results["suricata"]["alerts"])
            if results["suricata"].has_key("files") and len(results["suricata"]["files"]) > 0:
                report["suri_file_cnt"] = len(results["suricata"]["files"])
            if results["suricata"].has_key("http") and len(results["suricata"]["http"]) > 0:
                report["suri_http_cnt"] = len(results["suricata"]["http"])
            if results["suricata"].has_key("ssh") and len(results["suricata"]["ssh"]) > 0:
                report["suri_ssh_cnt"] = len(results["suricata"]["ssh"])
            if results["suricata"].has_key("dns") and len(results["suricata"]["dns"]) > 0:
                report["suri_dns_cnt"] = len(results["suricata"]["dns"])
        
        # Create an index based on the info.id dict key. Increases overall scalability
        # with large amounts of data.
        # Note: Silently ignores the creation if the index already exists.
        self.db.analysis.create_index("info.id", background=True)

	# In case data exceeds mongodb limit of 16MB,
	# be prepared to save into a json file
	save_json_analyses = os.path.join(self.analysis_path, "analyses.json")
	json_data = JSONEncoder().encode(report)

	# Compress CAPE output
	if "CAPE" in report:
		cape_json = json.dumps(report["CAPE"]).encode('utf8')
        	compressed_CAPE = zlib.compress(cape_json)
        	report["CAPE"] = Binary(compressed_CAPE)
                #log.debug("CAPE output size before compression: {}, after compression: {}".format(len(cape_json), len(compressed_CAPE)))

	# Compress behavioural analysis (enhanced & summary)
	if "enhanced" in report["behavior"]:
		compressed_behavior_enhanced = zlib.compress(JSONEncoder().encode(report["behavior"]["enhanced"]).encode('utf8'))
		report["behavior"]["enhanced"] = Binary(compressed_behavior_enhanced)
	if "summary" in report["behavior"]:
		compressed_behavior_summary = zlib.compress(JSONEncoder().encode(report["behavior"]["summary"]).encode('utf8'))
                report["behavior"]["summary"] = Binary(compressed_behavior_summary)

	# Compress virustotal results
	if "virustotal" in report:
		compressed_vt = zlib.compress(JSONEncoder().encode(report["virustotal"]).encode('utf8'))
        report["virustotal"] = Binary(compressed_vt)	

        # Store the report and retrieve its object id.
        try:
            self.db.analysis.save(report)
        except InvalidDocument as e:
            parent_key, psize = self.debug_dict_size(report)[0]
            child_key, csize = self.debug_dict_size(report[parent_key])[0]
            if not self.options.get("fix_large_docs", False):
                # Just log the error and problem keys
                log.error(str(e))
                log.error("Largest parent key: %s (%d MB)" % (parent_key, int(psize) / 1048576))
                log.error("Largest child key: %s (%d MB)" % (child_key, int(csize) / 1048576))
            else:
                # Delete the problem keys and check for more
                error_saved = True
                while error_saved:
                    log.warn("results['%s']['%s'] deleted due to >16MB size (%dMB)" %
                             (parent_key, child_key, int(psize) / 1048576))

                    if type(report) == list:
                        report = report[0]

                    with open(save_json_analyses, "w") as f:
                        f.write(json_data)
                    log.warn("results['%s']['%s'](%dMB) > saved as %s" %
                             (parent_key, child_key, int(psize) / 1048576, save_json_analyses))

                    del report[parent_key][child_key]
                    try:
                        self.db.analysis.save(report)
                        error_saved = False
                    except InvalidDocument as e:
                        parent_key, psize = self.debug_dict_size(report)[0]
                        child_key, csize = self.debug_dict_size(report[parent_key])[0]
                        log.error(str(e))
                        log.error("Largest parent key: %s (%d MB)" % (parent_key, int(psize) / 1048576))
                        log.error("Largest child key: %s (%d MB)" % (child_key, int(csize) / 1048576))

        self.conn.close()
