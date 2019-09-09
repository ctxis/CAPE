# Copyright (C) 2010-2015 KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys
import shutil
import logging
import argparse

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from datetime import datetime, timedelta

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report

from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.core.database import Database, Task, TASK_REPORTED
from bson.objectid import ObjectId

log = logging.getLogger(__name__)
cfg = Config("reporting")
ccfg = Config("cuckoo")
db = Database()

# Global connections
if cfg.mongodb and cfg.mongodb.enabled:
    from pymongo import MongoClient
    from pymongo.errors import AutoReconnect
    host = cfg.mongodb.get("host", "127.0.0.1")
    port = cfg.mongodb.get("port", 27017)
    mdb = cfg.mongodb.get("db", "cuckoo")

    try:
        results_db = MongoClient(host, port)[mdb]
    except Exception as e:
        log.warning("Unable to connect to MongoDB: %s", str(e))

if cfg.elasticsearchdb and cfg.elasticsearchdb.enabled and not cfg.elasticsearchdb.searchonly:
    from elasticsearch import Elasticsearch
    idx = cfg.elasticsearchdb.index + "-*"
    try:
        es = Elasticsearch(
                hosts = [{
                    "host": cfg.elasticsearchdb.host,
                    "port": cfg.elasticsearchdb.port,
                }],
                timeout = 60,
             )
    except Exception as e:
        log.warning("Unable to connect to ElasticSearch: %s", str(e))

def delete_mongo_data(tid):
    # TODO: Class-ify this or make it a function in utils, some code reuse
    # between this/process.py/django view
    analyses = results_db.analysis.find({"info.id": int(tid)})
    if analyses.count > 0:
        for analysis in analyses:
            log.info("deleting MongoDB data for Task #{0}".format(tid))
            for process in analysis.get("behavior", {}).get("processes", []):
                for call in process["calls"]:
                    results_db.calls.remove({"_id": ObjectId(call)})
            results_db.analysis.remove({"_id": ObjectId(analysis["_id"])})

def delete_elastic_data(tid):
    # TODO: Class-ify this or make it a function in utils, some code reuse
    # between this/process.py/django view
    analyses = es.search(
                   index=fullidx,
                   doc_type="analysis",
                   q="info.id: \"{0}\"".format(task_id)
               )["hits"]["hits"]
    if len(analyses) > 0:
        for analysis in analyses:
            esidx = analysis["_index"]
            esid = analysis["_id"]
            if analysis["_source"]["behavior"]:
                for process in analysis["_source"]["behavior"]["processes"]:
                    for call in process["calls"]:
                        es.delete(
                            index=esidx,
                            doc_type="calls",
                            id=call,
                        )
            es.delete(
                index=esidx,
                doc_type="analysis",
                id=esid,
                )
        log.debug("deleting ElasticSearch data for Task #{0}".format(tid))

def delete_files(curtask, delfiles):
    delfiles_list = delfiles
    if not isinstance(delfiles, list):
        delfiles_list = [delfiles]

    for _delent in delfiles_list:
        delent = _delent.format(curtask)
        if os.path.isdir(delent):
            try:
                shutil.rmtree(delent)
                log.debug("Task #{0} deleting {1} due to retention quota".format(
                    curtask, delent))
            except (IOError, OSError) as e:
                log.warn("Error removing {0}: {1}".format(delent, e))
        elif os.path.exists(delent):
            try:
                os.remove(delent)
                log.debug("Task #{0} deleting {1} due to retention quota".format(
                    curtask, delent))
            except OSError as e:
                log.warn("Error removing {0}: {1}".format(delent, e))

def delete_files_date(days):
    old = datetime.now() - timedelta(days=days)

    for root, dirs, files in os.walk(CUCKOO_ROOT + "/storage/analyses/", topdown=False):
        if datetime.fromtimestamp(os.path.getmtime(root)) < old:
            shutil.rmtree(root)
            print(root)
            continue

class Retention(Report):
    """Used to manage data retention and delete task data from
    disk after they have become older than the configured values.
    """

    def run(self, options):
        task_id = False
        delete_files_date(options.days)
        # only allow one reporter to execute this code, otherwise rmtree will race, etc
        delLocations = {
            "anal": CUCKOO_ROOT + "/storage/analyses/{0}/",
            # Handled seperately
            "mongo": True,
            #"elastic": None,
        }
        #retentions = self.options
        for item in delLocations.keys():
            print item
            if os.path.exists("last_id"):
                lastTaskLogged = open("last_id", "rb").read().strip()
            else:
                lastTaskLogged = 1

            add_date = datetime.now() - timedelta(days=options.days)
            buf = db.list_tasks(added_before=add_date, id_after=lastTaskLogged, order_by=Task.id.desc())
            if buf:
                task_id = buf[0].to_dict()["id"]
                # We need to delete some data
                for tid in buf:
                    try:
                        lastTask = tid.to_dict()["id"]
                        print "Going to remove", lastTask
                        if item != "mongo" and item != "elastic":
                            delete_files(lastTask, delLocations[item])
                        elif item == "mongo":
                            if cfg.mongodb and cfg.mongodb.enabled:
                                print "inside"
                                delete_mongo_data(lastTask)
                        elif item == "elastic":
                            if cfg.elasticsearchdb and cfg.elasticsearchdb.enabled and not cfg.elasticsearchdb.searchonly:
                                delete_elastic_data(lastTask)
                    except AutoReconnect:
                        results_db = MongoClient(host, port)[mdb]

        if task_id:
            w = open("last_id", "w")
            w.write(task_id)
            w.close()

if __name__ == '__main__':
    opt = argparse.ArgumentParser('value', description='Remove all reports older than X days')
    opt.add_argument('-d', '--days', action='store', type=int, help='Older then this days will be removed')
    options = opt.parse_args()
    if options.days:
        ret = Retention()
        ret.run(options)
    else:
        print opt.print_help()
