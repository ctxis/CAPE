import json
import requests
import logging
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.database import Database, TASK_COMPLETED, TASK_REPORTED

try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
    HAVE_MONGO = True
except ImportError:
    HAVE_MONGO = False
    print("missed pymongo")

log = logging.getLogger(__name__)
main_db = Database()
reporting_conf = Config("reporting")

class CALLBACKHOME(Report):
    "Notify us about analysis is done"
    order = 10000

    def run(self, results):
        urls = reporting_conf.notification.url.split(",")
        task_id = int(results.get('info', {}).get('id'))
        #mark as reported
        if HAVE_MONGO:
            try:
                conn = MongoClient(reporting_conf.mongodb.host, reporting_conf.mongodb.port)
                mongo_db = conn[reporting_conf.mongodb.db]
                # set complated_on time
                main_db.set_status(task_id, TASK_COMPLETED)
                # set reported time
                main_db.set_status(task_id, TASK_REPORTED)
                conn.close()
            except ConnectionFailure:
                log.error("Cannot connect to MongoDB")

            for url in urls:
                try:
                    res = requests.post(url, data=json.dumps({"task_id":task_id}), timeout=20)
                    if res and res.ok:
                        log.info("reported id: {}".format(task_id))
                    else:
                        log.info("failed to report {}".format(task_id))
                except Exception as e:
                    log.info(e)
