import os
import sys
import pymongo
CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.core.database import Database
from lib.cuckoo.common.config import Config

repconf = Config("reporting")
if len(sys.argv) == 2:
    db = Database()
    paths = db.sample_path_by_hash(sys.argv[1])
    paths = filter(None, [ os.path.exists(path) for path in paths])
    if paths:
        for path in paths:
            print(path)
    else:
        results_db = pymongo.MongoClient(repconf.mongodb.host,repconf.mongodb.port)[repconf.mongodb.db]
        tasks = results_db.analysis.find({"dropped.sha256": sys.argv[1]})
        if tasks:
            for task in tasks:
                path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task["info"]["id"]), "files", sys.argv[1])
                if os.path.exists(path):
                    paths = [path]
                    print(paths)
                    break
else:
    print("provide hash to search")
