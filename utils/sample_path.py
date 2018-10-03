import os
import sys
CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.core.database import Database

if len(sys.argv) == 2:
    db = Database()
    for path in db.sample_path_by_hash(sys.argv[1]):
        print(path)
else:
    print("provide hash to search")
