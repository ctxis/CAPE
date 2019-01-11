import os
import logging
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.utils import get_memdump_path

log = logging.getLogger(__name__)
reporting_conf = Config("reporting")


class RAMFSCLEAN(Report):
    "Remove/save memdump"
    order = 10001

        action = "delete"
        id = results["info"]["id"]
        if reporting_conf.ramfsclean.key in results:
            for block in results[reporting_conf.ramfsclean.key]:
                if "checkme" in block:
                    action = "store"
                    break

            if action == "delete":
                src = get_memdump_path(id)
                log.debug("Deleting memdump: {}".format(src))

                if os.path.exists(src):
                    os.remove(src)
            else:
                src = get_memdump_path(id)
                dest = get_memdump_path(id, analysis_folder=True)
                log.debug("Storing memdump: {}".format(dest))
                os.rename(src, dest)
