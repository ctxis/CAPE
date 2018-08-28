import os
import sys
import logging

log = logging.getLogger(__name__)

def get_file_content(paths):
    for path in paths:
        if os.path.exists(path):
            content = open(path, "rb").read()
            return content
    return False