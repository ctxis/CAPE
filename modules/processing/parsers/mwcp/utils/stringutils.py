"""
Utility used for string conversions.
"""

from future.builtins import str


def convert_to_unicode(input_string):
    if isinstance(input_string, str):
        return input_string
    else:
        return str(input_string, encoding='utf8', errors='replace')
