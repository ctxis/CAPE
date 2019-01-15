"""This is a wrapper interface to the construct library which adds extra helper functions."""


# Import interface
from construct import *
from mwcp.utils.construct.construct_html import html_hex
from mwcp.utils.construct.windows_enums import *
from mwcp.utils.construct.windows_structures import *

# NOTE: This must be imported last since it contains overwritten elements of the base construct library.
from mwcp.utils.construct.helpers import *
