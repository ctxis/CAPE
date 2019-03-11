"""Exposes interface for MWCP."""

import logging

# Add null handler to root logger to avoid "no handler" error when this is used as a library
logging.getLogger().addHandler(logging.NullHandler())


from mwcp import config
from mwcp.parser import Parser
from mwcp.parsers import register_parser_directory, iter_parsers, get_parser_descriptions
from mwcp.reporter import Reporter
from mwcp.resources import techanarchy_bridge
from mwcp.resources.dispatcher import Dispatcher, ComponentParser, FileObject, UnableToParse, UnidentifiedFile
from mwcp.utils.logutil import setup_logging
