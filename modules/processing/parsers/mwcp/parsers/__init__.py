"""
Interface for registering and accessing parsers.
"""

import collections
import glob
import importlib
import inspect
import logging
import os
import sys

import mwcp

logger = logging.getLogger(__name__)

# Dictionary containing:
# {
#     parser_name: {source_name: parser_class}
# }
_PARSERS = collections.defaultdict(dict)
_parsers_registered = False


def _register_entry_points():
    """
    Registers parsers found in entry_point: "mwcp.parsers"
    :return:
    """
    global _PARSERS
    # if pkg_resources is not available, we are not going to use this feature.
    # resorting on only to parsers founds with parserdir.
    try:
        import pkg_resources
    except ImportError:
        return
    for entry in pkg_resources.iter_entry_points('mwcp.parsers'):
        parser_name = entry.name
        source_name = entry.dist.project_name
        klass = entry.load()
        if not issubclass(klass, mwcp.Parser):
            raise ImportError('{!r} is not an subclass of mwcp.Parser'.format(klass))
        _PARSERS[parser_name][source_name] = klass


def _load_parser_class(file_path):
    """
    Imports and then finds the mwcp Parser from the given file path.
    (The first mwcp.Parser type object found will be returned.)

    :param file_path: File path to the python file containing the parser.
    :return: a class that subclasses mwcp.Parser or None on failure.
    """
    # In order to import the modules in a cross-compatible way, we are going to have to
    # temporarily extend the path to include the parser's directory.
    orig_path = list(sys.path)
    sys.path.insert(0, os.path.dirname(file_path))
    try:
        module_name, _ = os.path.splitext(os.path.basename(file_path))
        module = importlib.import_module(module_name)

        # find descendants of mwcp.Parser in this module.
        for _, klass in inspect.getmembers(module, inspect.isclass):
            if issubclass(klass, mwcp.Parser) and klass != mwcp.Parser:
                return klass
        return None
    finally:
        sys.path = orig_path


def register_parser_directory(parser_dir):
    """
    Registers parsers found in parser_dir. This function allows you to register one-off parsers
    that are not part of an installed python package.
    (Files that start with "_" are ignored.)

    :param str parser_dir: An extra directory to look for one-off parsers.
    """
    global _PARSERS

    # Look for .py file parsers in the directory.
    for fullpath in glob.glob(os.path.join(parser_dir, '[!_]*.py')):
        module_name = os.path.basename(fullpath)[:-3]
        # Account for old-style parsers that have a "_malwareconfigparser.py" prefix.
        if module_name.endswith('_malwareconfigparser'):
            parser_name = module_name[:-len('_malwareconfigparser')]
        else:
            parser_name = module_name

        # Store full path instead of class so we can import on-demand.
        _PARSERS[parser_name][parser_dir] = fullpath


def iter_parsers(name=None, source=None):
    """
    Iterates all registered parsers.

    :param str name: Filters parser based on a particular name. (":" notation is also supported)
    :param str source: Filters parser based on a particular source.
                       (source is either the name of a python package or path to local directory)

    e.g.
    >> list(iter_parsers())
    [
        ('foo', 'C:\...\parsers', <class 'foo_malwareconfigparser.Foo'>),
        ('foo', 'mwcp-acme', <class 'mwcp-acme.parsers.foo.Foo'>),
        ('bar', 'mwcp-acme', <class 'mwcp-acme.parsers.bar.Bar'>)
    ]
    >> list(iter_parsers(name='foo'))
    [
        ('foo', 'C:\...\parsers', <class 'foo_malwareconfigparser.Foo'>),
        ('foo', 'mwcp-acme', <class 'mwcp-acme.parsers.foo.Foo'>)
    ]
    >> list(iter_parsers(source='mwcp-acme'))
    [
        ('foo', 'mwcp-acme', <class 'mwcp_acme.parsers.foo.Foo'>),
        ('bar', 'mwcp-acme', <class 'mwcp_acme.parsers.bar.Bar'>
    ]
    >> list(iter_parsers('mwcp-acme:'))
    [
        ('foo', 'mwcp-acme', <class 'mwcp_acme.parsers.foo.Foo'>),
        ('bar', 'mwcp-acme', <class 'mwcp_acme.parsers.bar.Bar'>
    ]
    >> list(iter_parsers(name='foo', source='mwcp-acme'))
    [
        ('foo', 'mwcp-acme', <class 'mwcp_acme.parsers.foo.Foo'>)
    ]
    >> list(iter_parsers('mwcp-acme:foo'))
    [
        ('foo', 'mwcp-acme', <class 'mwcp_acme.parsers.foo.Foo'>)
    ]

    :yields: tuple containing: (parser_name, source_name, parser_class)
    """
    global _PARSERS
    # Automatically register any parsers found with 'mwcp.parsers' entry_points.
    global _parsers_registered
    if not _parsers_registered:
        _register_entry_points()
        _parsers_registered = True

    if name and not source:
        # If name is using ":" notation, assume it is being organized by "source_name:parser_name"
        # (os.path.basename is necessary in-case source is a file path containing ":"'s)
        orig_name = name
        _, _, name = os.path.basename(name).rpartition(':')
        source = orig_name[:-(len(name) + 1)]

    parser_dict = {name: _PARSERS.get(name, {})} if name else _PARSERS
    for name, source_dict in parser_dict.items():
        if source:
            source_dict = {source: source_dict.get(source, None)}
        for source_name, klass_or_file_path in source_dict.items():
            # If we have a string, it is a file path to our parser so we need to load it.
            if isinstance(klass_or_file_path, (str, bytes)):
                klass = _load_parser_class(klass_or_file_path)
                # Save this for next time.
                _PARSERS[name][source_name] = klass
            else:
                klass = klass_or_file_path
            if klass:
                yield name, source_name, klass


def get_parser_descriptions(name=None, source=None):
    """
    Retrieve list of parser descriptions

    Returns list of tuples per parser. Tuple contains parser name, author, and description.
    """
    descriptions = []
    # Since, description and author are instance variables, we are going to have to
    # temporarily initialize them in order to extract their info.
    # TODO: In the future, this information should be static attributes on the class itself.
    reporter = mwcp.Reporter()
    for _name, _source, klass in sorted(iter_parsers(name=name, source=source)):
        parser = klass(reporter)
        descriptions.append((_name, _source, parser.author, parser.description))
    return descriptions


