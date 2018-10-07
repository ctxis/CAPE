#!/usr/bin/env python

"""
Entropy and byte occurrence analysis over all file
-------------------------------------------
abs_fpath str:          Absolute file path - File to load and analyse
fname str:              Filename
blob bool:              Do not intelligently parse certain file types. Treat all files as a binary blob. E.g. don\'t add PE entry point or section splitter to the graph

chunks int:             How many chunks to split the file over. Smaller chunks give a more averaged graph, a larger number of chunks give more detail
ibytes list of dicts:   Dicts are interesting bytes wanting to be displayed on the graph. These can often show relationships and reason for dips or
                        increases in entropy at particular points. Bytes within each type are defined as lists of _decimals_, _not_ hex. Fields are:
                        name = The printed name
                        bytes = The bytes to represent
                        colour = The colour of the line
entcolour str           Colour of the entropy graph
"""
from __future__ import division


# # Import graph specific libs
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.ticker import MaxNLocator

import hashlib
import numpy as np
import statistics
from collections import Counter
import os
import json
import sys
import re


import lief


# # Python 2/3 fix
import json
try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

import logging
log = logging.getLogger('graph.ent')

# # Graph defaults
__chunks__ = 750
__ibytes__= '[ {"name":"0\'s", "colour": "#15ff04", "bytes": [0]}, {"name":"Exploit", "bytes": [44,144], "colour":"#ff2b01"}, {"name":"Printable ASCII", "colour":"b", "bytes": [32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126]} ]'
__ibytes_dict__ = json.loads(__ibytes__)
__entcolour__ = '#ff01d5'

# # Set args in args parse - the given parser is a sub parser
def args_setup(arg_parser):
    arg_parser.add_argument('-c','--chunks', type=int, default=__chunks__, metavar='750', help='Defines how many chunks the binary is split into (and therefore the amount of bytes submitted for shannon sampling per time). Higher number gives more detail')
    arg_parser.add_argument('--ibytes', type=str, nargs='?', metavar=' { "name":"0s", "bytes":[0] }, { "name":"Exploit", "bytes":[44, 144], "colour":"r" } ', default=__ibytes__, help='''
                    Bytes occurances to add to the graph - used to add extra visability into the type of bytes included in the binary. To disable this option, set the flag without an argument.
                    The "name" value is the name of the bytes for the legend, the "bytes" value is the bytes to count the percentage of per section, the "colour" value maybe a matplotlib colour
                    ( r,g,b etc.), a hex with or without an alpha value, or not defined (a seeded colour is chosen). The easiest way to construct these values is to create a dictionary and convert it using \'print(json.loads(dict))\'''')
    arg_parser.add_argument('--entcolour', type=str, metavar='#cf3da2ff', default=__entcolour__, help='Colour of the Entropy line')

# # Validate graph specific arguments - Set the defaults here
class ArgValidationEx(Exception): pass
def args_validation(args):

    # # Test to see what matplotlib backend is setup
    backend = matplotlib.get_backend()
    if not backend == 'TkAgg':
        log.warning('{} matplotlib backend in use. This graph generation was tested with "TkAgg", bugs may lie ahead...'.format(backend))

    # # Test to see if we should use defaults
    if args.graphtype == 'all':
        args.chunks = __chunks__ 
        args.ibytes = __ibytes__
        args.entcolour = __entcolour__

    # # Test ibytes is jalid json
    try:
        args.ibytes = json.loads(args.ibytes)
    except JSONDecodeError as e:
        raise ArgValidationEx('Error decoding json --ibytes value. {}: "{}"'.format(e, args.ibytes))
    except TypeError as e:
        args.ibytes = False

    # # Test to see if ibytes are sane
    if args.ibytes:

        ibytes_list = []

        for ib in args.ibytes:

            ibyte = {}

            if not type(ib) == dict:
                raise ArgValidationEx('Error validating --ibytes - "{}" value is not a dict: "{}"'.format(name, bytelist))
            elif type(ib) == dict:
                if not ('name' in ib.keys() and 'bytes' in ib.keys()):
                    raise ArgValidationEx('Error validating --ibytes - name or bytes field not present: {}'.format(ib))

                ibyte['name'] = ib['name']
                ibyte['bytes'] = []

                if not len(ib['bytes']) > 0:
                    raise ArgValidationEx('Error validating --ibytes - Missing "bytes" values: {}'.format(ib))

                for b in ib['bytes']:
                    if not type(b) == int:
                        raise ArgValidationEx('Error validating --ibytes - "{}" is not an int: "{}"'.format(name, b))
                    else:
                        ibyte['bytes'].append(b)

                # # Get/set the colour if it exists
                if not 'colour' in ib.keys():
                    log.warning('No colour defined for --ibytes byte range: {} {}'.format(ib['name'], ib['bytes']))
                    ibyte['colour'] = matplotlib.colors.to_rgba(hash_colour(ib['name']))
                else:
                    ibyte['colour'] = matplotlib.colors.to_rgba(ib['colour'])

            else:
                raise ArgValidationEx('Error validating --ibytes: {}'.format(ib))

            ibytes_list.append(ibyte)

        args.ibytes = ibytes_list


# # Generate the graph
def generate(abs_fpath, fname, blob, chunks=__chunks__, ibytes=__ibytes_dict__, **kwargs):

    with open(abs_fpath, 'rb') as fh:
        log.debug('Opening: "{}"'.format(fname))

        # # Calculate the overall chunksize 
        fs = os.fstat(fh.fileno()).st_size
        if chunks > fs:
            chunksize = 1
            nr_chunksize = 1
        else:
            chunksize = -(-fs // chunks)
            nr_chunksize = fs / chunks

        log.debug('Filesize: {}, Chunksize (rounded): {}, Chunksize: {}, Chunks: {}'.format(fs, chunksize, nr_chunksize, chunks))
        log.debug('Using ibytes: {}'.format(ibytes))
        log.debug('Producing shannon ent with chunksize {}'.format(chunksize))

        for index, _ in enumerate(ibytes):
            ibytes[index]['percentages'] = []

        shannon_samples = []
        for chunk in get_chunk(fh, chunksize=chunksize):

            # # Calculate ent
            ent = shannon_ent(chunk)
            shannon_samples.append(ent)

            # # Calculate percentages of given bytes, if provided
            if ibytes:
                cbytes = Counter(chunk)

                for index, _ in enumerate(ibytes):
                    occurrence = 0
                    for b in ibytes[index]['bytes']:
                        occurrence += cbytes[b]

                    ibytes[index]['percentages'].append((float(occurrence)/float(len(chunk)))*100)


    log.debug('Closed: "{}"'.format(fname))

    # # Create the figure
    fig, host = plt.subplots()

    log.debug('Plotting shannon samples')
    host.plot(np.array(shannon_samples), label='Entropy', c=hash_colour('Entropy'), zorder=1001, linewidth=1.5)

    host.set_ylabel('Entropy\n'.format(chunksize))
    host.set_xlabel('Raw file offset')
    host.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ('0x{:02X}'.format(int(x * nr_chunksize)))))
    host.xaxis.set_major_locator(MaxNLocator(10))
    plt.xticks(rotation=-10, ha='left')

    # # Draw the graphs in order
    zorder=1000

    # # Plot individual byte percentages
    if ibytes:

        axBytePc = host.twinx()
        axBytePc.set_ylabel('Occurrence of "interesting" bytes')
        axBytePc.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, pos: ('{:d}%'.format(int(x)))))

        for index, _ in enumerate(ibytes):
            zorder -= 1
            c = ibytes[index]['colour']
            axBytePc.plot(np.array(ibytes[index]['percentages']), label=ibytes[index]['name'], c=c, zorder=zorder, linewidth=0.7, alpha=0.75)

        axBytePc.set_ybound(lower=-0.3, upper=101)


    # # Amount of space required between the title and graph elements (such as the section name)
    # # Append a \n if you need more space!
    title_gap = '\n'

    # # Filetype specific additions
    if blob:
        log.warning('Parsing file as blob (as requested)')
    else:

        try:
            parsedbin = lief.parse(filepath=abs_fpath)
            log.debug('Parsed with lief as: {}'.format(type(parsedbin)))

        except lief.bad_file as e:
            parsedbin = None
            log.warning('Failed to parse binary format. Not adding file specific info')

        else:

            if type(parsedbin) == lief.PE.Binary:

                log.debug('Adding PE customisations')

                # # Entrypoint (EP) pointer and vline
                phy_ep_pointer = parsedbin.rva_to_offset(parsedbin.optional_header.addressof_entrypoint) / nr_chunksize
                log.debug('{}: {}'.format('Entrypoint', hex(parsedbin.optional_header.addressof_entrypoint)))

                host.axvline(x=phy_ep_pointer, linestyle=':', c='r', zorder=zorder-1)
                host.text(x=phy_ep_pointer, y=1.07, s='EP', rotation=45, va='bottom', ha='left')

                longest_section_name = 0
                # # Section vlines
                for index, section in enumerate(parsedbin.sections):
                    zorder -= 1

                    section_name = safe_section_name(section.name, index)
                    section_offset = section.offset / nr_chunksize

                    log.debug('{}: {}'.format(section_name, hex(section.offset)))

                    host.axvline(x=section_offset, linestyle='--', zorder=zorder)
                    host.text(x=section_offset, y=1.07, s=section_name, rotation=45, va='bottom', ha='left')

                    # # Get longest section name
                    longest_section_name = len(section_name) if len(section_name) > longest_section_name else longest_section_name

                # # Eval the space required to show the section names
                if longest_section_name <= 5:
                    title_gap = '\n' * 2
                elif longest_section_name <= 9:
                    title_gap = '\n' * 3
                elif longest_section_name <= 15:
                    title_gap = '\n' * 4

            elif type(parsedbin) == lief.ELF.Binary:

                log.debug('Adding ELF customisations')

                # # Entrypoint (EP) pointer and vline
                phy_ep_pointer = parsedbin.virtual_address_to_offset(parsedbin.header.entrypoint) / nr_chunksize
                log.debug('{}: {}'.format('Entrypoint', hex(parsedbin.header.entrypoint)))

                host.axvline(x=phy_ep_pointer, linestyle=':', c='r', zorder=zorder-1)
                host.text(x=phy_ep_pointer, y=1.07, s='EP', rotation=45, va='bottom', ha='left')

                longest_section_name = 0
                # # Section vlines
                for index, section in enumerate(parsedbin.sections):
                    zorder -= 1

                    section_name = safe_section_name(section.name, index)
                    section_offset = section.offset / nr_chunksize

                    log.debug('{}: {}'.format(section_name, hex(section.offset)))

                    host.axvline(x=section_offset, linestyle='--', zorder=zorder)
                    host.text(x=section_offset, y=1.07, s=section_name, rotation=45, va='bottom', ha='left')

                    # # Get longest section name
                    longest_section_name = len(section_name) if len(section_name) > longest_section_name else longest_section_name

                # # Eval the space required to show the section names
                if longest_section_name <= 5:
                    title_gap = '\n' * 2
                elif longest_section_name <= 9:
                    title_gap = '\n' * 3
                elif longest_section_name <= 15:
                    title_gap = '\n' * 4

            else:
                log.debug('File is a currently unsupported format - (supported by lief, not yet supported by binGraph)')

    # # Plot the entropy graph
    host.set_xbound(lower=-0.5, upper=len(shannon_samples)+0.5)
    host.set_ybound(lower=0, upper=1.05)

    # # Add legends + title (adjust for different options given)
    legends = []
    if ibytes:
        legends.append(host.legend(loc='upper left', bbox_to_anchor=(1.1, 1), frameon=False))
        legends.append(axBytePc.legend(loc='upper left', bbox_to_anchor=(1.1, 0.85), frameon=False))
    else:
        legends.append(host.legend(loc='upper left', bbox_to_anchor=(1.01, 1), frameon=False))

    if blob:
        host.set_title('Binary entropy (sampled over {chunksize} byte chunks): {fname}{title_gap}'.format(chunksize=chunksize, fname=fname, title_gap=title_gap))
    else:
        host.set_title('Binary entropy (sampled over {chunksize} byte chunks): {fname}{title_gap}'.format(chunksize=chunksize, fname=fname, title_gap=title_gap))

    # # Return the plt, kwargs for the plt.savefig function, and additional information for json data
    return plt, {'bbox_inches':'tight', 'bbox_extra_artists':tuple(legends)}, {}


# ### Helper functions

# # Read files as chunks
def get_chunk(fh, chunksize=8192):
    while True:
        chunk = fh.read(chunksize)

        # # Convert to bytearray if not python 3
        if sys.version_info[0] <= 3:
            chunk = bytearray(chunk)

        if chunk:
            yield list(chunk)
        else:
            break

# # Some samples may have a corrupt section name (e.g. 206c0533ce9bf83ecdf904bec2f3532d)
def safe_section_name(s_name, index):
        if s_name == '' or s_name == None:
            s_name = 'sect_{:d}'.format(index)

        # # Long sections names upset matplotlib
        if len(s_name) > 15:
            s_name = '{}...'.format(s_name[0:12])

        return s_name

# # Assign a colour to the section name. Static between samples
def hash_colour(text):

    name_colour = int('F'+hashlib.md5(text.encode('utf-8')).hexdigest()[:4], base=16)
    np.random.seed(int(name_colour))
    return matplotlib.colors.to_rgba(np.random.rand(3,))

# # Calculate entropy given a list
def shannon_ent(labels, base=256):
    value, counts = np.unique(labels, return_counts=True)
    norm_counts = counts / counts.sum()
    base = e if base is None else base
    return -(norm_counts * np.log(norm_counts)/np.log(base)).sum()


if __name__ == '__main__':

    import argparse

    logging.basicConfig(stream=sys.stderr, format='%(levelname)s | %(message)s', level=logging.DEBUG)
    logging.getLogger('matplotlib').setLevel(logging.CRITICAL)
    log = logging.getLogger('ent')

    # ## Global graphing default values
    __figformat__ = 'png'   # Output format of saved figure
    __figsize__ = (12,4)    # Size of figure in inches
    __figdpi__ = 100        # DPI of figure
    __showplt__ = False     # Show the plot interactively
    __blob__ = False        # Treat all files as binary blobs. Disable intelligently parsing of file format specific features.

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', type=str, required=True, metavar='malware.exe', help='Give me a graph of this file. See - if this is the only argument specified.')
    parser.add_argument('--showplt', action='store_true', default=__showplt__, help='Show plot interactively (disables saving to file)')
    parser.add_argument('--format', type=str, default=__figformat__, choices=['png', 'pdf', 'ps', 'eps','svg'], required=False, metavar='png', help='Graph output format')
    parser.add_argument('--figsize', type=int, nargs=2, default=__figsize__, metavar='#', help='Figure width and height in inches')
    parser.add_argument('--dpi', type=int, default=__figdpi__, metavar=__figdpi__, help='Figure dpi')
    parser.add_argument('--blob', action='store_true', default=__blob__, help='Do not intelligently parse certain file types. Treat all files as a binary blob. E.g. don\'t add PE entry point or section splitter to the graph')

    args_setup(parser)

    args = parser.parse_args()

    args.graphtype = __name__

    args_validation(args)

    args_dict = args.__dict__
    args_dict['abs_fpath'] = args.file
    args_dict['fname'] = os.path.basename(args.file)
    args_dict['abs_save_fpath'] = '{}.{}'.format(os.path.basename(args_dict['abs_fpath']), args.format)

    plt, save_kwargs, json_data = generate(**args_dict)

    fig = plt.gcf()
    fig.set_size_inches(*args.figsize, forward=True)

    plt.tight_layout()

    if args.showplt:
        log.debug('Opening graph interactively')
        plt.show()
    else:
        plt.savefig(args_dict['abs_save_fpath'], format=args.format, dpi=args.dpi, forward=True, **save_kwargs)
        log.info('Graph saved to: "{}"'.format(args_dict['abs_save_fpath']))
