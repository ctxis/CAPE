#encoding: utf-8
#!/usr/bin/env python

import sys
import pkgutil
import os
import logging
import argparse
import io
import base64
import json
import datetime

__version__ = {}
__version__['codename'] = 'Iron Airedale' # http://www.codenamegenerator.com/?prefix=metal&dictionary=dogs
__version__['digit'] = 3.0
__version__['run_date'] = datetime.datetime.now().isoformat()


# ## Global graphing default values
__figformat__ = 'png'   # Output format of saved figure
__figsize__ = (12,4)    # Size of figure in inches
__figdpi__ = 100        # DPI of figure
__json__ = False     # Show the plot interactively
__showplt__ = False     # Show the plot interactively
__blob__ = False        # Treat all files as binary blobs. Disable intelligently parsing of file format specific features.


# ## Default logging
#logging.getLogger("binGraph").setLevel(logging.INFO)
# # Lower the matplotlib logger
logging.getLogger('matplotlib').setLevel(logging.CRITICAL)
log = logging.getLogger(__name__)

# ### Helper functions

# # Gather files to process - give it a list of paths (files or directories)
# # and it will return all files in a list
def find_files(search_paths, recurse):

    __files__ = []
    for f in search_paths:

        if recurse and os.path.isdir(f):

            for dir_name, dirs, files in os.walk(f):
                log.debug('Found directory: {}'.format(dir_name))

                for fname in files:
                    abs_fpath = os.path.join(dir_name, fname)

                    if os.path.isfile(abs_fpath) and not os.path.islink(abs_fpath) and not os.stat(abs_fpath).st_size == 0:
                        log.info('File found: "{}"'.format(abs_fpath))
                        __files__.append(abs_fpath)

        elif os.path.isfile(f) and not os.path.islink(f) and not os.stat(f).st_size == 0:
            abs_fpath = os.path.abspath(f)
            log.info('Found file: "{}"'.format(abs_fpath))
            __files__.append(abs_fpath)

        else:
            log.critical('Not a file, skipping: "{}"'.format(f))
            pass

    return __files__

# # Cleanup given filename
def clean_fname(fn):

    return ''.join([c for c in fn if c.isalnum()])

# # Generate the different file names required
def gen_names(ffrmt, abs_fpath, abs_save_path, save_prefix=None, graphtype=None, findex=None):

    base_save_fname = '{prefix}-{findex}-{graphtype}-{cleaned_fname}.{ffrmt}'

    if save_prefix:
        save_fname = base_save_fname.replace('{prefix}', save_prefix)
    else:
        save_fname = base_save_fname.replace('{prefix}-', '')

    save_fname = save_fname.replace('{graphtype}', graphtype)

    cleaned_fname = clean_fname(os.path.basename(abs_fpath))

    if type(findex) == int:
        save_fname = save_fname.replace('{findex}', str(findex))
        save_fname = save_fname.replace('{cleaned_fname}', cleaned_fname)
    else:
        save_fname = save_fname.replace('{findex}-', '')
        save_fname = save_fname.replace('-{cleaned_fname}', '')

    save_fname = save_fname.replace('{ffrmt}', ffrmt)

    abs_save_fpath = os.path.join(abs_save_path, save_fname)

    return abs_save_fpath, os.path.basename(abs_fpath), cleaned_fname

# # Dynamically import graphtypes
def get_graph_modules():

    graphs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'graphs')
    graph_individuals = [x[0] for x in os.walk(graphs_dir)][1:]

    modules = {}

    for graph in graph_individuals:

        for importer, package_name, _ in pkgutil.iter_modules([graph]):

            if sys.version_info[0] < 3:
                full_package_name = '{}'.format(os.path.basename(graph))
            else:
                full_package_name = '{}.graph'.format(os.path.basename(graph), package_name)

            if not (full_package_name in sys.modules):

                if sys.version_info[0] < 3:
                    module = importer.find_module('graph', graph)
                else:
                    module = importer.find_module(full_package_name)

                if module:

                    module = module.load_module(full_package_name)

                modules[os.path.basename(graph)] = module

    return modules

# ## Graphs
# # Try and import the graphs
try:
    graphs = get_graph_modules()
except Exception as e:
    log.critical('Failed to import graph: {}'.format(e))
    #exit(0)

# # Main routine here
def generate_graphs(args_dict, file_path=False, save_dir=False):
    """
    This will allow to users use it as library
        args_dict = {
            'files': ['malware.exe'], 
            'graphtype': 'ent', 
            'verbose': False, 
            'showplt': False, 
            'format': 'svg', 
            'recurse': False, 
            'json': False, 
            '__dummy': True, 
            'entcolour': '#ff00ff', 
            'prefix': None, 
            'dpi': 100, 
            'file': ['malware.exe'], 
            'save_dir': '/tmp', 
            'chunks': 750, 
            'ibytes': [
                {'colour': (0.08235294117647059, 1.0, 0.01568627450980392, 1.0), 'bytes': [0], 'name': u"0's"}, 
                {'colour': (1.0, 0.16862745098039217, 0.00392156862745098, 1.0), 'bytes': [44, 144], 'name': u'Exploit'}, 
                {'colour': (0.0, 0.0, 1.0, 1), 'bytes': [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126], 'name': u'Printable ASCII'}
            ], 
            'figsize': (12, 4), 'blob': False
        }
    """
    if file_path:
        args_dict = {
            'files': [], 
            'graphtype': 'ent', 
            'verbose': False, 
            'showplt': False, 
            'format': 'svg', 
            'recurse': False, 
            'json': False, 
            '__dummy': True, 
            'entcolour': '#ff00ff', 
            'prefix': None, 
            'dpi': 100, 
            'file': [], 
            'save_dir': '', 
            'chunks': 750, 
            'ibytes': [
                {'colour': (0, 1, 0, 1), 'bytes': [0], 'name': u"Zeros"}, 
            ], 
            'figsize': (12, 4), 'blob': False
            }
    
    args_dict["files"] = [file_path]
    args_dict["file"] = [file_path]
    args_dict["save_dir"] = save_dir

    # # Detect if all graphs are being requested + set required defaults
    __graphtypes__ = []
    if args_dict["graphtype"] == 'all':
        __graphtypes__ = graphs
    else:
        __graphtypes__ = { args_dict["graphtype"]: graphs[args_dict["graphtype"]] }

    log.debug('Generating graphs: {}'.format(', '.join(__graphtypes__.keys()) ))

    # # Iterate over all given files
    for index, abs_fpath in enumerate(args_dict["files"]):

        log.info('+++ Processing: "{}"'.format(abs_fpath))
        
        for module_name, module in __graphtypes__.items():
            abs_save_fpath, fname, cleaned_fname = gen_names(args_dict["format"], abs_fpath, args_dict["save_dir"], save_prefix=args_dict["prefix"], graphtype=module_name, findex=(index if len(args_dict["files"])>1 else None))

            args_dict['abs_fpath'] = abs_fpath # Define the current file we are acting on
            args_dict['fname'] = fname
            args_dict['cleaned_fname'] = cleaned_fname

            # # Generate and output the graph
            plt, save_kwargs, json_data = module.generate(**args_dict)

            fig = plt.gcf()
            fig.set_size_inches(*args_dict["figsize"], forward=True)

            # # Add watermark - need to work out a way to not let this overlap
            # ax = plt.gca()
            # ax.text(-0.03, -0.15, 'github.com/geekscrapy/binGraph', ha='left', va='top', family='monospace', transform=ax.transAxes)

            plt.tight_layout()

            if args_dict["showplt"]:
                log.debug('Opening graph interactively')
                plt.show()
            elif args_dict["json"]:
                log.info('Saving as json file')

                output = {}
                output['info'] = json_data

                buf = io.BytesIO()
                plt.savefig(buf,format=args_dict["format"], dpi=args_dict["dpi"], forward=True, **save_kwargs)
                output['graph'] = base64.b64encode(buf.getvalue()).decode()
                buf.close()

                output['cmdline'] = ' '.join(args_dict)
                output['version'] = __version__

                abs_save_fpath = os.path.splitext(abs_save_fpath)[0] + '.json'
                with open(abs_save_fpath, 'w') as outfile:
                    json.dump(output, outfile)

                log.info('Graph saved to: "{}"'.format(abs_save_fpath))

            else:
                plt.savefig(abs_save_fpath, format=args_dict["format"], dpi=args_dict["dpi"], forward=True, **save_kwargs)
                log.info('Graph saved to: "{}"'.format(abs_save_fpath))

            plt.clf()
            plt.cla()
            plt.close()

        log.info('+++ Complete: "{}"'.format(abs_fpath))

# ### Main
if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, format='%(name)s | %(levelname)s | %(message)s')
    
    # # Import the defaults
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', type=str, required=True, nargs='+', metavar='malware.exe', help='Give me a graph of this file. See - if this is the only argument specified.')
    parser.add_argument('-r', '--recurse', action='store_true', help='If --file is a directory, add files recursively')
    parser.add_argument('-', dest='__dummy', action='store_true', help='*** Required if --file or -f is the only argument given before a graph type is provided (it\'s greedy!). E.g. "binGraph.py --file mal.exe - ent"')
    parser.add_argument('--prefix', type=str, metavar='', help='Add this prefix to the saved filenames') 
    parser.add_argument('--out', type=str, dest='save_dir', default=os.getcwd(), metavar='/data/graphs/', help='Where to save the graph files') 
    parser.add_argument('--json', action='store_true', default=__json__, help='Ouput graphs as json with graph images encoded as Base64')
    parser.add_argument('--showplt', action='store_true', default=__showplt__, help='Show plot interactively (disables saving to file)')
    parser.add_argument('--format', type=str, default=__figformat__, choices=['png', 'pdf', 'ps', 'eps','svg'], required=False, metavar='png', help='Graph output format. All matplotlib outputs are supported: e.g. png, pdf, ps, eps, svg')
    parser.add_argument('--figsize', type=int, nargs=2, default=__figsize__, metavar='#', help='Figure width and height in inches')
    parser.add_argument('--dpi', type=int, default=__figdpi__, metavar=__figdpi__, help='Figure dpi')
    parser.add_argument('--blob', action='store_true', default=__blob__, help='Do not intelligently parse certain file types. Treat all files as a binary blob. E.g. don\'t add PE entry point or section splitter to the graph')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print debug information to stderr')


    subparsers = parser.add_subparsers(dest='graphtype', help='Graph type to generate. Graphs can also be individually generated by running the in isolation: python graphs/ent/graph.py -f file.bin')
    subparsers.required = True

    subparsers.add_parser('all')

    # # Loop over all graph types to add their graph specific options
    for name, module in graphs.items():
        module_parser = subparsers.add_parser(name)
        module.args_setup(module_parser)

    args = parser.parse_args()

    # # Set logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('matplotlib').setLevel(logging.WARNING)

    log.debug('Found the following graph types: {}'.format(', '.join(graphs.keys())))

    # # Verify global arguments

    # # Get a list of files from the arguments
    __files__ = find_files(args.file, args.recurse)
    # # Adjust args to retain the list of files
    args.files = __files__

    # # Detect if all graphs are being requested + set required defaults
    __graphtypes__ = []
    if args.graphtype == 'all':
        __graphtypes__ = graphs
    else:
        __graphtypes__ = { args.graphtype: graphs[args.graphtype] }

    # # Allow graph modules to verify if their arguments have been set correctly
    for name, module in __graphtypes__.items():
        module.args_validation(args)

    # # Is the save_dir actually a dirctory?
    args.save_dir = os.path.abspath(args.save_dir)
    if not os.path.isdir(args.save_dir):
        log.critical('--save_dir is not a directory: {}'.format(args.save_dir))
        exit(1)

    args_dict = args.__dict__    
    generate_graphs(args_dict)