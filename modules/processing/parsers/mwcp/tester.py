"""
Test case support for DC3-MWCP. Parser output is stored in a json file per parser. To run test cases,
parser is re-run and compared to previous results.
"""
from __future__ import print_function, unicode_literals

# Standard imports
import json
import multiprocessing as mp
import logging
import os
import sys
import traceback
from timeit import default_timer

from future.builtins import open, str

logger = logging.getLogger(__name__)

import mwcp
from mwcp.utils.stringutils import convert_to_unicode
from mwcp.utils import multi_proc

try:
    import pkg_resources
except ImportError:
    pkg_resources = None

# Constants
DEFAULT_EXCLUDE_FIELDS = ["debug"]
INPUT_FILE_PATH = "inputfilename"
FILE_EXTENSION = ".json"

# Setting encoding to utf8 is a hotfix for a larger issue
encode_params = {
    'encoding': 'utf8',
    'errors': 'replace'
}


def multiproc_test_wrapper(args):
    """Wrapper function for running tests in multiple processes."""
    test_case = args[0]
    try:
        return test_case.run(*args[1:])
    except KeyboardInterrupt:
        return


class Tester(object):
    """DC3-MWCP Tester class"""

    def __init__(self, reporter, results_dir=None, parser_names=None, nprocs=None,
                 field_names=None, ignore_field_names=DEFAULT_EXCLUDE_FIELDS):
        """

        Run tests and compare produced results to expected results.

        :param mwcp.Reporter reporter: MWCP reporter object
        :param str results_dir: Directory of json test cases
                (defaults to dynamically pulling from a "parsertests" folder next to parser's directory.)
        :param [str] parser_names:
                A list of parser names to run tests for. If the list is empty (default),
                then test cases for all parsers will be run.
        :param [str] field_names:
                A restricted list of fields (metadata key values) that should be compared
                during testing. If the list is empty (default), then all fields, except those in
                ignore_field_names will be compared.
        :param int nprocs: Number of processes to use. (defaults to (3*num_cores)/4)
        """
        self.reporter = reporter
        self.results_dir = results_dir
        self.parser_names = parser_names or [None]
        self.field_names = field_names or []
        self.ignore_field_names = ignore_field_names
        self._test_cases = None
        self._results = []  # Cached results.
        self._processed = False
        self._nprocs = nprocs or (3 * mp.cpu_count()) // 4

    def __iter__(self):
        return self._iter_results()

    def _iter_results(self):
        # First yield any cached results.
        for result in self._results:
            yield result

        # Run tests in multiprocessing pool (if not already run)
        if not self._processed:
            self._processed = True
            pool = multi_proc.TPool(
                processes=self._nprocs, initializer=mwcp.register_parser_directory,
                initargs=(self.reporter.parserdir,))
            test_iter = pool.imap_unordered(
                multiproc_test_wrapper, [(test_case,) for test_case in self.test_cases])
            pool.close()

            try:
                for result in test_iter:
                    self._results.append(result)
                    yield result
            except KeyboardInterrupt:
                pool.terminate()
                raise

    @property
    def test_cases(self):
        """Returns test cases."""
        if self._test_cases is None:
            self._test_cases = []
            for parser_name in self.parser_names:
                # We want to iterate parsers in case parser_name represents a set of parsers from different sources.
                found = False
                for name, source, _ in mwcp.iter_parsers(parser_name):
                    found = True
                    parser = '{}:{}'.format(source, name)
                    results_file_path = self.get_results_filepath(parser)
                    if os.path.isfile(results_file_path):
                        for expected_results in self.parse_results_file(results_file_path):
                            self._test_cases.append(TestCase(
                                self.reporter, parser, expected_results,
                                field_names=self.field_names, ignore_field_names=self.ignore_field_names))
                    else:
                        # Add a failed result if the test case is missing.
                        self._results.append(TestResult(
                            parser=parser,
                            passed=False,
                            errors=['Test case file not found: {}'.format(results_file_path)],
                        ))

                if not found and parser_name:
                    # Add a failed results if we have an orphan test.
                    self._results.append(TestResult(
                        parser=parser_name,
                        passed=False,
                        errors=['Parser not found.']
                    ))
        return self._test_cases

    @property
    def total(self):
        """Returns total number of results."""
        return len(self._results) + len(self.test_cases)

    def gen_results(self, parser_name, input_file_path):
        """
        Generate JSON results for the given file using the given parser name.
        """
        self.reporter.run_parser(parser_name, input_file_path)
        self.reporter.metadata[INPUT_FILE_PATH] = convert_to_unicode(input_file_path)
        return self.reporter.metadata

    def list_test_files(self, parser_name):
        """
        Generate list of files (test cases) for parser
        """
        filelist = []
        for metadata in self.parse_results_file(self.get_results_filepath(parser_name)):
            filelist.append(metadata[INPUT_FILE_PATH])
        return filelist

    def get_results_filepath(self, name, source=None):
        """
        Returns the results file path based on the parser name provided and the
        previously specified output directory.
        """
        # TODO: Remove hardcoding "parsertests" folder. Determine better way to handle this.
        for parser_name, source, klass in mwcp.iter_parsers(name, source=source):
            file_name = parser_name + FILE_EXTENSION
            # Use hardcoded results dir if requested.
            if self.results_dir:
                return os.path.join(self.results_dir, file_name)

            # If source is a directory, assume there is a "parsertests" folder next to it.
            if os.path.isdir(source):
                return os.path.normpath(os.path.join(source, '..', 'parsertests', file_name))

            # Otherwise dynamically pull based on parser's top level module.
            top_level_module, _, _ = klass.__module__.partition('.')
            results_dir = pkg_resources.resource_filename(top_level_module, 'parsertests')
            return os.path.join(results_dir, file_name)

        raise ValueError('Invalid parser: {}'.format(name))

    def parse_results_file(self, results_file_path):
        """
        Parses and validates the the JSON results file and returns the parsed data.
        """
        with open(results_file_path) as results_file:
            data = json.load(results_file)

        # The results file data is expected to be a list of metadata dictionaries
        if not isinstance(data, list) or not all(isinstance(a, dict) for a in data):
            raise ValueError('Results file is invalid: {}'.format(results_file_path))

        return data

    def update_test_results(self, results_file_path, results_data, replace=True):
        """
        Update results in the results file with the passed in results data. If the
        file path for the results data matches a file path that is already found in
        the passed in results file, then the replace argument comes into play to
        determine if the record should be replaced.
        """

        # The results data is expected to be a dictionary representing results
        # for a single file
        assert isinstance(results_data, dict)

        if os.path.isfile(results_file_path):
            results_file_data = self.parse_results_file(results_file_path)

            # Check if there is a duplicate file path already in the results
            # path
            for index, metadata in enumerate(results_file_data):
                if metadata[INPUT_FILE_PATH] == results_data[INPUT_FILE_PATH]:
                    if replace:
                        results_file_data[index] = results_data
                    break
            else:
                # If no duplicate found, then append the passed in results data to
                # existing results
                results_file_data.append(results_data)
        else:
            # Results file should be a list of metadata dictionaries
            results_file_data = [results_data]

        # Write updated data to results file
        # NOTE: We need to use dumps instead of dump to avoid TypeError.
        with open(results_file_path, 'w', encoding='utf8') as results_file:
            results_file.write(str(json.dumps(results_file_data, results_file, indent=4, sort_keys=True)))

    def remove_test_results(self, parser_name, filenames):
        """
        remove filenames from test cases for parser_name

        return files that were removed
        """
        removed_files = []
        results_file_data = []
        for metadata in self.parse_results_file(self.get_results_filepath(parser_name)):
            if metadata[INPUT_FILE_PATH] in filenames:
                removed_files.append(metadata[INPUT_FILE_PATH])
            else:
                results_file_data.append(metadata)

        with open(self.get_results_filepath(parser_name), 'w', encoding='utf8') as results_file:
            results_file.write(str(json.dumps(results_file_data, results_file, indent=4, sort_keys=True)))

        return removed_files


class TestCase(object):

    def __init__(self, reporter, parser, expected_results,
                 field_names=None, ignore_field_names=DEFAULT_EXCLUDE_FIELDS):
        self._reporter = reporter
        self.input_file_path = expected_results[INPUT_FILE_PATH]
        self.filename = os.path.basename(self.input_file_path)
        self.parser = parser
        self.parser_source, _, self.parser_name = parser.rpartition(':')
        self.expected_results = expected_results
        self._field_names = field_names or []
        self._ignore_field_names = ignore_field_names or []

    def run(self):
        """Run test case."""
        start_time = default_timer()

        self._reporter.run_parser(self.parser, self.input_file_path)
        self._reporter.metadata[INPUT_FILE_PATH] = convert_to_unicode(self.input_file_path)
        results = self._reporter.metadata

        comparer_results = self._compare_results(self.expected_results, results)
        passed = all(comparer.passed for comparer in comparer_results)

        done_time = default_timer()
        run_time = done_time - start_time

        return TestResult(
            parser=self.parser,
            input_file_path=self.input_file_path,
            passed=passed,
            errors=self._reporter.errors,
            debug=self._reporter.metadata.get('debug', None),
            results=comparer_results,
            run_time=run_time
        )

    def _compare_results(self, results_a, results_b):
        """
        Compare two result sets. If the field names list is not empty,
        then only the fields (metadata key values) in the list will be compared.
        ignore_field_names fields are not compared unless included in field_names.
        """
        results = []

        # Cursory check to remove FILE_INPUT_PATH key from results since it is
        # a custom added field for test cases
        if INPUT_FILE_PATH in results_a:
            results_a = dict(results_a)
            del results_a[INPUT_FILE_PATH]
        if INPUT_FILE_PATH in results_b:
            results_b = dict(results_b)
            del results_b[INPUT_FILE_PATH]

        # Begin comparing results
        if self._field_names:
            for field_name in self._field_names:
                try:
                    comparer = self._compare_results_field(results_a, results_b, field_name)
                except:
                    comparer = ResultComparer(field_name)
                    self._reporter.error(traceback.format_exc())
                results.append(comparer)
        else:
            for ignore_field in self._ignore_field_names:
                results_a.pop(ignore_field, None)
                results_b.pop(ignore_field, None)
            all_field_names = set(results_a.keys()).union(list(results_b.keys()))
            for field_name in all_field_names:
                try:
                    comparer = self._compare_results_field(
                        results_a, results_b, field_name)
                except:
                    comparer = ResultComparer(field_name)
                    self._reporter.error(traceback.format_exc())
                results.append(comparer)

        return results

    def _compare_results_field(self, results_a, results_b, field_name):
        """
        Compare the values for a single results field in the two passed in results.

        Args:
            results_a (dict): MWCP generated result for a given file using a given parser.
            results_b (dict): MWCP generated result for a given file using a given parser.
        """

        # Check if provided field_name is a valid key (based on fields.json)
        try:
            field_name_u = convert_to_unicode(field_name)
        except:
            raise Exception(
                "Failed to convert field name '{}' to unicode.".format(field_name))

        try:
            field_type = self._reporter.fields[field_name_u]['type']
        except:
            raise Exception(
                "Key error. Field name '{}' was not identified as a standardized field.".format(field_name))

        # Establish value to send for comparison
        value_a = None
        value_b = None
        if field_name_u in results_a:
            value_a = results_a[field_name_u]
        if field_name_u in results_b:
            value_b = results_b[field_name_u]

        # Now compare results based on field type (see "fields.json" for more
        # details)
        if field_type == "listofstrings":
            comparer = ListOfStringsComparer(field_name_u)
            comparer.compare(value_a, value_b)
        elif field_type == "listofstringtuples":
            comparer = ListOfStringTuplesComparer(field_name_u)
            comparer.compare(value_a, value_b)
        elif field_type == "dictofstrings":
            comparer = DictOfStringsComparer(field_name_u)
            comparer.compare(value_a, value_b)
        else:
            raise Exception("Unhandled field type '{}' found for field name '{}'.".format(
                field_type, field_name))

        return comparer


class TestResult(object):

    def __init__(self, parser, passed,
                 input_file_path=None, errors=None, debug=None, results=None, run_time=None):
        self.parser_source, _, self.parser_name = parser.rpartition(':')
        self.input_file_path = input_file_path or 'N/A'
        self.filename = os.path.basename(input_file_path) if input_file_path else 'N/A'
        self.passed = passed
        self.errors = errors or []
        self.debug = debug or []
        self.results = results or []
        self.run_time = run_time or 0

    def print(self, failed_tests=True, passed_tests=True, json_format=False):
        """
        print test result based on provided parameters.

        :param bool failed_tests: Whether to show failed tests.
        :param bool passed_tests: Whether to show passed tests.
        :param bool json_format: Whether to format results as json.
        """
        # TODO: Do we need the json option?
        if json_format:
            passed = self.passed
            if (passed and passed_tests) or (not passed and failed_tests):
                print(json.dumps(self, indent=4, cls=MyEncoder))
        else:
            separator = ""

            filtered_output = ""
            passed = self.passed
            if passed and passed_tests:
                filtered_output += "Parser Name = {}\n".format(self.parser_name)
                if self.input_file_path and self.input_file_path != 'N/A':
                    filtered_output += "Input Filename = {}\n".format(self.input_file_path)
                filtered_output += "Tests Passed = {}\n".format(self.passed)
            elif not passed and failed_tests:
                filtered_output += "Parser Name = {}\n".format(self.parser_name)
                if self.input_file_path and self.input_file_path != 'N/A':
                    filtered_output += "Input Filename = {}\n".format(self.input_file_path)
                filtered_output += "Tests Passed = {}\n".format(self.passed)
                filtered_output += "Errors = {}".format("\n" if self.errors else "None\n")
                if self.errors:
                    for entry in self.errors:
                        filtered_output += "\t{0}\n".format(entry)
                filtered_output += "Debug Logs = {}".format("\n" if self.debug else "None\n")
                if self.debug:
                    for entry in self.debug:
                        filtered_output += "\t{0}\n".format(entry)
                if self.results:
                    filtered_output += "Results =\n"
                    for result in self.results:
                        if not result.passed:
                            filtered_output += "{0}\n".format(result)

            if filtered_output:
                filtered_output += "{0}\n".format(separator)
                print(filtered_output.encode(**encode_params))


####################################################
# Comparer classes for various MWCP field types
####################################################


class ResultComparer(object):

    def __init__(self, field):
        self.field = field
        self.passed = False
        self.missing = []  # Entries found in test case but not new results
        self.unexpected = []  # Entries found in new results but not test case

    def compare(self, test_case_results=None, new_results=None):
        """Compare two result sets and document any differences."""

        self.missing = []
        self.unexpected = []

        self.field_compare(test_case_results, new_results)

        self.passed = not bool(self.missing or self.unexpected)

    def field_compare(self, test_case_results, new_results):
        """Field specific compare function."""
        # Override in child classes
        raise NotImplementedError()

    def get_report(self, json=False, tabs=1):
        """
        If json parameter is False, get report as a unicode string.
        If json parameter is True, get report as a dictionary.
        """

        if json:
            return self.__dict__
        else:
            tab = tabs * "\t"
            tab_1 = tab + "\t"
            tab_2 = tab_1 + "\t"
            report = tab + "{}:\n".format(self.field)
            report += tab_1 + "Passed: {}\n".format(self.passed)
            if self.missing:
                report += tab_1 + "Missing From New Results:\n"
                for item in self.missing:
                    report += tab_2 + "{}\n".format(convert_to_unicode(item))
            if self.unexpected:
                report += tab_1 + "Unexpected New Results:\n"
                for item in self.unexpected:
                    report += tab_2 + "{}\n".format(convert_to_unicode(item))

            return report

    def __bytes__(self):
        return self.get_report().encode('utf8')

    def __unicode__(self):
        return self.get_report()

    def __str__(self):
        if sys.version_info >= (3, 0):
            return self.__unicode__()
        else:
            return self.__bytes__()

    def __repr__(self):
        return self.__str__()


class ListOfStringsComparer(ResultComparer):

    def field_compare(self, test_case_results, new_results):
        """Compare each string in a list of strings."""
        list_test = [] if not test_case_results else test_case_results
        list_new = [] if not new_results else new_results

        self.missing += list(set(list_test) - set(list_new))
        self.unexpected += list(set(list_new) - set(list_test))


class ListOfStringTuplesComparer(ResultComparer):

    def field_compare(self, test_case_results, new_results):
        """Compare each tuple of strings in a list of tuples."""
        set_list_test = []
        set_list_new = []
        if test_case_results:
            set_list_test = [set(x) for x in test_case_results]
        if new_results:
            set_list_new = [set(x) for x in new_results]

        for set_test in set_list_test:
            if set_test not in set_list_new:
                # Append the list entry here instead of the set to preserve the
                # entries ordering
                self.missing.append(
                    test_case_results[set_list_test.index(set_test)])

        for set_new in set_list_new:
            if set_new not in set_list_test:
                # Append the list entry here instead of the set to preserve the
                # entries ordering
                self.unexpected.append(
                    new_results[set_list_new.index(set_new)])


class DictOfStringsComparer(ResultComparer):

    def field_compare(self, test_case_results, new_results):
        """Compare each key value pair in a dictionary of strings."""
        dict_test = {} if not test_case_results else test_case_results
        dict_new = {} if not new_results else new_results

        for key in dict_test:
            if key not in dict_new:
                self.missing.append(u"{}: {}".format(key, dict_test[key]))
            elif set(dict_test[key]) != set(dict_new[key]):
                self.missing.append(u"{}: {}".format(key, dict_test[key]))

        for key in dict_new:
            if key not in dict_test:
                self.unexpected.append(u"{}: {}".format(key, dict_new[key]))
            elif set(dict_new[key]) != set(dict_test[key]):
                self.unexpected.append(u"{}: {}".format(key, dict_new[key]))


####################################################
# JSON encoders
####################################################


class MyEncoder(json.JSONEncoder):

    def default(self, o):
        return o.__dict__
