
class Parser(object):
    """
    Base class for malware config parsers

    DC3-MWCP modules should be named ${name}.py where ${name} the name used
    to invoke the parser.

    Currently, a new parser object is created by the framework for each run().
    """

    def __init__(self,
                 description='na',
                 author='na',
                 reporter=None
                 ):
        """
        Initializes the parser.

        :param description: short description
        :param author: initials of author
        :param mwcp.Reporter reporter: reference to reporter object that executed this parser.
                                       Set when parser is created.
        """
        self.description = description
        self.author = author
        self.reporter = reporter

    def run(self):
        """
        Parser execution method.

        All parsers should implement this function which will be called by DC3-MWCP Framework.

        All externally visible operations should be performed through the reporter object.

        """
        pass
