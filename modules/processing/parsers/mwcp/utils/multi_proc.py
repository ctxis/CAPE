"""
Helper methods for setting up multiprocessing workers with logging capabilities
"""

import logging
import multiprocessing as mp
import multiprocessing.pool

logger = logging.getLogger(__name__)

from mwcp.utils import logutil



class TProcess(mp.Process):
    """
    Slighted modified subclass of :class:`multiprocessing.Process`.

    Use this in place of ``Process`` to enable logging in the spawned process.
    """

    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None):
        kwargs = kwargs or {}
        super(TProcess, self).__init__(group, target, name, args, kwargs)
        self.queue = logutil.mp_queue

    def run(self):
        logutil.setup_logging(queue=self.queue)
        logger.debug("Setup logger in {}".format(mp.current_process().name))
        super(TProcess, self).run()


class TPool(mp.pool.Pool):
    """
    Version of :class:`multiprocessing.pool.Pool` that uses :class:`TProcess`.
    """
    Process = TProcess
