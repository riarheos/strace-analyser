""" The SysCallAnalyser class module """

import logging

# pylint: disable=missing-docstring

class FileStats:
    def __init__(self, name, open_time):
        self.name = name
        self.open_time = open_time
        self.read_time = 0.0
        self.write_time = 0.0

    def add_read_time(self, add):
        self.read_time += add

    def add_write_time(self, add):
        self.write_time += add

    def serialise(self, close_time):
        alive_time = close_time - self.open_time
        return 'file access %s (read_time %.4f, write_time %.4f, alive %.4f)' % (
            self.name,
            self.read_time,
            self.write_time,
            alive_time)


class SysCallAnalyser:
    """ Analyses the syscalls line-by-line making analytical predictions """
    def __init__(self, ignored_syscalls):
        self.log = logging.getLogger('app.analyser')
        self.ignore = set(ignored_syscalls)

        self.descriptors = {}

    @staticmethod
    def _getparam(args, start=0):
        """ Extracts one parameter from the args """
        largs = len(args)
        while start < largs:
            if args[start] != ' ':
                break
            start += 1
        end = args.find(',', start)

        if end > -1:
            return args[start:end]
        return args[start:]

    def process(self, evt):
        """ Process an event dispatching it to the routines """
        if not evt or 'syscall' not in evt:
            return

        # skip ignored
        if evt['syscall'] in self.ignore:
            return

        # write all down
        handler = getattr(self, evt['syscall'], None)
        if handler:
            handler(evt)
        else:
            self.log.debug('Unhandled syscall %s', evt)


    def close(self, evt):
        descriptor = self._getparam(evt['params'])
        if descriptor in self.descriptors:
            stats = self.descriptors[descriptor]
            del self.descriptors[descriptor]
            self.log.info(stats.serialise(evt['ts']))

    def execve(self, evt):
        cmd = self._getparam(evt['params'])
        self.log.info('execute %s', cmd)

    def open(self, evt):
        file = self._getparam(evt['params'])
        self.descriptors[evt['result']] = FileStats(file, evt['ts'])

    def openat(self, evt):
        location = self._getparam(evt['params'])
        file = self._getparam(evt['params'], len(location) + 1)
        self.descriptors[evt['result']] = FileStats(file, evt['ts'])

    def read(self, evt):
        descriptor = self._getparam(evt['params'])
        if descriptor in self.descriptors:
            stats = self.descriptors[descriptor]
            stats.add_read_time(evt['calltime'])

    def write(self, evt):
        descriptor = self._getparam(evt['params'])
        if descriptor in self.descriptors:
            stats = self.descriptors[descriptor]
            stats.add_write_time(evt['calltime'])

    def nanosleep(self, evt):
        self.log.info('sleep %.4f', evt['calltime'])

    def wait4(self, evt):
        self.log.info('wait for process %.4f', evt['calltime'])
