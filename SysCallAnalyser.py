""" The SysCallAnalyser class module """

import logging
import re

# pylint: disable=missing-docstring

class BaseStats:
    TYPE = 'undefined'

    def __init__(self, name, open_time):
        self.name = self._convert_name(name)
        self.open_time = open_time
        self.read_time = 0.0
        self.write_time = 0.0

    def _convert_name(self, name):
        return name

    def add_read_time(self, add):
        self.read_time += add

    def add_write_time(self, add):
        self.write_time += add

    def serialise(self, close_time):
        alive_time = close_time - self.open_time
        return '%s\t%s (read_time %.4f, write_time %.4f, alive %.4f)' % (
            self.TYPE,
            self.name,
            self.read_time,
            self.write_time,
            alive_time)

class FileStats(BaseStats):
    TYPE = 'file'

class NetStats(BaseStats):
    rx_family = re.compile(r'sa_family=(\w+)')
    rx_port = re.compile(r'sin6?_port=htons\((\d+)\)')
    rx_addr_4 = re.compile(r'sin_addr=inet_addr\("([^"]+)"\)')
    rx_addr_6 = re.compile(r'inet_pton\(AF_INET6, "([^"]+)"')
    rx_path = re.compile(r'sun_path="([^"]+)"')

    def _convert_name(self, name):
        family = self.rx_family.search(name)
        if not family:
            return name

        family = family.group(1)

        if family == 'AF_LOCAL':
            path = self.rx_path.search(name)
            if path:
                path = path.group(1)
            return 'unix:' + str(path)

        if family == 'AF_INET':
            port = self.rx_port.search(name).group(1)
            addr = self.rx_addr_4.search(name).group(1)
            return '%s:%s' % (addr, port)

        if family == 'AF_INET6':
            port = self.rx_port.search(name).group(1)
            addr = self.rx_addr_6.search(name).group(1)
            return '[%s]:%s' % (addr, port)

        return name


class InNetStats(NetStats):
    TYPE = 'net:in'

class OutNetStats(NetStats):
    TYPE = 'net:out'


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

        # quick find if there is no param
        if start == largs:
            return ''

        end_symbol = ','
        if args[start] == '{':
            end_symbol = '}'
            start += 1

        end = args.find(end_symbol, start)
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


    def accept(self, evt):
        file = self._getparam(evt['params'])
        sockinfo = self._getparam(evt['params'], len(file) + 1)
        self.descriptors[evt['result']] = InNetStats(sockinfo, evt['ts'])

    def close(self, evt):
        descriptor = self._getparam(evt['params'])
        if descriptor in self.descriptors:
            stats = self.descriptors[descriptor]
            del self.descriptors[descriptor]
            self.log.info(stats.serialise(evt['ts']))

    def connect(self, evt):
        descriptor = self._getparam(evt['params'])
        sockinfo = self._getparam(evt['params'], len(descriptor) + 1)
        self.descriptors[descriptor] = OutNetStats(sockinfo, evt['ts'])

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

    def recvfrom(self, evt):
        self.read(evt)

    def sendmmsg(self, evt):
        self.write(evt)

    def write(self, evt):
        descriptor = self._getparam(evt['params'])
        if descriptor in self.descriptors:
            stats = self.descriptors[descriptor]
            stats.add_write_time(evt['calltime'])

    def nanosleep(self, evt):
        self.log.info('sleep %.4f', evt['calltime'])

    def sendto(self, evt):
        self.write(evt)

    def wait4(self, evt):
        self.log.info('wait for process %.4f', evt['calltime'])
