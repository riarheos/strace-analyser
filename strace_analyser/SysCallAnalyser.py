""" The SysCallAnalyser class module """

import logging
import re

# pylint: disable=missing-docstring


def colorify(number):
    """ Adds colours based on the number value """
    color = '\033[92m'
    if number < 0.0001:
        color = '\033[90m'
    if number > 0.1:
        color = '\033[93m'
    if number > 0.5:
        color = '\033[91m'
    return '%s%.4f\033[0m' % (color, number)


def print_log(type_, read, write, total, name):
    """ Formats an output line with colours """
    line = '\033[97m%10s\033[0m   ' % type_
    line += 'rd %s  '   % colorify(read)  if read is not None  else '           '
    line += 'wr %s  '   % colorify(write) if write is not None else '           '
    line += 'tot %s   ' % colorify(total) if total is not None else '             '
    if name:
        line += name
    print(line)


class BaseStats:
    """ The base stats class. Holds several statistics and
        posesses the ability to dump itself """
    TYPE = 'undefined'

    def __init__(self, name, open_time):
        self.name = self._convert_name(name)
        self.open_time = open_time
        self.read_time = 0.0
        self.write_time = 0.0

    @staticmethod
    def _convert_name(name):
        return name

    def add_read_time(self, add):
        self.read_time += add

    def add_write_time(self, add):
        self.write_time += add

    def dump(self, close_time):
        alive_time = close_time - self.open_time
        print_log(self.TYPE, self.read_time, self.write_time, alive_time, self.name)

class FileStats(BaseStats):
    TYPE = 'file'

class NetStats(BaseStats):
    """ Allows long ip/port conversions to a human-readable format """
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
    TYPE = 'net in'

class OutNetStats(NetStats):
    TYPE = 'net out'


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
        elif args[start] == '"':
            end_symbol = '"'
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

    def accept4(self, evt):
        self.accept(evt)

    def close(self, evt):
        descriptor = self._getparam(evt['params'])
        if descriptor in self.descriptors:
            self.descriptors[descriptor].dump(evt['ts'])
            del self.descriptors[descriptor]

    def connect(self, evt):
        descriptor = self._getparam(evt['params'])
        sockinfo = self._getparam(evt['params'], len(descriptor) + 1)
        self.descriptors[descriptor] = OutNetStats(sockinfo, evt['ts'])

    def execve(self, evt):
        cmd = self._getparam(evt['params'])
        print_log('execute', None, None, None, cmd)

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

    def readv(self, evt):
        self.read(evt)

    def recvfrom(self, evt):
        self.read(evt)

    def recvmsg(self, evt):
        self.read(evt)

    def sendmmsg(self, evt):
        self.write(evt)

    def write(self, evt):
        descriptor = self._getparam(evt['params'])
        if descriptor in self.descriptors:
            stats = self.descriptors[descriptor]
            stats.add_write_time(evt['calltime'])

    def writev(self, evt):
        return self.write(evt)

    @staticmethod
    def nanosleep(evt):
        print_log('sleep', None, None, evt['calltime'], None)

    def sendto(self, evt):
        self.write(evt)

    @staticmethod
    def wait4(evt):
        print_log('proc:wait', None, None, evt['calltime'], None)
