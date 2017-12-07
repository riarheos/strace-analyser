""" The Strace Processor class module """

import logging
import re


# pylint: disable=too-few-public-methods
class StraceProcessor:
    """
    Process strace output line-by-line converting items to the dict
    """
    re_pidts = re.compile(r'^(?:\[pid\s+(?P<pid>\d+)\] )?(?P<ts>[\d\.]+) (?P<data>.*)$')
    re_generic = re.compile(r'^(?P<syscall>\w+)\((?P<params>.*)\)\s+= '
                            r'(?P<result>\S+).*<(?P<calltime>[\d\.]+)>$')
    re_resumed = re.compile(r'^<\.\.\. \w+ resumed> (?P<data>.*)')

    def __init__(self):
        self.log = logging.getLogger('app.processor')
        self.unfinished = dict()

    def process(self, line):
        """ Convert a text strace line to a dict """

        # extract the pid and the ts
        m_pidts = self.re_pidts.match(line.strip())
        if not m_pidts:
            self.log.debug('Unparsable line: %s', line)
            return

        data = m_pidts.group('data')
        pid = m_pidts.group('pid')
        pid = int(pid) if pid else 0

        # keep unfinished lines
        if data.endswith('<unfinished ...>'):
            self.unfinished[pid] = data[:-17]
            return

        # join unfinished lines
        m_resumed = self.re_resumed.match(data)
        if m_resumed:
            if pid in self.unfinished:
                data = self.unfinished[pid] + m_resumed.group('data')
                del self.unfinished[pid]
            else:
                self.log.debug('Non-started line: %s', line)
                return

        m_generic = self.re_generic.match(data)
        if not m_generic:
            self.log.debug('Unparsable data: %s', line)
            return

        result = m_generic.groupdict()
        result['ts'] = float(m_pidts.group('ts'))
        result['pid'] = pid
        result['calltime'] = float(result['calltime'])

        return result
