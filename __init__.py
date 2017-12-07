"""
This is a strace analyser module

One should use it like this:

strace -f -ttt -v -qq -T -s 1024 -p <pid> 2>&1 | strace-analyser
"""

import fileinput
import yaconfig
from StraceProcessor import StraceProcessor
from SysCallAnalyser import SysCallAnalyser


def main():
    """ The main entry point """
    conf = yaconfig.load_config('strace-analyser.yaml')

    processor = StraceProcessor()
    analyser = SysCallAnalyser(conf.syscalls.ignore)
    for line in fileinput.input():
        evt = processor.process(line)
        analyser.process(evt)

if __name__ == '__main__':
    main()
