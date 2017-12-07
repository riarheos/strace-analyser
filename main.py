import yaconfig
from StraceProcessor import StraceProcessor
from SysCallAnalyser import SysCallAnalyser
import fileinput

#strace -f -ttt -v -qq -T -s 1024 bash -c 'sleep 1; ls' > stra^C.log

def main():
    conf = yaconfig.load_config('strace-analyser.yaml')

    processor = StraceProcessor()
    analyser = SysCallAnalyser(conf.syscalls.ignore)
    for line in fileinput.input():
        evt = processor.process(line)
        analyser.process(evt)

if __name__ == '__main__':
    main()
