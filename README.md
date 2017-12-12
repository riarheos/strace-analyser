# strace-analyser
The strace analyser is a strace postprocessor.
It can track file/network requests and write down timings.

Linux-only due to strace :)

![Strace Analyser Preview]
(https://github.com/riarheos/strace-analyser/raw/master/strace_image.png)

## Installation

    pip install https://github.com/riarheos/strace-analyser/archive/master.zip

or (Debian/Ubuntu way)

    git clone https://github.com/riarheos/strace-analyser.git
    cd strace-analyser
    debuild
    dpkg -i ../strace-analyser_*.deb
    
## Usage

    strace -f -ttt -v -qq -T -s 1024 -p <PID> 2>&1 | strace-analyser
