# pylint: disable=all

from setuptools import setup, find_packages
setup(
    name                = "strace-analyser",
    version             = "1",
    author              = "Pavel Pushkarev",
    author_email        = "paulmd@ya.ru",
    description         = ("The simple strace analisation routine"),
    license             = "GPL",
    url                 = "https://github.com/riarheos/strace-analyser",
    packages            = find_packages(),
    scripts             = ['strace-analyser'],
    install_requires    = ['python-yaml'],
    package_data = {
        '': ['*.yaml'],
    }
)
