# pylint: disable=all

from setuptools import setup, find_packages
setup(
    name                = "strace-analyser",
    version             = "1",
    author              = "Pavel Pushkarev",
    author_email        = "media-admin@yandex-team.ru",
    description         = ("The simple strace analisation routine"),
    license             = "GPL",
    url                 = "https://github.yandex-team.ru/admins/strace-analyser",
    packages            = find_packages(),
    scripts             = ['strace-analyser'],
    install_requires    = ['yaconfig'],
    package_data = {
        '': ['*.yaml'],
    }
)
