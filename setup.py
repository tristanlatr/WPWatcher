#! /usr/bin/env python3
from setuptools import setup, find_packages
import sys
if sys.version_info[0] < 3: 
    raise RuntimeError("You must use Python 3")
# The directory containing this file
import pathlib
HERE = pathlib.Path(__file__).parent
# About the project
ABOUT = {}
exec((HERE / "wpwatcher" / "__version__.py").read_text(), ABOUT)
# The text of the README file
README = (HERE / "README.md").read_text()
setup(
    name                =   ABOUT['__title__'],
    description         =   ABOUT['__description__'],
    url                 =   ABOUT['__url__'],
    maintainer          =   ABOUT['__author__'],
    version             =   ABOUT['__version__'],
    packages            =   find_packages(exclude=('tests')), 
    entry_points        =   {'console_scripts': ['wpwatcher = wpwatcher.cli:main'],},
    classifiers         =   ["Programming Language :: Python :: 3"],
    license             =   ABOUT['__license__'],
    long_description    =   README,
    long_description_content_type   =   "text/markdown",
    install_requires    =   ['wpscan-out-parse>=1.8.1'],
    extras_require      =   {'syslog' : ['rfc5424-logging-handler', 'cefevent']},
    keywords            =   ABOUT['__keywords__'],
)