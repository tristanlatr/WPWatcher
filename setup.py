#! /usr/bin/env python3
from setuptools import setup, find_packages
import pathlib
# The directory containing this file
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
    classifiers         =   [
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Environment :: Console",
        "Topic :: Security",
        "Topic :: Utilities",
        "Topic :: System :: Monitoring",
        "Programming Language :: Python :: 3",
        "Typing :: Typed",
        "License :: OSI Approved :: Apache Software License", ],
    license             =   ABOUT['__license__'],
    long_description    =   README,
    long_description_content_type   =   "text/markdown",
    python_requires     =   '>=3.6',
    install_requires    =   ['wpscan-out-parse>=1.9.1', 'filelock', ],
    extras_require      =   {'syslog' : ['rfc5424-logging-handler', 'cefevent'],
                             'docs': ["Sphinx", "recommonmark"], 
                             'dev': ["pytest", "pytest-cov", "codecov", "coverage", "tox", "mypy"]},
    keywords            =   ABOUT['__keywords__'],
)
