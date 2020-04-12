#! /usr/bin/env python3
from setuptools import setup
import pathlib
import re
import sys
import subprocess
# Helper method that will parse wpwatcher.py to extract config setup values
def parse_setup(key):
    part={}
    for line in WPWATCHER.splitlines():
        if key in line:
            exec(line, part)
            break
    return(part[key])
# The directory containing this file
HERE = pathlib.Path(__file__).parent
# Read and store wpwatcher.py file
WPWATCHER = (HERE / "wpwatcher" / "__init__.py").read_text()
# The text of the README file
README = (HERE / "README.md").read_text()

setup(
    name                =   'wpwatcher',
    description         =   "WordPress Watcher is a Python wrapper for WPScan that manages scans on multiple sites and reports by email.",
    url                 =   parse_setup('GIT_URL'),
    maintainer          =   parse_setup('AUTHORS'),
    version             =   parse_setup('VERSION'),
    packages            =   ['wpwatcher',], 
    entry_points        =   {'console_scripts': ['wpwatcher = wpwatcher.cli:main'],},
    classifiers         =   ["Programming Language :: Python :: 3"],
    license             =   'Apache License 2.0',
    long_description    =   README,
    long_description_content_type   =   "text/markdown"
)