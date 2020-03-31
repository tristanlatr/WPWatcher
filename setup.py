#! /usr/bin/env python3
from setuptools import setup
import pathlib
import re
# The directory containing this file
HERE = pathlib.Path(__file__).parent
# Read the begin of the file and parse version of the project
version = {}
for line in (HERE / "wpwatcher.py").read_text().splitlines():
    if "VERSION" in line:
        exec(line, version)
        break
# The text of the README file
README = (HERE / "README.md").read_text()
setup(
    name='wpwatcher',
    description="WordPress Watcher is a Python wrapper for WPScan that manages scans on multiple sites and reports by email.",
    url='https://github.com/tristanlatr/WPWatcher',
    maintainer='Florian Roth, Tristan Landès',
    version=version['VERSION'],
    py_modules=['wpscan_parser'],
    entry_points = {'console_scripts': ['wpwatcher=wpwatcher:wpwatcher'],},
    scripts=['wpwatcher.py','wpscan_parser.py'],
    classifiers=["Programming Language :: Python :: 3"],
    license='Apache License 2.0',
    long_description=README,
    long_description_content_type="text/markdown"
)