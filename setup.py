#! /usr/bin/env python3
from setuptools import setup
import pathlib
# The directory containing this file
HERE = pathlib.Path(__file__).parent
# The text of the README file
README = (HERE / "README.md").read_text()
setup(
    name='wpwatcher',
    description="WordPress Watcher is a Python wrapper for WPScan",
    url='https://github.com/tristanlatr/WPWatcher',
    maintainer='Florian Roth, Tristan Landès',
    version='0.3',
    entry_points = {'console_scripts': ['wpwatcher=wpwatcher:wpwatcher'],},
    scripts=['wpwatcher.py'],
    classifiers=["Programming Language :: Python :: 3"],
    license='Apache License 2.0',
    long_description=README,
    long_description_content_type="text/markdown"
)