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
WPWATCHER = (HERE / "wpwatcher.py").read_text()
# The text of the README file
README = (HERE / "README.md").read_text()
# Add ./setup.py publish command
if sys.argv[1]=="publish":
    script="""#! /bin/bash
python3 setup.py build check sdist bdist_wheel
twine upload --verbose dist/*
python3 setup.py clean
rm -rf ./dist
rm -fr ./build
rm -fr ./wpwatcher.egg-info"""
    with open('/tmp/publish-wpwatcher.py','w') as scriptfile:
        scriptfile.write(script)
    result,err=subprocess.Popen(["cat","/tmp/publish-wpwatcher.py","|","bash"], stdout=subprocess.PIPE ).communicate()
    print(result)
    print(err)
else:
    setup(
        name                =   'wpwatcher',
        description         =   "WordPress Watcher is a Python wrapper for WPScan that manages scans on multiple sites and reports by email.",
        url                 =   parse_setup('GIT_URL'),
        maintainer          =   parse_setup('AUTHORS'),
        version             =   parse_setup('VERSION'),
        py_modules          =   ['wpscan_parser'],
        entry_points        =   {'console_scripts': ['wpwatcher=wpwatcher:wpwatcher'],},
        scripts             =   ['wpwatcher.py','wpscan_parser.py'],
        classifiers         =   ["Programming Language :: Python :: 3"],
        license             =   'Apache License 2.0',
        long_description    =   README,
        long_description_content_type   =   "text/markdown"
    )