#! /usr/bin/env python3
from setuptools import setup
from setuptools.command.install import install
import sys
if sys.version_info[0] < 3: 
    raise EnvironmentError("Sorry, you must use Python 3")
# The directory containing this file
import pathlib
import urllib
import tempfile
import os
import stat
HERE = pathlib.Path(__file__).parent
# Helper method that will parse wpwatcher.py to extract config setup values
def parse_setup(key):
    part={}
    for line in WPWATCHER.splitlines():
        if key in line:
            exec(line, part)
            break
    return(part[key])

class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        install.run(self)
        # PUT YOUR POST-INSTALL SCRIPT HERE or CALL A FUNCTION
        os.system('sh -c "$(curl -sSL https://raw.githubusercontent.com/lukaspustina/wpscan-analyze/master/install.sh)"')
        print()
        print("Done installing WPWatcher")

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
    long_description_content_type   =   "text/markdown",
    cmdclass={
        'install': PostInstallCommand,
    }
)