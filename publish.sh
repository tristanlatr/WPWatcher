#! /bin/bash
python3 setup.py build check sdist bdist_wheel
twine upload --verbose dist/*
python3 setup.py clean
rm -rf ./dist
rm -fr ./build
rm -fr ./wpwatcher.egg-info