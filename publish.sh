#! /bin/bash
git tag $(python3 setup.py -V)
git push --tags
