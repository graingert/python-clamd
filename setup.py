#!/usr/bin/env python
from setuptools import setup

setup(
    setup_requires=['d2to1>=0.2.9'],
    d2to1=True,

    # This ensures that the MANIFEST.in is read, but it
    # will become the default in distutils2.
    include_package_data=True,
)
