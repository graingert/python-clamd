#!/usr/bin/env python
from ez_setup import use_setuptools
use_setuptools("0.7.0")

from setuptools import setup, find_packages

readme = open('README.rst').read()
history = open('CHANGES.rst').read().replace('.. :changelog:', '')

setup(
    name="clamd",
    version='1.0.2',
    author="Thomas Grainger",
    author_email="python-clamd@graingert.co.uk",
    maintainer="Thomas Grainger",
    maintainer_email = "python-clamd@graingert.co.uk",
    keywords = "python, clamav, antivirus, scanner, virus, libclamav, clamd",
    description = "Clamd is a python interface to Clamd (Clamav daemon).",
    long_description=readme + '\n\n' + history,
    url="https://github.com/graingert/python-clamd",
    package_dir={'': 'src'},
    packages=find_packages('src', exclude="tests"),
    classifiers = [
        "License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)",
    ],
    tests_require = (
        "nose==1.3.3",
        "six==1.7.3",
    ),
    test_suite='nose.collector',
    zip_safe=True,
    include_package_data=False,
)
