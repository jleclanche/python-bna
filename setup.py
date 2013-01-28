#!/usr/bin/env python

import os.path
from distutils.core import setup

README = open(os.path.join(os.path.dirname(__file__), "README.rst")).read()

CLASSIFIERS = [
	"Development Status :: 5 - Production/Stable",
	"Intended Audience :: Developers",
	"License :: OSI Approved :: MIT License",
	"Programming Language :: Python",
	"Topic :: Security",
	"Topic :: Security :: Cryptography",
]

import bna
VERSION = bna.__version__

setup(
	name = "python-bna",
	py_modules = ["bna"],
	scripts = ["bin/bna"],
	author = "Jerome Leclanche",
	author_email = "jerome.leclanche+pypi@gmail.com",
	classifiers = CLASSIFIERS,
	description = "Battle.net Authenticator routines in Python.",
	download_url = "https://github.com/Adys/python-bna/tarball/master",
	long_description = README,
	url = "https://github.com/Adys/python-bna",
	version = VERSION,
)
