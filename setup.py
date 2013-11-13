#!/usr/bin/env python

import os.path
from distutils.core import setup

README = open(os.path.join(os.path.dirname(__file__), "README.rst")).read()

CLASSIFIERS = [
	"Development Status :: 5 - Production/Stable",
	"Intended Audience :: Developers",
	"License :: OSI Approved :: MIT License",
	"Programming Language :: Python",
	"Programming Language :: Python :: 2.6",
	"Programming Language :: Python :: 2.7",
	"Programming Language :: Python :: 3",
	"Programming Language :: Python :: 3.3",
	"Topic :: Security",
	"Topic :: Security :: Cryptography",
]

import bna

setup(
	name = "python-bna",
	py_modules = ["bna"],
	scripts = ["bin/bna"],
	author = bna.__author__,
	author_email = bna.__email__,
	classifiers = CLASSIFIERS,
	description = "Battle.net Authenticator routines in Python.",
	download_url = "https://github.com/Adys/python-bna/tarball/master",
	long_description = README,
	url = "https://github.com/Adys/python-bna",
	version = bna.__version__,
)
