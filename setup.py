#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

setup(
	name = "python-bna",
	py_packages = ["bna"],
	author = "Jerome Leclanche",
	author_email = "adys.wh@gmail.com",
	classifiers = CLASSIFIERS,
	description = "Battle.net Authenticator routines in Python.",
	download_url = "http://github.com/Adys/python-bna/tarball/master",
	long_description = README,
	url = "http://github.com/Adys/python-bna",
	version = "1.2",
)
