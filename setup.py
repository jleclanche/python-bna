#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os.path
from distutils.core import setup

README = open(os.path.join(os.path.dirname(__file__), "README.rst")).read()

setup(
	name = "python-bna",
	py_modules = ["bna"],
	author = "Jerome Leclanche",
	author_email = "adys.wh@gmail.com",
	url = "http://github.com/Adys/python-bna",
	download_url = "http://github.com/Adys/python-bna/tarball/master",
	description = "Battle.net Authenticator routines in Python.",
	long_description = README,
	version = "1.1",
)
