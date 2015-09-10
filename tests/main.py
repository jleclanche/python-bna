#!/usr/bin/env python
"""
Tests for python-bna

>>> import bna
>>> serial = "US120910711868"
>>> secret = b"88aaface48291e09dc1ece9c2aa44d839983a7ff"
>>> bna.get_token(secret, time=1347279358)
(93461643, 2)
>>> bna.get_token(secret, time=1347279359)
(93461643, 1)
>>> bna.get_token(secret, time=1347279360)
(86031001, 30)
>>> bna.get_restore_code(serial, secret)
'4B91NQCYQ3'
>>> bna.normalize_serial(bna.prettify_serial(serial)) == serial
True
"""

if __name__ == "__main__":
	import doctest
	doctest.testmod()
