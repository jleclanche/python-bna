#!/usr/bin/env python

import urllib.parse

import bna


SERIAL = "US120910711868"
SECRET = b"88aaface48291e09dc1ece9c2aa44d839983a7ff"
SECRET_ENC = "HA4GCYLGMFRWKNBYGI4TCZJQHFSGGMLFMNSTSYZSMFQTINDEHAZTSOJYGNQTOZTG"


def test_token():
	assert bna.get_token(SECRET, time=1347279358) == (93461643, 2)
	assert bna.get_token(SECRET, time=1347279359) == (93461643, 1)
	assert bna.get_token(SECRET, time=1347279360) == (86031001, 30)
	assert bna.get_restore_code(SERIAL, SECRET) == "4B91NQCYQ3"

	pretty_serial = bna.prettify_serial(SERIAL)
	assert pretty_serial == "US-1209-1071-1868"
	assert bna.normalize_serial(pretty_serial) == SERIAL


def test_otpauth_url():
	otpauth_url = bna.get_otpauth_url(SERIAL, SECRET)
	p = urllib.parse.urlparse(otpauth_url)
	assert p.scheme == "otpauth"
	assert p.netloc == "totp"
	assert p.path == "/Battle.net:%s" % (SERIAL)
	params = urllib.parse.parse_qs(p.query)
	assert params["secret"] == [SECRET_ENC]
	assert params["issuer"] == ["Battle.net"]
	assert params["digits"] == ["8"]
