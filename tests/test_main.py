#!/usr/bin/env python

import urllib.parse
from base64 import b32encode

from pyotp import TOTP

import bna


SERIAL = "US120910711868"
SECRET = b"88aaface48291e09dc1ece9c2aa44d839983a7ff"
SECRET_ENC = "HA4GCYLGMFRWKNBYGI4TCZJQHFSGGMLFMNSTSYZSMFQTINDEHAZTSOJYGNQTOZTG"


def test_token():
	totp = TOTP(b32encode(SECRET), digits=8)
	assert totp.at(1347279358) == "93461643"
	assert totp.at(1347279359) == "93461643"
	assert totp.at(1347279360) == "86031001"


def test_restore_code():
	assert bna.get_restore_code(SERIAL, SECRET) == "4B91NQCYQ3"


def test_serial():
	pretty_serial = bna.prettify_serial(SERIAL)
	assert pretty_serial == "US-1209-1071-1868"
	assert bna.normalize_serial(pretty_serial) == SERIAL


def test_otpauth_url():
	otpauth_url = bna.get_otpauth_url(SERIAL, SECRET_ENC)
	p = urllib.parse.urlparse(otpauth_url)
	assert p.scheme == "otpauth"
	assert p.netloc == "totp"
	assert p.path == "/Battle.net:%s" % (SERIAL)
	params = urllib.parse.parse_qs(p.query)
	assert params["secret"] == [SECRET_ENC]
	assert params["issuer"] == ["Battle.net"]
	assert params["digits"] == ["8"]
