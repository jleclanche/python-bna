"""
Utility functions
"""
from base64 import b32encode
from urllib.parse import urlencode, urlunparse


def normalize_serial(serial):
	"""
	Normalizes a serial
	Will uppercase it, remove its dashes and strip
	any whitespace
	"""
	return serial.upper().replace("-", "").strip()


def prettify_serial(serial):
	"""
	Returns the prettified version of a serial
	It should look like XX-AAAA-BBBB-CCCC-DDDD
	"""
	serial = normalize_serial(serial)
	if len(serial) != 14:
		raise ValueError("serial %r should be 14 characters long" % (serial))

	def digits(chars):
		if not chars.isdigit():
			raise ValueError("bad serial %r" % (serial))
		return "%04i" % int((chars))

	return "%s-%s-%s-%s" % (
		serial[0:2].upper(),
		digits(serial[2:6]),
		digits(serial[6:10]),
		digits(serial[10:14])
	)


def get_otpauth_url(serial, secret, issuer="Battle.net", digits=8):
	"""
	Get the OTPAuth URL for the serial/secret pair
	https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	"""
	code = b32encode(secret).decode()
	protocol = "otpauth"
	type = "totp"
	label = "%s:%s" % (issuer, serial)
	params = {"secret": code, "issuer": issuer, "digits": 8}
	return urlunparse((protocol, type, label, "", urlencode(params), ""))
