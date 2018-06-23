"""
Utility functions
"""
from base64 import b32encode
from typing import Union
from urllib.parse import urlencode, urlunparse


def normalize_serial(serial: str) -> str:
	"""
	Normalizes a serial
	Will uppercase it, remove its dashes and strip
	any whitespace
	"""
	return serial.upper().replace("-", "").strip()


def prettify_serial(serial: str) -> str:
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


def get_otpauth_url(
	serial: str,
	secret: Union[bytes, str],
	issuer: str="Battle.net",
	digits: int=8
) -> str:
	"""
	Get the OTPAuth URL for the serial/secret pair
	https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	"""
	if not isinstance(secret, str):
		secret = b32encode(secret)
	protocol = "otpauth"
	type = "totp"
	label = "%s:%s" % (issuer, serial)
	params = {"secret": secret, "issuer": issuer, "digits": 8}
	return urlunparse((protocol, type, label, "", urlencode(params), ""))
