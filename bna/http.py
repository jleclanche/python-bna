import hmac
import struct
from hashlib import sha1
from http.client import HTTPConnection
from secrets import token_bytes
from time import time
from typing import Optional, Tuple

from .constants import ENROLL_HOSTS, PATHS
from .crypto import decrypt, encrypt, restore_code_to_bytes
from .utils import normalize_serial


class HTTPError(Exception):
	def __init__(self, msg, response):
		self.response = response
		super().__init__(msg)


def get_server_response(data: Optional[str], host: str, path: str) -> bytes:
	"""
	Send computed data to Blizzard servers
	Return the answer from the server
	"""
	conn = HTTPConnection(host)
	conn.request("POST", path, data)
	response = conn.getresponse()

	if response.status != 200:
		raise HTTPError("%s returned status %i" % (host, response.status), response)

	ret = response.read()
	conn.close()
	return ret


def enroll(
	data: str, host: str = ENROLL_HOSTS["default"], path: str = PATHS["enroll"]
) -> bytes:
	return get_server_response(data, host, path)


def request_new_serial(
	region: str = "US", model: str = "Motorola RAZR v3"
) -> Tuple[str, bytes]:
	"""
	Requests a new authenticator
	This will connect to the Blizzard servers
	"""

	def base_msg(otp, region, model):
		ret = (otp + b"\0" * 37)[:37]
		ret += region.encode() or b"\0\0"
		ret += (model.encode() + b"\0" * 16)[:16]
		return b"\1" + ret

	otp = token_bytes(37)
	data = base_msg(otp, region, model)

	e = encrypt(data)
	# get the host, or fallback to default
	host = ENROLL_HOSTS.get(region, ENROLL_HOSTS["default"])
	response = decrypt(enroll(e, host)[8:], otp)

	secret = bytes(response[:20])
	serial = response[20:].decode()

	region = serial[:2]
	if region not in ("CN", "EU", "US"):
		raise ValueError("Unexpected region: %r" % (region))

	return serial, secret


def get_time_offset(region: str = "US", path: str = PATHS["time"]) -> int:
	"""
	Calculates the time difference in seconds as a float
	between the local host and a remote server

	This function returns the difference in milliseconds as an int.
	Negative numbers indicate the local clock is ahead of the
	server clock.
	"""
	host = ENROLL_HOSTS.get(region, ENROLL_HOSTS["default"])
	response = get_server_response(None, host, path)
	t = time()

	# NOTE: The server returns time in milliseconds as an int whereas
	# Python returns it as a float, in seconds.
	server_time = int(struct.unpack(">Q", response)[0])

	return server_time - int(t * 1000)


def restore(serial: str, restore_code: str) -> bytes:
	restore_code = restore_code.upper()
	serial = normalize_serial(serial)
	if len(restore_code) != 10:
		raise ValueError("invalid restore code (should be 10 bytes): %r" % (restore_code))

	challenge = initiate_paper_restore(serial)
	if len(challenge) != 32:
		raise ValueError("Bad challenge length (expected 32, got %i)" % (len(challenge)))

	code = restore_code_to_bytes(restore_code)
	hash = hmac.new(code, serial.encode() + challenge, digestmod=sha1).digest()

	otp = token_bytes(20)
	e = encrypt(hash + otp)
	response = validate_paper_restore(serial + e)
	secret = decrypt(response, otp)

	return secret


def initiate_paper_restore(
	serial: str, host: str = ENROLL_HOSTS["default"], path: str = PATHS["init_restore"]
) -> bytes:
	return get_server_response(serial, host, path)


def validate_paper_restore(
	data: str, host: str = ENROLL_HOSTS["default"], path: str = PATHS["validate_restore"]
) -> bytes:
	try:
		response = get_server_response(data, host, path)
	except HTTPError as e:
		if e.response.status == 600:
			raise HTTPError("Invalid serial or restore key", e.response)
		else:
			raise
	return response
