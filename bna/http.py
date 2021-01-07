import hmac
import struct
from base64 import b32encode
from hashlib import sha1
from http.client import HTTPConnection
from secrets import token_bytes
from time import time
from typing import Optional, Tuple

from .constants import ENROLL_HOSTS
from .crypto import decrypt, encrypt, restore_code_to_bytes
from .utils import normalize_serial


class HTTPError(Exception):
	def __init__(self, msg, response):
		self.response = response
		super().__init__(msg)


class APIClient:
	def __init__(self, *, region: str = "US", host: str = ""):
		self.region = region
		self.host = host or ENROLL_HOSTS.get(region, ENROLL_HOSTS["default"])

	def post(self, path: str, *, data: Optional[str] = None) -> bytes:
		conn = HTTPConnection(self.host)
		conn.request("POST", path, data)
		response = conn.getresponse()

		if response.status != 200:
			raise HTTPError("%s returned status %i" % (self.host, response.status), response)

		ret = response.read()
		conn.close()
		return ret

	def enroll(self, data):
		return self.post("/enrollment/enroll.htm", data=data)

	def get_time(self) -> int:
		response = self.post("/enrollment/time.htm")
		return int(struct.unpack(">Q", response)[0])

	def initiate_paper_restore(self, serial: str):
		response = self.post("/enrollment/initiatePaperRestore.htm", data=serial)
		resp_size = len(response)
		if resp_size != 32:
			raise ValueError("Bad challenge response (%i bytes)" % (resp_size))

		return response

	def validate_paper_restore(self, serial: str, encrypted_data: str):
		data = serial + encrypted_data
		try:
			response = self.post("/enrollment/validatePaperRestore.htm", data=data)
		except HTTPError as e:
			if e.response.status == 600:
				raise HTTPError("Invalid serial or restore key", e.response)
			else:
				raise
		return response


def request_new_serial(
	region: str = "US", model: str = "Motorola RAZR v3"
) -> Tuple[str, str]:
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
	encrypted_data = encrypt(data)

	client = APIClient(region=region)
	response = client.enroll(encrypted_data)[8:]

	decrypted_response = decrypt(response, otp)

	secret = b32encode(decrypted_response[:20]).decode()
	serial = decrypted_response[20:].decode()

	region = serial[:2]
	if region not in ("CN", "EU", "KR", "US"):
		raise ValueError("Unexpected region: %r" % (region))

	return serial, secret


def get_time_offset(region: str = "US") -> int:
	"""
	Calculates the time difference in seconds as a float
	between the local host and a remote server

	This function returns the difference in milliseconds as an int.
	Negative numbers indicate the local clock is ahead of the
	server clock.
	"""
	client = APIClient(region=region)
	server_time = client.get_time()
	local_time = time()

	# NOTE: The server returns time in milliseconds as an int whereas
	# Python returns it as a float, in seconds.
	return server_time - int(local_time * 1000)


def restore(serial: str, restore_code: str) -> str:
	serial = normalize_serial(serial)
	restore_code = restore_code.upper()
	if len(restore_code) != 10:
		raise ValueError(f"invalid restore code (should be 10 characters): {restore_code}")

	# Region is always the first two chars of a restore code
	region = serial[:2]
	client = APIClient(region=region)
	challenge = client.initiate_paper_restore(serial)

	code = restore_code_to_bytes(restore_code)
	hash = hmac.new(code, serial.encode() + challenge, digestmod=sha1).digest()

	otp = token_bytes(20)
	encrypted_data = encrypt(hash + otp)
	response = client.validate_paper_restore(serial, encrypted_data)
	secret = decrypt(response, otp)

	return b32encode(secret).decode()
