"""
python-bna
Battle.net Authenticator routines in Python.

Specification can be found here:
* <http://bnetauth.freeportal.us/specification.html>
Note: Link likely dead. Check webarchive.
"""

import base64
import hmac

from binascii import hexlify
from hashlib import sha1
from http.client import HTTPConnection
from struct import pack, unpack
from time import time
from urllib.parse import urlencode, urlunparse


RSA_MOD = 104890018807986556874007710914205443157030159668034197186125678960287470894290830530618284943118405110896322835449099433232093151168250152146023319326491587651685252774820340995950744075665455681760652136576493028733914892166700899109836291180881063097461175643998356321993663868233366705340758102567742483097
RSA_KEY = 257

ENROLL_HOSTS = {
	# "CN": "mobile-service.battlenet.com.cn",
	# "EU": "m.eu.mobileservice.blizzard.com",
	# "US": "m.us.mobileservice.blizzard.com",
	# "EU": "eu.mobile-service.blizzard.com",
	# "US": "us.mobile-service.blizzard.com",
	"default": "mobile-service.blizzard.com",
}

INIT_RESTORE_PATH = "/enrollment/initiatePaperRestore.htm"
VALIDATE_RESTORE_PATH = "/enrollment/validatePaperRestore.htm"
ENROLL_PATH = "/enrollment/enroll.htm"


class HTTPError(Exception):
	def __init__(self, msg, response):
		self.response = response
		super(HTTPError, self).__init__(msg)


def get_one_time_pad(length):
	def timedigest():
		return sha1(str(time()).encode()).digest()

	return (timedigest() + timedigest())[:length]


def get_server_response(data, host, path):
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


def enroll(data, host=ENROLL_HOSTS["default"], path=ENROLL_PATH):
	return get_server_response(data, host, path)


def encrypt(data):
	data = int(hexlify(data), 16)
	n = data ** RSA_KEY % RSA_MOD
	ret = ""
	while n > 0:
		n, m = divmod(n, 256)
		ret = chr(m) + ret
	return ret


def decrypt(response, otp):
	ret = bytearray()
	for c, e in zip(response, otp):
		ret.append(c ^ e)
	return ret


def request_new_serial(region="US", model="Motorola RAZR v3"):
	"""
	Requests a new authenticator
	This will connect to the Blizzard servers
	"""
	def base_msg(otp, region, model):
		ret = (otp + b"\0" * 37)[:37]
		ret += region.encode() or b"\0\0"
		ret += (model.encode() + b"\0" * 16)[:16]
		return b"\1" + ret

	otp = get_one_time_pad(37)
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


def bytes_to_restore_code(digest):
	ret = []
	for i in digest:
		c = i & 0x1f
		if c < 10:
			c += 48
		else:
			c += 55
			if c > 72:  # I
				c += 1
			if c > 75:  # L
				c += 1
			if c > 78:  # O
				c += 1
			if c > 82:  # S
				c += 1
		ret.append(chr(c))

	return "".join(ret)


def get_restore_code(serial, secret):
	data = (serial.encode() + secret)
	digest = sha1(data).digest()[-10:]
	return bytes_to_restore_code(digest)


def get_token(secret, digits=8, seconds=30, time=time):
	"""
	Computes the token for a given secret
	Returns the token, and the seconds remaining
	for that token
	"""
	if hasattr(time, "__call__"):
		time = time()
	t = int(time)
	msg = pack(">Q", int(t / seconds))
	r = hmac.new(secret, msg, sha1).digest()
	k = r[19]
	idx = k & 0x0f
	h = unpack(">L", r[idx:idx + 4])[0] & 0x7fffffff
	return h % (10 ** digits), -(t % seconds - seconds)


def get_time_offset(region="US", path="/enrollment/time.htm"):
	"""
	Calculates the time difference in seconds as a float
	between the local host and a remote server

	NOTE: The server returns time in milliseconds as an int while
	Python returns it as a float, in seconds.

	This function returns the difference in milliseconds as an int.
	Negative numbers indicate the local clock is ahead of the
	server clock.
	"""
	host = ENROLL_HOSTS.get(region, ENROLL_HOSTS["default"])
	response = get_server_response(None, host, path)
	t = time()
	remoteTime = int(unpack(">Q", response)[0])

	return remoteTime - int(t * 1000)


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


# restore functions, as reverse-engineered from the android implementation

def restore(serial, code):
	serial = normalize_serial(serial)
	if len(code) != 10:
		raise ValueError("invalid restore code (should be 10 bytes): %r" % (code))

	challenge = initiate_paper_restore(serial)
	if len(challenge) != 32:
		raise ValueError("Invalid challenge length (expected 32, got %i)" % (len(challenge)))

	code = restore_code_to_bytes(code)
	hash = hmac.new(code, serial.encode() + challenge, digestmod=sha1).digest()

	otp = get_one_time_pad(20)
	e = encrypt(hash + otp)
	response = validate_paper_restore(serial + e)
	secret = decrypt(response, otp)

	return secret


def restore_code_to_bytes(code):
	ret = bytearray()
	for c in code:
		c = ord(c)
		if 58 > c > 47:
			c -= 48
		else:
			mod = c - 55
			if c > 72:
				mod -= 1
			if c > 75:
				mod -= 1
			if c > 78:
				mod -= 1
			if c > 82:
				mod -= 1
			c = mod
		ret.append(c)

	return bytes(ret)


def get_otpauth_url(serial, secret, issuer="Battle.net", digits=8):
	code = base64.b32encode(secret).decode()
	protocol = "otpauth"
	type = "totp"
	label = "%s:%s" % (issuer, serial)
	params = {"secret": code, "issuer": issuer, "digits": 8}
	return urlunparse(protocol, type, label, "", urlencode(params), "")


def initiate_paper_restore(serial, host=ENROLL_HOSTS["default"], path=INIT_RESTORE_PATH):
	return get_server_response(serial, host, path)


def validate_paper_restore(data, host=ENROLL_HOSTS["default"], path=VALIDATE_RESTORE_PATH):
	try:
		response = get_server_response(data, host, path)
	except HTTPError as e:
		if e.response.status == 600:
			raise HTTPError("Invalid serial or restore key", e.response)
		else:
			raise
	return response
