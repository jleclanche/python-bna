"""
python-bna
Battle.net Authenticator routines in Python.

Specification can be found here:
  <http://bnetauth.freeportal.us/specification.html>
Python implementation by Jerome Leclanche <jerome.leclanche@gmail.com>
"""

__version__ = "3.0"

import hmac
from binascii import hexlify
from hashlib import sha1
try:
	from http.client import HTTPConnection
except ImportError:
	from httplib import HTTPConnection
from time import time

RSA_KEY = 104890018807986556874007710914205443157030159668034197186125678960287470894290830530618284943118405110896322835449099433232093151168250152146023319326491587651685252774820340995950744075665455681760652136576493028733914892166700899109836291180881063097461175643998356321993663868233366705340758102567742483097
RSA_MOD = 257

ENROLL_HOSTS = {
	"EU": "m.eu.mobileservice.blizzard.com",
	"US": "m.us.mobileservice.blizzard.com",
	#"EU": "eu.mobile-service.blizzard.com",
	#"US": "us.mobile-service.blizzard.com",
	"default": "mobile-service.blizzard.com",
}

class HTTPError(Exception):
	def __init__(self, msg, response):
		self.response = response
		super(HTTPError, self).__init__(msg)

def getEmptyEncryptMsg(otp, region, model):
	ret = (otp + b"\0" * 37)[:37]
	ret += region.encode() or b"\0\0"
	ret += (model.encode() + b"\0" * 16)[:16]
	return b"\1" + ret

def getServerResponse(data, host, path):
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

def enroll(data, host=ENROLL_HOSTS["default"], path="/enrollment/enroll.htm"):
	return getServerResponse(data, host, path)

def encrypt(data):
	data = int(hexlify(data), 16)
	n = data ** RSA_MOD % RSA_KEY
	ret = ""
	while n > 0:
		n, m = divmod(n, 256)
		ret = chr(m) + ret
	return ret

def decrypt(response, otp):
	ret = bytearray()
	for c, e in zip(response, otp):
		# python2 compatibility
		if isinstance(c, str):
			c = ord(c)
			e = ord(e)

		ret.append(c ^ e)
	return ret

def requestNewSerial(region="US", model="Motorola RAZR v3"):
	"""
	Requests a new authenticator
	This will connect to the Blizzard servers
	"""
	def timedigest():
		return sha1(str(time()).encode()).digest()

	otp = (timedigest() + timedigest())[:37]
	data = getEmptyEncryptMsg(otp, region, model)

	e = encrypt(data)
	host = ENROLL_HOSTS.get(region, ENROLL_HOSTS["default"]) # get the host, or fallback to default
	response = decrypt(enroll(e, host)[8:], otp)

	secret = bytes(response[:20])
	serial = response[20:].decode()

	region = serial[:2]
	if region not in ("EU", "US"):
		raise ValueError("Unexpected region: %r" % (region))

	return {"serial": serial, "secret": secret}

def bytesToRestoreCode(digest):
	ret = []
	for i in digest:
		c = i & 0x1f
		if c < 10:
			c += 48
		else:
			c += 55
			if c > 72: # I
				c += 1
			if c > 75: # L
				c += 1
			if c > 78: # O
				c += 1
			if c > 82: # S
				c += 1
		ret.append(chr(c))

	return "".join(ret)

def getRestoreCode(serial, secret):
	data = (serial.encode() + secret)
	digest = sha1(data).digest()[-10:]
	return bytesToRestoreCode(digest)

def getToken(secret, digits=8, seconds=30):
	"""
	Computes the token for a given secret
	Returns the token, and the seconds remaining
	for that token
	"""
	from struct import pack, unpack
	t = int(time())
	msg = pack(">Q", int(t / seconds))
	r = hmac.new(secret, msg, sha1).digest()
	k = r[19]

	# Python2 compat
	if isinstance(k, str):
		k = ord(k)

	idx = k & 0x0f
	h = unpack(">L", r[idx:idx+4])[0] & 0x7fffffff
	return h % (10 ** digits), -(t % seconds - seconds)


def normalizeSerial(serial):
	"""
	Normalizes a serial
	Will uppercase it, remove its dashes and strip
	any whitespace
	"""
	return serial.upper().replace("-", "").strip()

def prettifySerial(serial):
	"""
	Returns the prettified version of a serial
	It should look like XX-AAAA-BBBB-CCCC-DDDD
	"""
	serial = normalizeSerial(serial)
	if len(serial) != 14:
		raise ValueError("serial %r should be 14 characters long" % (serial))

	def digits(chars):
		if not chars.isdigit():
			raise ValueError("bad serial %r" % (serial))
		return "%04i" % int((chars))

	return "%s-%s-%s-%s" % (serial[0:2].upper(), digits(serial[2:6]), digits(serial[6:10]), digits(serial[10:14]))
