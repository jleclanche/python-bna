# -*- coding: utf-8 -*-
"""
python-bna
Battle.net Authenticator routines in Python.

Specification can be found here:
  <http://bnetauth.freeportal.us/specification.html>
Python implementation by Jerome Leclanche <jerome.leclanche@gmail.com>
"""
from time import time
from hashlib import sha1

RSA_KEY = 104890018807986556874007710914205443157030159668034197186125678960287470894290830530618284943118405110896322835449099433232093151168250152146023319326491587651685252774820340995950744075665455681760652136576493028733914892166700899109836291180881063097461175643998356321993663868233366705340758102567742483097
RSA_MOD = 257

ENROLL_HOSTS = {
	#"EU": "m.eu.mobileservice.blizzard.com",
	#"US": "m.us.mobileservice.blizzard.com",
	"EU": "eu.mobile-service.blizzard.com",
	"US": "us.mobile-service.blizzard.com",
	"default": "mobile-service.blizzard.com",
}

class HTTPError(Exception):
	pass

def getEmptyEncryptMsg(otp, region, model):
	ret = (otp + "\0" * 37)[:37]
	ret += region or "\0\0"
	ret += (model + "\0" * 16)[:16]
	return chr(1) + ret

def doEnroll(data, enroll_host=ENROLL_HOSTS["default"], enroll_uri="/enrollment/enroll.htm"):
	"""
	Send computed data to Blizzard servers
	Return the answer from the server
	"""
	from http.client import HTTPConnection

	conn = HTTPConnection(enroll_host)
	conn.request("POST", enroll_uri, data)
	response = conn.getresponse()

	if response.status != 200:
		raise HTTPError("%s returned status %i" % (enroll_host, response.status))

	ret = response.read()
	conn.close()
	return ret

def encrypt(data):
	data = int(data.encode("hex"), 16)
	n = data ** RSA_MOD % RSA_KEY
	ret = ""
	while n > 0:
		n, m = divmod(n, 256)
		ret = chr(m) + ret
	return ret

def decrypt(response, otp):
	return "".join(chr(ord(c) ^ ord(e)) for c, e in zip(response, otp))

def requestNewSerial(region="US", model="Motorola RAZR v3"):
	"""
	Requests a new authenticator
	This will connect to the Blizzard servers
	"""
	def timedigest(): return sha1(str(time())).digest()

	otp = (timedigest() + timedigest())[:37]
	data = getEmptyEncryptMsg(otp, region, model)

	host = ENROLL_HOSTS.get(region, ENROLL_HOSTS["default"]) # get the host, or fallback to default
	e = encrypt(data)
	response = decrypt(doEnroll(e, host)[8:], otp)

	secret = response[:20]
	serial = response[20:]

	region = serial[:2]
	if region not in ("EU", "US"):
		raise ValueError("Unexpected region: %r" % (region))

	return {"serial": serial, "secret": secret}

def getToken(secret, digits=8, seconds=30):
	"""
	Computes the token for a given secret
	Returns the token, and the seconds remaining
	for that token
	"""
	import hmac
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
	Will lowercase it, remove its dashes and strip
	any whitespace
	"""
	return serial.lower().replace("-", "").strip()

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
