import hmac
import struct
from binascii import hexlify
from hashlib import sha1
from time import time

from .constants import RSA_KEY, RSA_MOD


def get_one_time_pad(length):
	def timedigest():
		return sha1(str(time()).encode()).digest()

	return (timedigest() + timedigest())[:length]


def get_token(secret, digits=8, seconds=30, time=time):
	"""
	Computes the token for a given secret
	Returns the token, and the seconds remaining
	for that token
	"""
	if hasattr(time, "__call__"):
		time = time()
	t = int(time)
	msg = struct.pack(">Q", int(t / seconds))
	r = hmac.new(secret, msg, sha1).digest()
	k = r[19]
	idx = k & 0x0f
	h = struct.unpack(">L", r[idx:idx + 4])[0] & 0x7fffffff
	return h % (10 ** digits), -(t % seconds - seconds)


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
