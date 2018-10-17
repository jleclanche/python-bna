from base64 import b32decode
from hashlib import sha1
from typing import Union

from .constants import RSA_KEY, RSA_MOD


def encrypt(data: bytes) -> str:
	base_num = int(data.hex(), 16)
	n = base_num ** RSA_KEY % RSA_MOD
	ret = ""
	while n > 0:
		n, m = divmod(n, 256)
		ret = chr(m) + ret
	return ret


def decrypt(response: bytes, otp: bytes) -> bytearray:
	ret = bytearray()
	for c, e in zip(response, otp):
		ret.append(c ^ e)
	return ret


def bytes_to_restore_code(digest: Union[bytes, bytearray]) -> str:
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


def get_restore_code(serial: str, secret: str) -> str:
	secret_bytes = b32decode(secret)
	data = serial.encode() + secret_bytes
	digest = sha1(data).digest()[-10:]
	return bytes_to_restore_code(digest)


def restore_code_to_bytes(code: str) -> bytes:
	ret = bytearray()
	for c in code:
		i = ord(c)
		if 58 > i > 47:
			i -= 48
		else:
			mod = i - 55
			if i > 72:
				mod -= 1
			if i > 75:
				mod -= 1
			if i > 78:
				mod -= 1
			if i > 82:
				mod -= 1
			i = mod
		ret.append(i)

	return bytes(ret)
