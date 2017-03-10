"""
python-bna
Battle.net Authenticator routines in Python.

Specification can be found here:
* <http://bnetauth.freeportal.us/specification.html>
Note: Link likely dead. Check webarchive.
"""

from .crypto import get_restore_code, get_token
from .http import get_time_offset, HTTPError, request_new_serial, restore
from .utils import get_otpauth_url, normalize_serial, prettify_serial


__all__ = [
	"get_restore_code", "get_token",
	"get_time_offset", "HTTPError", "request_new_serial", "restore",
	"get_otpauth_url", "normalize_serial", "prettify_serial",
]
