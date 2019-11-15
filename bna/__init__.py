"""
python-bna
Blizzard Authenticator routines in Python.

Specification can be found here:
* <http://bnetauth.freeportal.us/specification.html>
Note: Link likely dead. Check webarchive.
"""

import pkg_resources

from .crypto import get_restore_code
from .http import HTTPError, get_time_offset, request_new_serial, restore
from .utils import get_otpauth_url, normalize_serial, prettify_serial

__all__ = [
	"get_restore_code",
	"get_time_offset",
	"HTTPError",
	"request_new_serial",
	"restore",
	"get_otpauth_url",
	"normalize_serial",
	"prettify_serial",
]
__version__ = pkg_resources.require("bna")[0].version
