Using the command-line tool
===========================

bna is a command line interface to the python-bna library. It can store and manage multiple authenticators, as well as create new ones.


Two things to remember:
 - Using an authenticator on the same computer as the one you're playing on is *not secure*.
 - It is impossible (without knowing the secret) to import an existing authenticator

Configuration is stored in ~/.config/bna/bna.conf. You can pass a different config directory with --config=~/.bna.conf for example.

Creating a new authenticator
----------------------------
::

	$ bna --new

If you do not already have an authenticator, it will be set as default. You can pass --set-default otherwise.

Getting an authentication token
-------------------------------
::

	$ bna
	01234567
	$ bna EU-1234-1234-1234
	76543210

Getting a serial's restore code
-------------------------------
::

	$ bna --restore-code
	Z45Q9CVXRR
	$ bna --restore EU-1234-1234-1234 ABCDE98765
	Restored serial EU-1234-1234-1234

OTP from Mobile
---------------
::

	$ bna --otpauth-url
	otpauth://totp/Battle.net:EU123412341234:?secret=ASFAS75ASDF75889G9AD7S69AS7697AS&issuer=Battle.net&digits=8


Now paste this to your OTP app, or convert to QRCode and scan, or manually enter the secret.

Note: This will not work with "Google Authenticator" as it does not support 8 digits, try "FreeOTP_"


Using the python-bna library
============================

Requesting a new authenticator
------------------------------
::

	import bna
	try:
		# region is EU or US
		# note that EU authenticators are valid in the US, and vice versa
		serial, secret = bna.request_new_serial("US")
	except bna.HTTPError as e:
		print("Could not connect:", e)

Getting a token
---------------
::

	# Get and print a token
	token, time_remaining = bna.get_token(secret=secret)
	print(token)

	# print a new token every time the previous one expires
	from time import sleep
	while True:
		token, time_remaining = bna.get_token(secret=secret)
		print(token)
		sleep(time_remaining)


.. _FreeOTP: https://fedorahosted.org/freeotp/
